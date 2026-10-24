# RADIUS (G4.3b) — `crates/proto-radius`

Cliente RADIUS do BNG, servidor de CoA/Disconnect e codec, em Rust puro, sem `unsafe` e
**sans-IO**: nada aqui abre socket nem lê relógio. Quem chama (o serviço BNG do daemon, G4.3d)
move os bytes e passa o tempo; os testes fazem o mesmo com uma rede virtual. Camada L2, ao lado
dos outros `proto-*`.

Por que importa: os sistemas de gestão de provedor do Brasil (MK-Auth, IXC, SGP, Hubsoft) falam
RADIUS com os atributos da MikroTik. Falando o mesmo dialeto, o operador migra de um
concentrador MikroTik sem mexer no sistema.

## O que tem

| Módulo | O quê | Regra |
|---|---|---|
| `packet` | `Packet::parse` valida cabeçalho e o tamanho de todo atributo uma vez; depois a visão e os iteradores só emprestam o buffer (zero cópia, nenhuma alocação no decode). VSA com vários sub-atributos, atributos estendidos e longos com fragmentação. `Builder` e `AttrList` para escrever | RFC 2865 §3/§5, §5.26; RFC 6929 §2 |
| `crypto` | Request/Response Authenticator, Message-Authenticator, User-Password, sal do Tunnel-Password e das chaves MPPE, CHAP; comparações em tempo constante | RFC 2865 §3/§5.2, RFC 2866 §3, RFC 2869 §5.14, RFC 5176 §2.3/§3.4, RFC 2868 §3.5, RFC 2548 §2.4.2, RFC 1994 §4.1 |
| `mschap` | MS-CHAPv1/v2 (NT-Response, resposta do autenticador "S=…") e chaves MPPE; leiaute dos VSAs da Microsoft | RFC 2433, RFC 2759 §8, RFC 3079 §3, RFC 2548 |
| `dict` | Dicionário tipado (tipos da RFC 8044), estendível em tempo de execução com texto no formato do FreeRADIUS; papel de cada atributo em CoA/DM | RFC 8044, RFC 6929 §2.8 ("invalid attribute"), RFC 5176 §3 |
| `rate_limit` | `Mikrotik-Rate-Limit` (e o `rate-limit` do perfil PPP): leitura e escrita com os padrões do manual da MikroTik | manual RADIUS da MikroTik |
| `acct` | Conteúdo do Accounting-Request (contadores de 64 bits em Octets + Gigawords) e agenda de interims com dispersão | RFC 2866, RFC 2869 §5.1–§5.3, §5.16 |
| `client` | Access/Accounting/Status-Server; retransmissão, failover, identificadores, Blast-RADIUS | RFC 5080 §2.2.1/§2.2.2, RFC 5997, RFC 2866 §5.2 |
| `dynauth` | Servidor de CoA e Disconnect do NAS | RFC 5176 |
| `juniper` | Sintaxe `serviço(arg,…)` do `ERX-Service-Activate` (só leitura) | dicionário ERX |
| `testserver` | Servidor RADIUS de teste (usuários PAP/CHAP/MS-CHAPv1/v2, atributos, perdas e atrasos programados, cache de duplicados) | RFC 5080 §2.2.2 |
| `fuzz` | Oráculos do fuzzing (`docs/fuzzing.md`, alvo `radius`) | — |

### Dicionário embutido

Padrão (RFC 2865, 2866, 2868, 2869, 3162, 4372, 4675, 4818, 4849, 5176, 6911, 6929), Microsoft
(311), DSL Forum (3561: Agent-Circuit-Id/Remote-Id e as taxas de linha da RFC 4679), MikroTik
(14988: Rate-Limit, Group, Address-List, Recv/Xmit/Total-Limit e Gigawords, Mark-Id,
Delegated-IPv6-Pool, DHCP-Option-Set…; os de wireless ficaram de fora), Juniper/ERX (4874:
Service-Activate/Deactivate/Statistics, políticas, só leitura), Ascend (529: Data-Rate e
Xmit-Rate, que o RouterOS lê sem Rate-Limit) e Redback (2352: Agent-Circuit-Id/Remote-Id, que o
RouterOS manda). Mais atributos: `Dictionary::load(texto)` com `VENDOR`, `BEGIN-VENDOR`,
`ATTRIBUTE nome número tipo [has_tag,encrypt=1|2]` — o arquivo de dicionário que todo servidor
RADIUS já tem.

### Cliente: padrões e o que difere do RouterOS

| Parâmetro | Padrão | RouterOS `/radius` | Por quê |
|---|---|---|---|
| Tempo inicial (IRT) | 1,1 s | `timeout=1100ms` | o mesmo número, mas com recuo exponencial e ±10 % de dispersão (RFC 5080 §2.2.1): 3000 NAS religando juntos não viram 3000 pedidos/s eternos |
| Transmissões por servidor | 3 (acesso), 5 (contabilização) | fixo | RFC 5080: MRC/MRD/MRT |
| Duração por servidor | 8 s (acesso), 30 s (contabilização) | — | MRD, entre 5 e 30 s como a RFC pede |
| Message-Authenticator | sempre enviado; resposta sem ele é descartada | `require-message-auth=yes-for-request-resp` | Blast-RADIUS (CVE-2024-3596) |
| Servidor morto | 3 trocas falhas seguidas; volta por Status-Server (opcional por servidor) ou após 30 s | — | RFC 5997 §4.1/§4.3; com todos mortos, ainda tenta |
| Identificadores | 256 por socket, novo socket sob carga (padrão até 16 = 4096 em voo por servidor), fila depois | um socket | RFC 5080 §2.2.2 (não reusar enquanto pendente, LRU) |
| Contabilização | repete até ser confirmada (rodadas pelos servidores); idade máxima opcional | — | RFC 5080 §2.2.1 ("until the request is acknowledged") |
| Interim | um interim novo da mesma sessão substitui o pendente | — | contadores são cumulativos: um servidor fora do ar não acumula interims velhos |

Acct-Delay-Time é posto pelo cliente em cada tentativa num servidor novo (RFC 2866 §5.2: mudá-lo
muda o identificador); a retransmissão ao mesmo servidor é o mesmo pacote, byte a byte.

### Servidor de CoA/DM (RFC 5176)

`DynAuthServer::handle` descarta em silêncio (fonte desconhecida, autenticador errado,
Message-Authenticator inválido ou ausente quando exigido, Event-Timestamp fora da janela de 300 s,
duplicata ainda em processamento), responde duplicatas do cache (mesma janela, como a §6.3 manda)
ou entrega um `DynAuthRequest`: seletor de sessão (Acct-Session-Id, User-Name, Framed-IP,
Framed-IPv6-Prefix, NAS-Port, NAS-Port-Id, Calling/Called-Station-Id, CUI, Agent-Circuit-Id/
Remote-Id), mudanças de autorização, `authorize_only` (§3.2) e, quando a RFC já decide a resposta,
o `precheck` (401 atributo não suportado, 402 sem identificação/State, 403 NAS errado, 404, 405).
O daemon acha as sessões (`SessionSelector::select`), aplica em todas ou em nenhuma (atomicidade,
§2.3) e responde com `respond(…, Ack | Nak(ErrorCause))`; Proxy-State e State voltam como a RFC
manda, e toda resposta leva Message-Authenticator e Event-Timestamp.

**Melhor que o RouterOS onde a RFC deixa:** o RouterOS não troca IP nem pool por CoA ("a user
must be disconnected first"). A RFC 5176 (nota 6) diz como: CoA com Service-Type Authorize Only →
o NAS responde CoA-NAK 507 e manda um Access-Request; o Access-Accept novo traz o endereço. O
servidor já entrega isso pronto (`authorize_only`, State); o G4.3d faz a reautorização e, quando o
PPP permite, a renegociação do IPCP.

## Testes

- **Exemplos das RFCs como testes dourados:** RFC 2865 §7.1, §7.2 e §7.3 com as erratas
  verificadas 1469 e 6486 (o pacote impresso da §7.3 tem o tamanho do State errado e é recusado;
  o corrigido decodifica); RFC 5997 §6.1–§6.3 (a §6.2 imprime o código 02, mas o autenticador foi
  calculado sobre o código 5: erro de digitação do dump, documentado no teste); RFC 2759 §9.2
  (NT-Response e "S=407A…") e §9.3 (chaves DES com paridade); RFC 3079 §3.5.3 (chave mestra e
  chave de envio, que é a do servidor).
- **Proptest em tudo:** codec (ida e volta, assinatura confere só com o segredo certo, pacote
  válido com bytes trocados), User-Password, sal, atributos longos, rate-limit (formatar e ler é
  identidade, a forma canônica é estável), agenda de interims, serviço Juniper, dicionário.
- **Fuzzing:** alvo `radius` no `fuzz/` e os mesmos oráculos no CI (`tests/fuzz.rs`), com
  sementes em `fuzz/seeds/radius/`.
- **Cliente contra o servidor de teste** (`tests/client.rs`): PAP/CHAP/MS-CHAPv2 com chaves
  MPPE decifradas, Blast-RADIUS, segredo errado, recuo e failover, servidor morto e Status-Server,
  `dead-time`, Acct-Delay-Time crescente, substituição de interim, idade máxima, crescimento de
  sockets e fila, pressão de volta, respostas falsas.
- **Simulação de carga** (`tests/load_sim.rs`): 100 000 Access-Requests e 100 000
  Interim-Updates (20 000 sessões), 3 % de perda em cada sentido, dois servidores de autenticação
  e dois de contabilização, o primário morto por um minuto. Confere a cada datagrama: nenhum
  identificador repetido enquanto pendente, retransmissão idêntica, failover com identificador e
  autenticador novos e Acct-Delay-Time que não diminui, tabelas internas consistentes, todo
  pedido termina uma vez. Resultado (**medido**): 233 243 datagramas, 30 199 retransmissões,
  3 034 failovers, 13 749 perdidos, 97 983 aceitos, 2 000 recusados, 17 timeouts (pedidos que
  perderam as três tentativas no único servidor vivo), 4 s em debug.
- **UDP de verdade em 127.0.0.1** (`tests/udp_loopback.rs`, sem root): 2000 pedidos em 8 sockets
  contra o servidor de teste numa thread; CoA e Disconnect de um DAC até o servidor dinâmico.
- **Interoperabilidade com FreeRADIUS** (`radclient`/`radtest`): não há `freeradius-utils` nesta
  máquina; ficou para o G4.3bb.

## Desempenho (**medido**, 2026-10-24, AMD Ryzen AI MAX+ 395, build release, `cargo bench -p corerouter-proto-radius`)

| Benchmark | Mediana | Por segundo |
|---|---|---|
| decodificar um Access-Request de BNG (13 atributos + VSAs) e percorrer tudo | 26 ns | 38 M |
| o mesmo passando pelo dicionário tipado | 334 ns | 3,0 M |
| montar Access-Request com PAP e Message-Authenticator | 757 ns | 1,3 M |
| conferir Access-Accept (MD5 + HMAC-MD5) e ler o Rate-Limit | 758 ns | 1,3 M |
| `Mikrotik-Rate-Limit` completo | 57 ns | 17,5 M |
| CoA: conferir, classificar e responder ACK | 1,85 µs | 541 k |
| cliente + servidor de teste, 1000 pedidos (os dois lados numa thread) | 2,7 µs/pedido | 368 k |

O custo é o MD5/HMAC-MD5 (três ou quatro por pedido). Uma tempestade de 10 000 assinantes
religando custa ~27 ms de CPU no cliente (**estimado** a partir da linha de cima). Melhoria
possível: guardar o estado do HMAC (ipad/opad) por segredo — G4.3bc.

## RADIUS como serviço do sistema (G4.3j)

O `proto-radius` não abre socket; quem o põe na rede é o serviço `radius` do daemon
(`apps/corerouter-daemon/src/service/radius.rs` e o driver `radius_aaa.rs`). PPP (G4.3d), IPoE
(G4.3f), hotspot e o login do roteador pedem por ele; ninguém fala RADIUS por conta própria.

### Comandos (nomes do RouterOS v7)

| Comando | O quê |
|---|---|
| `radius.add/set/remove/enable/disable/move/list` | `/radius`: `address`, `service` (ppp, login, hotspot, wireless, dhcp, ipsec, dot1x), `secret` (só escrita: a lista mostra `***`), `authentication_port` 1812, `accounting_port` 1813, `timeout` 1100 ms, `src_address`, `vrf`, `require_message_auth` (`yes-for-request-resp`), `protocol` (udp; radsec no G4.3ba), `realm`, `called_id`, `domain`, `accounting_backup`, `status_server`, `disabled`, `comment`. A ordem é a do failover (`radius.move`) |
| `radius.incoming.set/get` | `/radius incoming`: `accept` (no), `port` (**3799**, RFC 5176 §2.3; o RouterOS usa 1700), `vrf`, `replay_window` (300 s), `require_event_timestamp`, `require_message_auth`; o `get` traz os contadores |
| `radius.monitor` | `/radius monitor` por servidor: estado (`up`, `down`, `probing`, `disabled`, `idle`), pending, requests, accepts, rejects, acct_responses, resends, timeouts, bad_replies, unsolicited, last_request_rtt, sockets |
| `radius.test` | tarefa: um Access-Request de teste (PAP) pelo serviço, e a resposta com os atributos decodificados pelo nome (o RouterOS não tem) |
| `ppp.aaa.set/get` | `/ppp aaa`: `use_radius`, `accounting`, `interim_update` (0 ou 60..86400 s, RFC 2869 §5.16), `interim_jitter` (20 %), `use_circuit_id_in_nas_port_id`, `enable_ipv6_accounting` |

Recusado: segredo vazio, `src_address` que não é endereço do roteador ou é de outra família, o
mesmo servidor (endereço, porta, VRF) duas vezes para o mesmo serviço, RadSec.

### O serviço

- **Uma pista por serviço** (ppp, login…): um `Client` com as entradas daquele serviço na ordem
  do failover — autenticação na ordem da lista; contabilização com as `accounting_backup` depois
  das outras. Cada socket UDP sai do `src_address` (e do VRF, com `SO_BINDTODEVICE`); o cliente
  pede outro socket quando os 256 identificadores de um acabam (até 16 por servidor) e uma thread
  leitora por socket entrega os datagramas ao driver.
- **Estado por servidor:** `up`; `down` depois de 3 trocas falhas seguidas (pulado por 30 s);
  `probing` quando `status_server=yes` (RFC 5997). Servidor fora do ar e de volta vão para o log.
- **Config nova sem perder pedido:** uma mudança constrói pistas novas; as velhas terminam o que
  têm pendente (um Stop de contabilização não se perde por um `radius.set`) e os contadores delas
  somam nos totais do monitor.
- **API sem async** (`corerouter_engine::radius::AaaBackend`, os tipos em
  `corerouter_model::radius`): `authenticate(pedido, callback)` → Accept/Reject/Challenge/
  Timeout/Error com os atributos decodificados, o pacote e o autenticador do pedido (para as chaves
  MPPE); `account(pedido, fonte de contadores)` → Start/Interim-Update/Stop. Um Start com fonte
  agenda os interims da sessão (intervalo do Acct-Interim-Interval ou do `ppp.aaa interim_update`,
  com dispersão fixa por sessão dentro de `interim_jitter` % do intervalo, nunca depois do
  intervalo); um interim novo substitui o pendente da mesma sessão. O callback roda na thread do
  serviço, que nunca trava a sessão: os logs vão por uma fila que o serviço descarrega.
- **CoA e Disconnect** (`/radius incoming`): as origens aceitas são as entradas ativas do
  `/radius`, cada uma com o seu segredo; origem desconhecida é descartada sem resposta (RFC 5176
  §5), Event-Timestamp fora da janela também; a retransmissão recebe a mesma resposta do cache,
  sem aplicar de novo. O pedido conferido vai aos donos de sessão registrados
  (`AaaBackend::register_owner`, o ponto em que o G4.3d se pluga) e, sem dono que o aceite, volta
  NAK com Error-Cause 503 (Session Context Not Found).
- **Log em português**, tópico `radius` (`servidor … fora do ar; usando o próximo da lista`,
  `… recusado por …`, `CoA de … aceito`).

Limites conhecidos: o `realm` e o `called_id` usados são os da primeira entrada do serviço (os
atributos são os mesmos para todos os servidores do failover); uma entrada com
`require_message_auth=no` baixa a exigência da pista inteira (senão as respostas dela seriam todas
descartadas).

### Testes

- Comandos (`crates/engine/src/cmd/radius.rs`, `ppp_aaa.rs`): sucesso, validação, rollback,
  ordem do failover, `radius.test` como tarefa.
- Serviço contra o servidor de teste em UDP de verdade (`service/radius_aaa_tests.rs`, sem root):
  atributos da resposta; retransmissão (primeira perdida) e timeout (três envios: 100 + 200 +
  400 ms); failover com o primário caído (marcado `probing`, o próximo pedido vai direto ao
  segundo); 10 000 autenticações de uma vez sem colisão de identificador; contabilização (Start,
  Stop, Gigawords) e `accounting=no`; dispersão de 10 000 interims; CoA aceito, retransmitido
  (cache), com Event-Timestamp velho (descartado), de origem desconhecida (descartado) e sem dono
  (NAK 503); recarga com pedido pendente.
- Ponta a ponta no daemon (`apps/corerouter-daemon/tests/radius.rs`): `radius.add` e
  `radius.test` pelo canal de controle contra o servidor de teste em 127.0.0.1, o monitor, o log
  e um Disconnect respondido com NAK 503.

### Desempenho (**medido**, 2026-10-24, AMD Ryzen AI MAX+ 395, build release, `cargo bench -p corerouter-daemon --bench radius_aaa`)

| Benchmark | Mediana | Por segundo |
|---|---|---|
| uma autenticação de cada vez, ida e volta pelo serviço (fila, PAP + Message-Authenticator, UDP em 127.0.0.1, resposta conferida e decodificada, callback) | 13,9 µs | 72 k |
| 1000 autenticações ao mesmo tempo | 5,15 ms por lote | 194 k |

O servidor de teste roda numa thread só, então o número é do caminho inteiro, não só do cliente.
O buffer de recepção dos sockets pesa: com o padrão do kernel (~200 KiB) a rajada de 1000
respostas transbordava e o lote levava 6,6 s (retransmissões de 5 s); com 4 MiB pedidos no socket
(limitado por `net.core.rmem_max`), 5,15 ms.

## Pesquisa

### Fontes

- **RFCs** (cadeia completa no Datatracker e erratas): RFC 2865 (atualizada por 2868, 3575,
  5080, 6929, 8044, 9765; erratas 368, 1469, 2712, 6486), RFC 2866, RFC 2869, RFC 3162, RFC
  6911, RFC 6929 (§2.1/§2.2 formatos, §2.8 atributo inválido), RFC 8044 (tipos), RFC 5080 (§2.2.1
  retransmissão com IRT/MRC/MRT/MRD e RAND, §2.2.2 duplicados e LRU de identificadores, §2.3
  contabilização), RFC 5997 (Status-Server: §3, §4.1 não retransmitir, Message-Authenticator
  obrigatório, aceitar 2 ou 5; §6 exemplos), RFC 5176 (obsoleta a 3576; atualizada por 8559 e
  9765: §2.3 porta 3799, todo atributo obrigatório, atomicidade; §3 identificação; §3.2 Authorize
  Only; §3.5 Error-Cause; §3.6 tabela; §6.3 Event-Timestamp e janela de 300 s), RFC 2548
  (Microsoft), RFC 2759 e RFC 3079 (MS-CHAPv2 e MPPE), RFC 2868 (túnel, sal), RFC 4679 (DSL
  Forum), RFC 9765 (RADIUS/1.1 sobre TLS, sem MD5). Blast-RADIUS: CVE-2024-3596
  (blastradius.fail) e o rascunho "deprecating RADIUS/UDP" do RADEXT.
- **MikroTik RouterOS v7** (help.mikrotik.com, "RADIUS"): `timeout` 1100 ms,
  `require-message-auth=yes-for-request-resp`, `protocol=udp|radsec`, `/radius incoming`
  (`accept`, `port=1700`, `vrf`), tabela de atributos recebidos e enviados, sintaxe do
  Rate-Limit com os exemplos, CoA que não troca IP/pool, Acct-Session-Id e Calling-Station-Id.
- **Outros:** FreeRADIUS (dicionários `mikrotik`, `microsoft`, `erx`; `radclient`; Status-Server
  e "zombie period"), Juniper MX/ERX (Activate-Service/Deactivate-Service com parâmetros), Cisco
  IOS-XE (`radius-server deadtime`, `automate-tester`), accel-ppp (`dae-server` para CoA/Disconnect), VyOS.
  Crate `radius` (moznion, MIT, parado desde 2024, sem RFC 4679 nem CoA no lado do NAS): por isso
  codec próprio.

### O que adotamos

O comportamento e os nomes da MikroTik nos atributos (os sistemas brasileiros mandam isso), o
`timeout` de 1,1 s como tempo inicial, o Message-Authenticator obrigatório; a retransmissão da RFC
5080 em vez do tempo fixo; Status-Server da RFC 5997 e o "deadtime" da Cisco/FreeRADIUS para
servidor morto; duplicados e janela da RFC 5176 §6.3; Authorize Only para mudar endereço por CoA.

### Melhorias propostas (entraram)

- Interim com dispersão determinística por sessão (`acct::InterimSchedule`): depois de uma OLT
  reiniciar, os interims não chegam todos no mesmo segundo para sempre; nunca atrasa além do
  intervalo configurado; respeita o mínimo de 60 s (RFC 2869 §5.16).
- Interim pendente substituído pelo novo da mesma sessão.
- Mais de 256 pedidos em voo por servidor (sockets extras), com fila e pressão de volta.
- Precheck da RFC 5176 pronto: o daemon só decide o que é dele.
- Contadores por servidor como o `/radius monitor` (pendentes, aceitos, recusados, reenvios,
  timeouts, respostas ruins, RTT), mais respostas não solicitadas.

### Fora agora (viram gaps)

- RadSec (RADIUS sobre TLS, RFC 6614) e RADIUS/1.1 (RFC 9765): G4.3ba. O cliente é sans-IO; o
  transporte TLS entra por baixo sem mudar a máquina de estados.
- Goldens de interoperabilidade gravados com `radclient`/`radtest` do FreeRADIUS: G4.3bb.
- Estado do HMAC por segredo, para baixar o custo por pedido: G4.3bc.
- EAP (EAP-Message, RFC 3579) não é usado em PPPoE de provedor; atributos de wireless da MikroTik
  ficaram de fora do dicionário (podem vir por `Dictionary::load`).

## Extras e riscos

- **Risco: servidor antigo sem Message-Authenticator.** Com o padrão novo, um servidor velho que
  não manda Message-Authenticator no Access-Accept tem as respostas descartadas e todo login
  falha. Mitigação: o contador `bad_replies` sobe a cada uma (o G4.3d mostra na janela e no
  log) e `require_message_authenticator=false` existe, como o `require-message-auth=no` do
  RouterOS.
- **Risco: tempestade de reconexão.** Com milhares de PPPoE caindo juntos, o recuo exponencial
  e a dispersão espalham os pedidos; a fila por servidor e `max_pending` seguram a memória.
- **Risco: CoA forjado.** Só fontes na lista, segredo por fonte, autenticador conferido,
  Event-Timestamp opcionalmente obrigatório, cache limitado (`max_cache`).
- **Segredo:** o cliente não guarda senha em texto além do pedido pendente (necessário para
  reenviar a outro servidor com outro segredo); some quando o pedido termina.
