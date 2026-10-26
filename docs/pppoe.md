# PPPoE / BNG em Rust puro (`proto-pppoe`, G4.3)

Status: **G4.3a** feito; **G4.3d** feito (comandos, serviço `pppoe`, janela PPP e extras, §8) — o crate L2 `crates/proto-pppoe`: codecs de PPPoE e PPP e as máquinas
sans-IO do concentrador (servidor BNG) e do assinante (cliente, gerador de carga). Sem I/O, sem
`unsafe`, compila para `wasm32-unknown-unknown`. O serviço do daemon, os comandos `ppp.*` e a
janela PPP vêm na G4.3d; o plano de dados XDP por assinante é a G4.3c; o RADIUS é a G4.3b
(`proto-radius`).

**Decisão do usuário (2026-10-24):** BNG em Rust puro, não orquestrar o accel-ppp — "altíssimo
desempenho e algo fora da curva", com as RFCs e os padrões dos melhores roteadores e teste em massa
de cada etapa. O plano de controle (Discovery, LCP, autenticação, IPCP/IPv6CP) é nosso, sobre
AF_PACKET; o plano de dados é eBPF/XDP. Não usamos o `/dev/ppp` nem uma netdev `ppp` por sessão:
isso evita ioctls `unsafe` (proibidos fora do `dataplane-ebpf`) e o gargalo do kernel com dezenas
de milhares de interfaces. A comparação está em `docs/architecture.md` §1.4.

## 1. O que o crate tem

| Módulo | O quê | Norma |
|---|---|---|
| `eth` | Ethernet II com até duas tags (802.1Q, 802.1ad, 0x9100) | IEEE 802.1Q |
| `discovery` | PADI/PADO/PADR/PADS/PADT (+PADM/PADN), todas as tags; Agent-Circuit-Id/Remote-Id | RFC 2516 §4–§5 e Apêndice A, RFC 4638, RFC 4679 §5 (TR-101), RFC 4937 |
| `ppp` | cabeçalho de sessão, campo Protocol (com PFC tolerado na leitura), pacote de controle, opções | RFC 2516 §6, RFC 1661 §2, §5, §6 |
| `lcp` | códigos e todas as opções (MRU, ACCM, Auth-Protocol, Quality, Magic, PFC, ACFC, FCS-Alt, Callback, MRRU/Short-Seq/Endpoint de multilink só leitura) | RFC 1661 §6, RFC 1570, RFC 1990 §5.1 |
| `auth` | PAP; CHAP-MD5; MS-CHAPv1/v2 (resposta, authenticator response, mensagem de falha); chaves MPPE via `proto-radius` | RFC 1334 §2, RFC 1994 §4, RFC 2433, RFC 2759, RFC 3079 §3 |
| `ncp` | IPCP (IP-Address, DNS, NBNS, recusa VJ e IP-Addresses) e IPv6CP (Interface-Identifier) | RFC 1332 §3, RFC 1877 §1, RFC 5072 §4 |
| `nd` | IPv6 no enlace PPP (G4.3e): link-local do IPv6CP, identificador estável e opaco, RS/RA/NS/NA/Echo, RA com PIO, MTU, RDNSS e DNSSL, tempos do RA | RFC 5072 §5, RFC 8064, RFC 7217, RFC 5453, RFC 4861, RFC 8106, RFC 8200 §8.1 |
| `fsm` | o autômato de negociação de opções, célula por célula da tabela de transições, com os contadores do §4.6 | RFC 1661 §4 |
| `layers` | a lógica de opções de LCP/IPCP/IPv6CP para servidor e cliente | RFC 1661 §6, RFC 2516 §7, RFC 1332, RFC 5072 |
| `guard` | AC-Cookie HMAC-SHA-256 com segredo rotativo, limites de PADI (global e por MAC), gerador de desafios/magic | RFC 2516 §9 |
| `timer` | relógio explícito (`Millis`) e roda de timers (4096 × 16 ms) | — |
| `server` | o concentrador: Discovery, sessões num slab indexado pelo SESSION_ID, autenticação e endereço pedidos ao chamador, keepalive | RFC 2516, RFC 1661 §3 |
| `client` | o assinante: Discovery, LCP, PAP/CHAP/MS-CHAP como autenticado, IPCP/IPv6CP, keepalive | idem |
| `descriptor` | `SessionDescriptor`/`SessionKey`, com os nomes do `dataplane-ebpf-common::pppoe` (G4.3c) | — |
| `lab`, `fuzz` | o laboratório em memória (N clientes × servidores, rede hostil, relógio falso) e os oráculos de fuzz | — |

## 2. A API que o serviço (G4.3d) dirige

Tudo sans-IO, no mesmo padrão do DHCP e do RADIUS: o chamador entrega quadros e o tempo, e recebe
quadros para transmitir e eventos.

```rust
let mut bng = Server::new(ServerConfig { ac_mac, ac_name, local_ipv4, .. }, seed_do_getrandom, agora);
let mut out = ServerOutput::new();
bng.handle_frame(agora, ifindex, &quadro, &mut out);     // 0x8863 e 0x8864 do AF_PACKET
bng.handle_timers(agora, &mut out);                     // em bng.next_deadline()
for (ifindex, f) in out.frames() { /* sendto no AF_PACKET */ }
for ev in out.events.drain(..) {
    match ev {
        Event::Authenticate { session, request } => // local: request.verify_local(senha);
            // RADIUS: Access-Request com request.method; depois:
            { bng.auth_reply(agora, session, AuthVerdict::Accept(..), &mut out); }
        Event::NeedAddress { session } => { bng.address_reply(agora, session, Some(..), &mut out); }
        Event::Up { descriptor, .. } | Event::Changed { descriptor, .. } => // mapas XDP (G4.3c)
            {}
        Event::Down { key, ipv4, reason, .. } => // tira do XDP, devolve o endereço, Acct-Stop
            {}
    }
}
out.clear();
```

- **Uma `Server` é um espaço de SESSION_ID** (≤ 65 534 sessões; RFC 2516 §4: 0 e 0xffff
  reservados). As sessões ficam num slab indexado pelo SID: busca O(1), sem hash por pacote. Mais
  de 65 534 assinantes = uma `Server` por grupo de portas de acesso (a simulação de 100 mil usa
  duas).
- **`SessionRef { sid, gen_ }`** nomeia a sessão nas respostas assíncronas; uma resposta velha (a
  sessão acabou, o SID voltou) é ignorada. O SID livre volta numa fila FIFO: um SID é reusado o
  mais tarde possível.
- **`Authorization`** leva a resposta do RADIUS ou do `/ppp secret`: a string `S=` do MS-CHAPv2
  (obrigatória; sem ela o cliente recusa o Success, RFC 2759 §8.8), o endereço (Framed-IP), o
  `RateLimit` (`Mikrotik-Rate-Limit`, o tipo do `proto-radius`) e o Session-Timeout.
- **`SessionDescriptor`** é o que a G4.3c espelha nos mapas: `ifindex`, `sid`, `vlan`/`inner_vlan`
  (0 ou `TAGGED | VID`), `outer_tpid`, `mtu` (o MRU do assinante), `client_mac`, `server_mac`,
  `ipv4`, `ipv6_iid`, `rate_limit`; mais `username`, `auth`, `circuit_id`/`remote_id`
  (RFC 4679) e `session_timeout`.
- **Sem alocação por pacote:** a leitura é por fatias emprestadas do quadro; a saída vai para
  buffers do `Output` reusados (`clear` mantém a capacidade). Aloca-se por sessão (o slab, o
  nome do usuário) e por evento de autenticação, não por pacote.

## 3. Comportamento e padrões (RouterOS v7 + accel-ppp)

| Parâmetro | Padrão | De onde |
|---|---|---|
| `max_mru` / `max_mtu` | 1480 / 1480 | RouterOS `max-mru`/`max-mtu` |
| `max_payload` (RFC 4638) | desligado (1492) | RFC 4638 §5: ecoar só se suportado |
| `auth` | mschap2, mschap1, chap, pap | RouterOS `authentication` |
| `one_session_per_host` | sim | RouterOS |
| `max_sessions` | 65 534 | RouterOS `max-sessions` |
| `keepalive_interval_ms` × `keepalive_misses` | 5 s × 2 (= 10 s) | RouterOS `keepalive-timeout=10` |
| `fsm` | 3 s, Max-Terminate 2, Max-Configure 10, Max-Failure 5 | RFC 1661 §4.6 |
| `cookie_timeout_ms`, `require_cookie` | 5 s, sim | accel-ppp `cookie-timeout`; RFC 2516 §9 |
| `padi_limit`, `mac_padi_limit` | desligados | accel-ppp `padi-limit` |
| `pado_delay` | nenhum | accel-ppp `pado-delay` (faixas por número de sessões) |
| `vlans` | qualquer | RouterOS `pppoe-over-vlan-range` |
| `answer_timeout_ms`, `setup_timeout_ms` | 30 s, 60 s | — |

O caminho de uma sessão: PADI → PADO (com AC-Cookie) → PADR (cookie conferido) → PADS → LCP (o AC
fala primeiro: Configure-Request com MRU, Auth-Protocol e Magic) → autenticação (o AC manda o
Challenge; no PAP espera o pedido) → `Event::Authenticate` → `auth_reply` → Success →
IPCP/IPv6CP (o endereço já veio na autorização ou chega por `NeedAddress`; o Configure-Request
do assinante que chega antes fica guardado e é respondido quando o endereço chega, sem esperar
o temporizador dele) → `Event::Up`.

## 4. As regras das RFCs e onde cada uma é testada

| Regra | Nível | Teste |
|---|---|---|
| RFC 2516 §4: VER = TYPE = 1; LENGTH só do payload, enchimento Ethernet ignorado | MUST | `discovery::tests::rfc2516_4_*` |
| §4: SESSION_ID 0xffff reservado; único por sessão | MUST | `server::tests::rfc2516_4_sids_are_unique_nonzero_and_never_ffff`, `Lab::check` em toda simulação |
| §5.1: PADI com exatamente um Service-Name | MUST | `rfc2516_5_2_unserved_service_or_bad_padi_gets_no_answer` |
| §5.2: responder PADI só se puder servir | SHOULD | idem; `max_sessions_answers_ac_system_error_and_stops_offering` |
| §5.2: PADO com AC-Name e o mesmo Service-Name; Host-Uniq e Relay-Session-Id ecoados sem mudança | MUST | `rfc2516_5_2_pado_carries_ac_name_same_service_and_echoes` |
| §5.4: Service-Name recusado → PADS com Service-Name-Error e SID 0 | MUST | `rfc2516_5_4_bad_service_in_padr_is_service_name_error_with_sid_zero` |
| §5.4: falta de recurso → AC-System-Error | MAY | `max_sessions_answers_ac_system_error_and_stops_offering` |
| §5.5: depois do PADT nenhum tráfego PPP, nem Terminate | MUST | `rfc2516_5_5_padt_from_the_host_frees_at_once_and_silently` |
| §7: MRU ≤ 1492; ACCM, ACFC e FCS-Alternatives recusados; PFC NOT RECOMMENDED | MUST/MUST NOT | `layers::tests::rfc2516_7_*` |
| §9: AC-Cookie contra DoS, regenerável a partir do MAC | SHOULD | `guard::tests::rfc2516_9_*`, `rfc2516_9_padr_without_valid_cookie_creates_nothing`, `padr_flood_with_forged_cookies_creates_nothing`, `ac_cookie_replay_is_refused` |
| RFC 4638 §5: PPP-Max-Payload ecoado só se suportado | MUST | `rfc4638_ppp_max_payload_echoed_only_when_supported` |
| RFC 4679 §5: Agent-Circuit-ID/Remote-ID (≤ 63) no Vendor-Specific 3561 | — | `discovery::tests::rfc4679_*` |
| RFC 1661 §2: Protocol ímpar/par; PFC lido | MUST | `ppp::tests::rfc1661_2_*`, `rfc1661_6_5_*` |
| §4.1: a tabela de transições, célula a célula | MUST | `fsm::tests` (19 casos) |
| §4.6: restart 3 s, Max-Terminate 2, Max-Configure 10, Max-Failure 5 | SHOULD | `rfc1661_4_6_*` |
| §5: octetos além de Length são enchimento; Length < 4 descartado | MUST | `rfc1661_5_padding_past_length_is_ignored` |
| §5.2: Ack com o Identifier e as opções exatas do último Request; resposta duplicada não conta duas vezes | MUST | `rfc1661_5_2_ack_must_match_id_and_options`, `rfc1661_5_2_a_duplicated_ack_does_not_renegotiate` |
| §5.4: Reject só com opções pedidas | MUST | `rfc1661_5_4_reject_must_be_a_subset_of_the_request` |
| §5.6/§5.7: Code-Reject e Protocol-Reject; RXJ- fatal | MUST | `rfc1661_5_6_code_reject_of_a_needed_code_is_fatal` |
| §5.8: Echo só em Opened, Magic zero se não negociado | MUST | `rejecting_auth_is_fatal_for_the_server` (magic 0), simulações (echo dos dois lados) |
| §6.4: Magic zero sempre Nak; loop → Nak com outro valor | MUST | `rfc1661_6_4_magic_zero_and_own_magic_are_naked` |
| §3.5: link renegociado autentica de novo | — | `mass_reconnect_after_an_outage`, `heavy_loss_duplication_and_reordering` |
| RFC 1334 §2.2.1: Identifier novo em cada Authenticate-Request | MUST | `rfc1334_lost_pap_ack_is_recovered` |
| RFC 1994 §4.1: Identifier novo em cada Challenge; Responses repetidas aceitas depois do Success | MUST | `rfc1994_4_1_lost_success_is_recovered_by_a_repeated_response` |
| RFC 1994 §4.2: falha → o autenticador SHOULD encerrar | SHOULD | `wrong_password_is_refused_and_cleaned_up`, `authentication_failures_at_scale_leave_nothing_behind` |
| RFC 2759 §8, §9.2: amostras do MS-CHAPv2 (NT-Response, "S=…") | — | `auth::tests::rfc2759_9_2_sample_data` |
| RFC 2759 §8.8: o cliente confere o authenticator antes de aceitar | MUST | `rfc2759_verify_accepts_the_sample_and_refuses_a_wrong_password` |
| RFC 2433 Apêndice B: amostra do MS-CHAPv1 | — | `rfc2433_b_sample_nt_response` |
| RFC 3079 §3.5.3: chaves MPPE de 128 bits da amostra | — | `rfc3079_3_5_3_sample_128_bit_keys` |
| RFC 1332 §3.3 / RFC 1877: Nak com o endereço e o DNS; sem DNS → Reject | — | `rfc1332_3_3_server_naks_with_the_assigned_address` |
| RFC 5072 §4.1: identificador zero ou igual ao nosso → Nak com outro | MUST | `rfc5072_4_1_zero_or_equal_iid_is_naked` |

## 5. Teste em massa

Cada etapa tem os seus testes de unidade (acima); por cima deles, `tests/sim.rs` põe N assinantes
contra o BNG no laboratório em memória (`lab`): relógio falso, perda, duplicação, reordenação com
atraso, autenticação com latência de RADIUS, pool de endereços, reconexão como a de um CPE. Toda
simulação termina com `Lab::check` (índices do servidor consistentes, SIDs únicos, uma sessão por
assinante, nenhum endereço emprestado duas vezes ou a sessão morta) e, quando faz sentido, com o
desmonte: todos mandam PADT e não sobra sessão nem endereço.

| Simulação | Rede | Confere |
|---|---|---|
| `hundred_thousand_sessions_reach_opened_on_a_lossy_network` | 100 000 assinantes, 2 portas, PAP + CHAP, 0,5 % perda, 0,2 % duplicação, 1 % reordenação | as 100 000 sessões em Opened; nenhuma morte além de keepalive; nada sobra depois do PADT |
| `heavy_loss_duplication_and_reordering` | 2000, os quatro métodos, 5 % perda, 5 % duplicação, 10 % reordenação (até 50 ms) | nenhuma sessão morre por erro de protocolo; todas voltam quando a rede sara |
| `mschap2_at_scale_with_ipv6cp` | 5000, MS-CHAPv2 + IPv6CP | IPCP e IPv6CP em todas |
| `padi_flood_creates_no_state_and_legit_hosts_still_connect` | 200 000 PADIs de MACs aleatórios em 10 s, com `padi_limit` 2000/s e 1/s por MAC | PADI não cria estado; os 1000 assinantes legítimos entram |
| `padr_flood_with_forged_cookies_creates_nothing` | 100 000 PADRs com cookie forjado | zero sessões |
| `ac_cookie_replay_is_refused` | PADR capturado e repetido: igual, de outro MAC, depois do timeout, depois da sessão acabar | cookie preso ao MAC; a cópia não cria sessão; expirado não abre nada |
| `authentication_failures_at_scale_leave_nothing_behind` | 10 000, 10 % senha errada | 9000 em Opened, 1000 recusados sem endereço nem sessão |
| `mass_reconnect_after_an_outage` | 20 000 em Opened, 60 s sem rede, volta | o keepalive derruba todas; todas voltam juntas |
| `cpe_reboot_storm_replaces_sessions_one_per_host` | 5000 CPEs reiniciam sem PADT | one-session-per-host troca cada uma; nada duplica |

`tests/fuzz.rs` roda os oráculos de `src/fuzz.rs` com proptest (bytes aleatórios e quadros reais
de uma conversa do laboratório com bits trocados, bytes cortados e inseridos) e um oráculo de
**conversa viva**: cliente e servidor reais conversando com edições nos quadros em voo nos dois
sentidos; depois das edições a rede sara e tudo tem de terminar limpo. `PPPOE_FUZZ_CASES=N` aumenta
a rodada. A rodada longa com libFuzzer fica em `crates/proto-pppoe/fuzz` (alvos `discovery`,
`session`, `server`, `client`, `conversation`): `cd crates/proto-pppoe/fuzz && cargo +nightly fuzz run
-s none server -- -max_total_time=600`.

### O que a simulação achou (e foi corrigido)

A simulação em massa não é decoração: com a rede hostil ela achou oito defeitos de
interoperabilidade que os testes por regra não pegavam.

1. **Configure-Ack duplicado renegociava o LCP** (Opened × RCA → tld, scr). Agora cada
   Configure-Request recebe uma resposta só; cópias atrasadas com o mesmo Identifier são
   descartadas (o `seen_ack` do pppd; RFC 1661 §5.2).
2. **LCP renegociado não autenticava de novo** no servidor, e o cliente esperava um Challenge que
   não vinha. RFC 1661 §3.5: depois de renegociar, a fase Authenticate volta; um veredito ainda a
   caminho da tentativa velha é descartado.
3. **Success do CHAP perdido**: o cliente ficava em Authenticate e o IPCP do servidor falhava. O
   cliente repete a Response e o servidor responde na fase Network (RFC 1994 §4.1).
4. **Ack do PAP perdido**: a repetição vem com Identifier novo (RFC 1334 §2.2.1) e era ignorada.
5. **Challenge duplicado** fazia o cliente MS-CHAPv2 responder com outro Peer-Challenge, e o
   Success do servidor não batia mais. Challenge repetido → a mesma Response.
6. **Challenge velho reordenado** (de antes de uma renegociação) chegava depois do vivo; o
   cliente passava a responder só ao velho. Ele agora lembra as Responses da fase e aceita o
   Success de qualquer uma.
7. **PADR duplicado e atrasado** chegava depois do LCP começar e, com one-session-per-host,
   derrubava a sessão. A cópia do PADR que criou a sessão (mesmo Host-Uniq e AC-Cookie) recebe o
   mesmo PADS em qualquer fase, conferida antes da idade do cookie.
8. **PADT do servidor perdido** deixava o cliente "em pé" sem sessão. O cliente tem keepalive
   próprio (como o `lcp-echo-interval` do pppd) e o servidor responde a quadro de sessão
   desconhecida com PADT (limitado a 100/s, para não virar refletor).

## 6. Pesquisa

Fontes (veja também `docs/research-sources.md`):

- **MikroTik RouterOS v7**: `PPPoE` (`/interface pppoe-server server`: `service-name`, `max-mtu`,
  `max-mru`, `mrru`, `authentication`, `keepalive-timeout`, `one-session-per-host`,
  `max-sessions`, `pado-delay`, `default-profile`, `pppoe-over-vlan-range`), `PPP AAA`
  (`/ppp profile`, `/ppp secret`, `rate-limit`), `RADIUS` (`Mikrotik-Rate-Limit`) —
  help.mikrotik.com/docs.
- **accel-ppp** (o BNG do VyOS): `[pppoe]` `ac-name`, `service-name`, `pado-delay`,
  `padi-limit`, `cookie-timeout`, `mac-filter`, `ifname-in-sid`, `tr101`; `[ppp]` `lcp-echo-*`,
  `mtu/mru`, `ipv6`, `single-session` — accel-ppp.org/docs.
- **Juniper Junos** (subscriber management): perfis dinâmicos, `pppoe-options`
  (`service-name-table` com ação por nome, `max-sessions`, limites por VLAN/MAC), keepalive,
  `short-cycle protection` (atraso crescente para quem reconecta em loop).
- **Cisco IOS-XE** (BBA groups): `pppoe limit per-mac`/`per-vlan`, `pppoe throttle` (taxa por
  MAC/VLAN), `ppp lcp delay`, `ppp max-configure/max-failure`.
- **RFCs**: RFC 2516 (PPPoE; errata no rfc-editor), RFC 4638 (PPP-Max-Payload), RFC 4679 (DSL
  Forum vendor attributes / TR-101), RFC 4937 (PADM/PADN), RFC 5578 (credits, não usado), RFC 1661
  (PPP; atualizada pela RFC 2153 e RFC 5342), RFC 1570 (Identification, Time-Remaining), RFC 1990
  (multilink, só leitura), RFC 1334 (PAP), RFC 1994 (CHAP; atualizada pela RFC 2484), RFC 2433
  (MS-CHAPv1), RFC 2759 (MS-CHAPv2), RFC 3079 (MPPE), RFC 1332 (IPCP; atualizada pela RFC 3241),
  RFC 1877 (DNS/NBNS), RFC 5072 (IPv6CP; atualizada pela RFC 8064, que recomenda identificador
  estável e opaco). Cada regra está citada no código e no teste (tabela do §4).

O que o MikroTik faz e adotamos: os nomes e os padrões (§3), mschap2 primeiro, one-session-per-host
ligado, keepalive de 10 s, VLAN por faixa, MRU 1480. O que os outros fazem melhor e entrou já:
AC-Cookie obrigatório e sem estado por PADI (RFC 2516 §9; o RouterOS não documenta cookie),
limites de PADI global e por MAC e `pado-delay` por número de sessões (accel-ppp, Cisco
throttle), Relay-Session-Id e Agent-Circuit-Id/Remote-Id (TR-101) guardados no descritor para o
RADIUS, PADT para quadro de sessão desconhecida (limitado), resposta ao PADR repetido com o mesmo
SID.

### Melhorias propostas

- **Entra agora:** tudo testado em massa no CI (100 mil sessões, ataques, apagão), coisa que
  nenhum dos outros publica; o servidor pergunta autenticação e endereço por evento, então local,
  RADIUS e a futura API do motor são o mesmo caminho; descritor de sessão pronto para o XDP.
- **Vira gap depois:** short-cycle protection do Junos (atraso crescente para quem reconecta em
  loop) e limite por VLAN; `Service-Name` com ação (perfil diferente por nome); LCP echo
  adaptativo (só quando não há tráfego, lendo os contadores do XDP: o plano de controle não vê
  os dados); SID por VLAN para passar de 65 534 por porta; IPv6CP com identificador estável
  (RFC 8064) — entram na G4.3d/G4.3e.

### O que ficou de fora e por quê

- **Capturas reais do pppd/rp-pppoe como golden:** o pppd precisa do `/dev/ppp` e de root (o
  dispositivo é `crw------- root`); agentes não usam `sudo`. As amostras das RFCs (MS-CHAPv1/v2,
  MPPE) são goldens, e a interoperabilidade real fica para a G4.3g (BNG Blaster em enlace de
  verdade, rodada pelo usuário).
- **MS-CHAP LM response, EAP, CBCP, multilink, compressão (VJ, CCP/MPPE no plano de dados):**
  obsoletos ou fora do caminho de um BNG de ISP; as opções são lidas e recusadas como manda a RFC.
- **MPPE no plano de dados:** só as chaves (RFC 3079) existem, para o RADIUS; cifrar no XDP não
  faz sentido em PPPoE de ISP.

## 7. Desempenho

Números do `cargo bench -p corerouter-proto-pppoe --bench pppoe` (**medido**, Ryzen AI Max+ 395,
release; a tabela completa vai para `docs/perf.md` pela fila): ler um PADI 25 ns, um
Configure-Request do LCP 26 ns; responder um PADI com PADO (com o HMAC do cookie) 176 ns, um Echo
numa sessão aberta 31 ns; uma sessão inteira, de PADI a IPCP Opened, 6,3 µs contando servidor,
cliente e a rede simulada (≈ 159 mil sessões por segundo num núcleo). A sessão ocupa ≈ 750 B no
servidor (**estimado** a partir dos 624 B **medidos** da `Session`). O plano de controle não é o
gargalo: uma reconexão em massa de 100 mil assinantes custa menos de 1 s de CPU; o que limita é
a rede de acesso e o RADIUS.

## 8. Serviço (G4.3d): comandos, daemon e janela PPP

A G4.3d liga o crate ao roteador em quatro PRs empilhados: **(a)** modelo e comandos, **(b)** o
serviço `pppoe` no daemon, **(c)** a janela PPP, **(d)** os extras aprovados. Este parágrafo é o
desenho dos quatro; cada PR atualiza o que mudou.

### 8.1 Pesquisa

- **MikroTik RouterOS v7** — [PPP AAA](https://help.mikrotik.com/docs/spaces/ROS/pages/132350049/PPP+AAA)
  (o help.mikrotik.com está congelado; o manual novo é manual.mikrotik.com/docs/7.25) e
  [PPPoE](https://help.mikrotik.com/docs/display/ROS/PPPoE):
  - `/interface pppoe-server server`: `service-name` (vazio: qualquer), `interface`, `max-mtu` e
    `max-mru` 1480, `mrru` desligado, `authentication` mschap2,mschap1,chap,pap,
    `keepalive-timeout` 10 (o cliente cai depois de 2 × o tempo), `one-session-per-host` **no**,
    `max-sessions` 0 = sem limite, `default-profile` default, `pppoe-over-vlan-range` (faixas
    `100-115,120`), `accept-untagged` yes. `pado-delay` existe no RouterOS mas a página não o
    documenta.
  - `/ppp profile`: `local-address`/`remote-address` (endereço ou pool), `dns-server`,
    `rate-limit` (`rx/tx [burst [limiar [tempo [prioridade [mínimo]]]]]`, do ponto de vista do
    roteador: rx = upload do assinante), `address-list`, `only-one` (yes/no/default; ignorado com
    RADIUS), `change-tcp-mss` (o manual recomenda desligar acima de 10 sessões e usar uma regra
    mangle), `idle-timeout`, `session-timeout`, `on-up`/`on-down` (scripts com `$user`,
    `$remote-address`, `$caller-id`, `$interface`…). Dois perfis embutidos que não se apagam:
    `default` (only-one=no, change-tcp-mss=yes) e `default-encryption`.
  - `/ppp secret`: `name`, `password`, `service` (any, pppoe, l2tp…), `profile` (default),
    `local-address`, `remote-address`, `caller-id` (o MAC no PPPoE), `limit-bytes-in/out`,
    `routes`, `comment`, `disabled`.
  - **Precedência:** secret > perfil do secret > `default-profile` do servidor; um endereço fixo
    ganha de um pool; com RADIUS, os atributos ganham e o que falta vem do perfil.
  - `/ppp active`: `name`, `service`, `caller-id`, `address`, `uptime`, `encoding`,
    `session-id`, `limit-bytes-*`, `radius`; `print stats` dá bytes e pacotes.
- **accel-ppp** (o BNG do VyOS, `accel-ppp.conf`): `[pppoe] pado-delay=0,100:100,200:5000` (atraso
  por número de sessões), `padi-limit`, `mac-filter`, `tr101`, `ifname-in-sid`; `[ppp]
  lcp-echo-interval/failure`, `single-session=replace`; `[radius] interim-verbose`, `dae-server`
  (CoA/DM); `[shaper]` aplica `Filter-Id`/vendor rate-limit; `[cli] show sessions` com colunas
  escolhidas (ifname, username, calling-sid, ip, rate-limit, uptime, rx/tx).
- **Juniper Junos** (subscriber management): perfis dinâmicos, `pppoe-underlying-options
  max-sessions`, `short-cycle-protection` (atraso crescente a quem reconecta em loop), `show
  subscribers extensive` e `show network-access aaa subscribers` com o motivo da última queda
  (`Terminate-Cause`).
- **Cisco IOS-XE** (BBA groups): `pppoe limit per-mac`/`per-vlan`, `pppoe throttle per-mac/
  per-vlan` (sessões por intervalo), `ppp lcp delay`, `show pppoe session` e `debug pppoe
  errors` — a resposta a "por que esse cliente não sobe" é um debug global, não uma consulta.
- **RFCs:** RFC 2516 (§4 SESSION_ID, §5.5 PADT, §9 AC-Cookie), RFC 1661 §3 (fases) e §5.8
  (Echo), RFC 2865 (Access-Request: NAS-Port-Type Virtual = 5, Service-Type Framed = 2,
  Framed-Protocol PPP = 1, Calling-Station-Id = MAC), RFC 2866 (Acct-Status-Type
  Start/Interim/Stop, Acct-Session-Id único, Acct-Terminate-Cause §5.10), RFC 2869 §5.16
  (Acct-Interim-Interval ≥ 60), RFC 5080 §2.2.1 (interims dispersos), RFC 5176 (CoA/DM: §3.2
  NAK 503 sem sessão, §3.5 Error-Cause), RFC 4679 (Agent-Circuit-Id/Remote-Id no NAS-Port-Id e no
  RADIUS), RFC 6911 (Framed-IPv6-*; G4.3e), RFC 3046 (opção 82; G4.3f).

### 8.2 O que adotamos

- **Nomes do RouterOS v7** em todos os comandos: `interface.pppoe-server.server.*`,
  `ppp.profile.*`, `ppp.secret.*`, `ppp.active.*`, `ppp.aaa.*` (G4.3j); os parâmetros usam `_` no
  lugar de `-`, como o resto do motor.
- **Padrões do RouterOS**, com três exceções de segurança, explicadas no ⓘ e na saída
  (`warnings`): `one_session_per_host=yes` (um CPE que reinicia sem PADT seguraria dois
  endereços), `ac_cookie=yes` (RFC 2516 §9; o RouterOS não documenta cookie) e limites de PADI
  e de sessões novas por segundo (accel-ppp `padi-limit`, Cisco `pppoe throttle`).
- **`on_up`/`on_down` são listas de comandos do motor**, não scripts: `[{command, params}]` com
  `$user`, `$remote-address`, `$local-address`, `$caller-id`, `$interface`, `$service` nos
  valores de texto. Validados ao gravar (o comando existe, aceita os parâmetros, não é tarefa nem
  comando PPP — sem laço), executados pelo serviço e registrados no journal como qualquer
  comando. Nada de interpretador.
- **Um servidor habilitado por interface** (o RouterOS aceita vários Service-Names na mesma porta):
  cada servidor é um espaço de SESSION_ID (RFC 2516 §4) e dois na mesma porta dariam o mesmo id a
  dois assinantes. Vários Service-Names por porta (com perfil por nome, como o
  `service-name-table` do Junos) ficam para uma gap.
- **Senha só de escrita:** `ppp.secret.list` mostra `***`; o journal mascara `password`
  (`auth::SECRET_KEYS`); o `/export` escreve o secret como linha comentada, sem a senha. Fica em claro no config porque CHAP e MS-CHAP precisam do segredo (RFC
  1994 §4.1).
- **Perfis embutidos** `default` e `default-encryption` existem sem entrada no config; editar um
  grava uma cópia; não se apagam nem mudam de nome. `default-encryption` existe pelo nome (quem
  vem do MikroTik o referencia); MPPE no plano de dados não faz sentido em PPPoE de ISP (§6).

### 8.3 Melhorias propostas (entram agora)

- **"Derruba N sessões" antes de aplicar:** mudar a interface, a VLAN ou o Service-Name, desligar
  ou remover um servidor com sessões ativas é recusado com o número (`force=yes` aplica). Em
  Safe Mode, a mudança se desfaz se o operador perder o roteador. O RouterOS derruba calado.
- **`ppp.why {name|mac}`:** até onde chegam os logins de um assinante (PADI → PADR → LCP → auth →
  NCP → up), quantas tentativas por etapa, e o motivo da última queda em português com o que
  fazer (do `DownReason` do `proto-pppoe` e do Reply-Message do RADIUS). Nos outros é um debug
  global (Cisco) ou um campo de texto (Junos).
- **`ppp.history`:** os últimos logins, falhas e quedas, filtráveis por usuário, MAC e evento.
- **`pado_delay_by_load`** (accel-ppp) e **`new_session_rate`**: num BNG carregado o PADO
  atrasa e um BNG mais leve responde antes; numa reconexão em massa as sessões novas entram a
  2000/s (padrão) em vez de uma rajada que derruba o RADIUS. 20 mil assinantes voltam em 10 s
  (**estimado**; o plano de controle faz ≈ 159 mil sessões/s, **medido** na G4.3a).
- **Conferências ao gravar:** pool inexistente, perfil inexistente, endereço fixo dentro de um
  pool (o pool pode emprestá-lo a outro), dois secrets com o mesmo endereço, IP na interface de
  acesso, VLAN que também é uma interface VLAN, autenticação vazia (recusada), só PAP, keepalive
  desligado.
- **Importação em massa:** um lote atômico (`command_batch`) de 10 mil `ppp.secret.add` custa
  um snapshot só (0,47 s em debug, **medido**); um comando sozinho copia a tabela de secrets que
  escreve (copy-on-write da seção, `CowArc`).

### 8.4 O serviço `pppoe` do daemon (PR b, feito)

- **Sockets:** um AF_PACKET por interface de acesso para 0x8863 (Discovery) e 0x8864 (sessão),
  com as APIs seguras do `hal-linux` (como `l2`/`dhcp`), VLAN pelo auxdata. Com o XDP da G4.3c
  ativo só os quadros de controle (LCP/PAP/CHAP/IPCP) e o que o XDP não trata sobem
  (`XDP_PASS`); sem ele (backend virtual, placa sem XDP), o serviço também carrega dados pelo
  caminho lento e conta os bytes.
- **Uma thread por grupo de portas** dona de um `proto_pppoe::Server` (≤ 65 534 sessões; mais
  sessões = mais grupos). Ela não segura o lock da `Session` na rede: lê o config em execução por
  instantâneo (os `Arc` das seções), e só pega o lock para os hooks e o journal, fora do laço de
  pacotes.
- **Autenticação:** `/ppp secret` primeiro (`request.verify_local`); se não houver o usuário e
  `ppp.aaa use_radius=yes`, `AaaBackend::authenticate` da G4.3j (o callback roda na thread do
  RADIUS e só manda a resposta por canal para a thread do PPPoE). `caller-id`, `service`,
  `disabled`, `only-one` e `limit-bytes-*` conferidos aqui.
- **Endereço:** fixo do secret → Framed-IP-Address → Framed-Pool → `remote_address` do perfil
  (pool, com `next_pool`). O pool do PPP é um alocador próprio do serviço sobre as faixas do
  `/ip pool`: um pool serve o PPP ou o DHCP, não os dois. Um endereço fixo já em uso recusa o
  login, em vez de dar o mesmo endereço a dois assinantes.
- **VLAN sem `unsafe`:** a tag que o kernel tira do quadro só se lê por `PACKET_AUXDATA`, sem
  binding seguro. Então cada VLAN do `pppoe-over-vlan-range` tem o seu socket com um filtro BPF
  clássico (`SKF_AD_VLAN_TAG`), e o socket diz a VLAN; até 512 VLANs sem XDP. QinQ fica com o
  XDP (G4.3l).
- **Limite de sessões novas no PADI:** sem PADO, o CPE repete o PADI com recuo. No PADR seria
  pior: a repetição traz um AC-Cookie que vence (5 s) durante o recuo, e 155 de 10 mil CPEs
  desistiam no teste em namespace antes da correção.
- **Plano de dados:** `Event::Up`/`Changed` → `pppoe_upsert` no mapa de sessões (G4.3c) com o
  `rate_limit` no policer; `Down` → `pppoe_remove`, devolve o endereço, Acct-Stop com
  Acct-Terminate-Cause.
- **Contabilização:** Start/Interim/Stop com os contadores por sessão do XDP (`AcctSource`); o
  keepalive vira "sem tráfego há N s" lido desses contadores, como proposto na G4.3a.
- **CoA/DM:** o serviço é um `SessionOwner` da G4.3j: rate-limit novo ao vivo (só o policer
  muda), Disconnect-Request → Terminate + PADT; mudança de Framed-IP = desconectar e o CPE volta
  com o endereço novo (o PPP não troca endereço numa sessão aberta sem renegociar o IPCP; isso
  vai explicado no ⓘ).
- **Identidade:** fonte `pppoe` do chip (G0.25) → o login de quem tem o endereço; o "Quem era?"
  do CGNAT mostra o login no instante.
- **address-list:** entrada dinâmica (`timeout`, não gravada) na subida, removida na queda.
- **Plano de dados escolhido sozinho:** com o XDP preso às portas de acesso
  (`ip.firewall.xdp`), as sessões vão para o mapa da G4.3c com a descida em XDP (`F_FAST_DOWN`;
  a entrega pelo kernel é a G4.3ca) e a subida pelo kernel (o `forward` e as filas veem tudo).
  Sem XDP (laboratório, placa sem XDP, teste sem root), o serviço carrega o IPv4: subida por
  socket raw com o anti-spoofing do XDP, descida por rota /32 num dummy `bng0`, lida por um
  socket que só vê o que o host envia. Correto, não rápido: ≈ 1500 sessões/s e alguns kpps por
  núcleo em debug.

### 8.5 Números (**medido**, release salvo indicação)

- Setup do BNG: **≈ 94 mil sessões/s** num núcleo, do PADI ao IPCP Opened, com MS-CHAPv2, pool,
  mapa XDP e histórico (`cargo bench -p corerouter-daemon --bench pppoe_bng`).
- Memória: **≈ 3,9 KB por sessão** com o servidor `proto-pppoe`, a tabela ativa, o histórico e o
  "Why?". 100 mil assinantes ≈ 390 MB. Um BNG com netdev por sessão (pppd/accel-ppp) paga a
  netdev no kernel (dezenas de KB cada, **estimado**).
- Ponta a ponta por veth, debug: 10 mil CPEs em 6,5 s; reconexão em massa de 10 mil em 34 s com
  `new_session_rate=1000`.

### 8.6 Extras (PR d)

- **Selo de identidade e "Quem era?" com o login PPPoE.** `ip.identity.lookup` pergunta ao
  serviço (`PppBackend::who`/`who_at`): o login de quem tem o endereço agora e, num instante
  passado, quem tinha, pelo histórico do serviço. O CGNAT › Quem era? (porta pública → endereço
  interno, G2.3) chega ao login. Clicar no selo abre PPP › Active Connections com a sessão.
- **Gráfico por assinante.** O serviço mede `rx_bps`/`tx_bps` a cada segundo pelos contadores da
  sessão (XDP ou caminho lento); a coluna Traffic desenha os últimos ~2 min. O histórico longo
  por login, no armazenamento do G4.5, é a G4.3o.
- **Aviso de inadimplência por address-list** (o que os provedores fazem com o MikroTik):
  1. o sistema de cobrança manda um CoA com `Mikrotik-Address-List=inadimplentes`. O endereço
     entra na lista na hora (entrada dinâmica), sem derrubar a sessão; o valor vazio tira o
     assinante da lista. No login vale o mesmo atributo no Access-Accept, ou o `address_list` do
     perfil;
  2. uma regra de dstnat leva o HTTP de quem está na lista para a página de aviso:

     ```sh
     corerouter-cli run ip.firewall.nat.add '{"chain":"dstnat","src_address_list":"inadimplentes","protocol":"tcp","dst_port":"80","action":"dst-nat","to_addresses":"10.0.0.2","to_ports":"80","comment":"aviso de inadimplência"}'
     ```

     e uma regra de filtro deixa só DNS e a página para essa lista, se o provedor bloqueia.
- **Comandos para o MCP:** tudo é comando com `params` documentado. Por exemplo, um agente
  responde "por que o João não conecta?" com `ppp.why {name}` e derruba um assinante com
  `ppp.active.remove {name}`.

### 8.7 Riscos e como evitamos

- **Travar o plano de controle:** nunca segurar o lock da sessão no laço de pacotes; hooks com
  limite (8 por perfil) e fora do laço; um panic numa thread do serviço é reiniciado pelo
  supervisor (G0.10) e as sessões caem — por isso nada de `unwrap`.
- **Reconexão em massa** derrubando RADIUS e pool: `new_session_rate`, `pado_delay_by_load`,
  `padi_limit`.
- **Address-list com muitos assinantes:** as entradas dinâmicas são no máximo 65 536 no
  roteador inteiro (`MAX_DYNAMIC`) e duram até 35 dias (o serviço as refaz a cada 30). Um perfil
  com `address_list` para 100 mil assinantes passa do teto: use a lista para os casos (os
  inadimplentes), não para todos.
- **Assinante preso no XDP depois da queda:** toda `Down` remove a entrada; o serviço, ao
  reiniciar, limpa o mapa inteiro antes de aceitar sessões (o PADT ao SID desconhecido faz o CPE
  reconectar).
- **Compatibilidade com quem vem do MikroTik:** os padrões diferentes vêm com aviso na saída e
  no ⓘ.

## 9. IPv6 por assinante (G4.3e)

Dual-stack no BNG: IPv6CP sobe o enlace com endereços link-local, um RA por sessão anuncia o /64
do enlace (SLAAC), o DHCPv6 da sessão entrega o prefixo delegado (IA_PD) e, se pedido, um
endereço (IA_NA), e o XDP leva o /64 e o PD nos mapas da G4.3c (o `PPPOE_V6` já é uma LPM com as
duas entradas por sessão e o `owns_v6` já confere a origem). PRs empilhados:

| PR | Parte |
|---|---|
| a | codecs: `proto-pppoe::nd` (RS/RA/NS/NA/Echo, RDNSS/DNSSL, identificador estável), `proto-dhcp::sub6` (DHCPv6 da sessão), IPv6CP com identificador estável e `use-ipv6` por sessão (`Server::set_ipv6`), simulação de 100 mil sessões dual-stack |
| b | serviço: perfil (`use_ipv6`, pools, `dhcpv6_lease_time`), RADIUS, contabilização, mapas XDP, e2e de 10 mil sessões dual-stack |
| c | janela PPP: colunas e ⓘ |

### 9.1 Pesquisa

Fontes:

- **MikroTik RouterOS v7** — `/ppp profile` (manual.mikrotik.com, 7.25, "PPP AAA"): `use-ipv6`
  (`yes | no | default | require`, padrão `default` = ligado com o pacote IPv6),
  `remote-ipv6-prefix-pool` (um prefixo do `/ipv6 pool` por cliente, com rota; vai no RA),
  `remote-ipv6-prefix-reuse` (um /64 só para todos os clientes do perfil), `dhcpv6-pd-pool`
  (pool do servidor DHCPv6-PD criado por sessão), `dhcpv6-use-radius`, `dhcpv6-lease-time`
  (desde 7.20, padrão 1d); `/ppp secret` `remote-ipv6-prefix` (prefixo fixo para o ND);
  `/ppp aaa` `enable-ipv6-accounting` (contadores IPv4 e IPv6 separados, só com rate-limit e com
  prefixo dado pelo PPP; não vale para o PD do DHCPv6 dinâmico). RADIUS: `Framed-IPv6-Prefix`,
  `Framed-IPv6-Pool`, `Mikrotik-Delegated-IPv6-Pool` (VSA 22); relatos no fórum de que o
  `Delegated-IPv6-Prefix` só funciona se o CPE pedir PD, de que o prefixo delegado **não vai na
  contabilização** e de que é preciso um pool por cliente para PD fixo.
- **accel-ppp** (o BNG do VyOS): `[ipv6-pool]` com `prefix` e `delegate`, `[ipv6-nd]`
  (`AdvManagedFlag`, `AdvOtherConfigFlag`, `AdvPrefixValidLifetime`, `AdvRDNSS`, intervalo do
  RA), `[ipv6-dhcp]` (o servidor DHCPv6 é por sessão e só entrega o que a sessão já tem,
  `pref-lifetime`/`valid-lifetime`), `ipv6-intf-id`/`ipv6-peer-intf-id` (fixo, `random` ou
  `calling-sid`), RADIUS `Framed-IPv6-Prefix`, `Delegated-IPv6-Prefix`, `Framed-Interface-Id`.
- **Juniper Junos** (subscriber management): perfis dinâmicos com
  `$junos-ipv6-ndra-prefix` (RA) e `$junos-ipv6-delegated-prefix`; `framed-ipv6-pool` e
  `delegated-ipv6-pool` do RADIUS; contadores de IPv6 separados por VSA; o prefixo do PD vai no
  Acct-Start.
- **Cisco IOS-XE** (BBA): `ipv6 nd prefix framed-ipv6-prefix`, `ipv6 dhcp pool` com
  `prefix-delegation aaa`, `ipv6 nd other-config-flag`; RA unicast por sessão.
- **BBF TR-187** (IPv6 em PPP): IPv6CP só negocia o identificador; o /64 do WAN por RA (SLAAC)
  ou WAN sem número (só PD); DHCPv6-PD obrigatório para a LAN do CPE; RA com O ligado quando o
  DHCPv6 entrega DNS e PD, M quando há IA_NA; prefixo e PD vindos do RADIUS. TR-177/RFC 7084 (CPE):
  o CPE pede IA_PD com ou sem IA_NA e aceita qualquer combinação.
- **RFCs**: RFC 5072 (IPv6CP; atualizada pela RFC 8064, "Recommendation on Stable IPv6 Interface
  Identifiers", que manda usar identificadores estáveis e opacos à la RFC 7217 em vez de
  derivados do MAC), RFC 7217 (o algoritmo), RFC 5453 (identificadores reservados), RFC 4861
  (ND: §4.1/§4.2/§4.3/§4.4 formatos, §4.6.2 PIO, §4.6.4 MTU, §6.1.1/§7.1.1 validação, §6.2.4
  e §6.2.6 tempos; atualizada pelas RFCs 5942, 6980, 7048, 7527, 7559, 8028, 8319 — a 8319
  sobe o limite do Router Lifetime e do MaxRtrAdvInterval), RFC 8106 (RDNSS/DNSSL; §5.1
  lifetime ≥ 3 × MaxRtrAdvInterval), RFC 8200 §8.1 (checksum; UDP com checksum 0 é inválido),
  RFC 9915 (DHCPv6, antes 8415; §16 validação, §18.3 respostas, §21.4/§21.21 T1/T2, §21.14
  Rapid Commit), RFC 3162 (RADIUS e IPv6: `Framed-Interface-Id` 96, `Framed-IPv6-Prefix` 97,
  `Framed-IPv6-Route` 99, `Framed-IPv6-Pool` 100), RFC 4818 (`Delegated-IPv6-Prefix` 123,
  também no Accounting-Request), RFC 6911 (`Framed-IPv6-Address` 168,
  `DNS-Server-IPv6-Address` 169, `Delegated-IPv6-Prefix-Pool` 171,
  `Stateful-IPv6-Address-Pool` 172). O dicionário do `proto-radius` já tem todos.

### 9.2 O que adotamos

- **Nomes do RouterOS** no perfil: `use_ipv6`, `remote_ipv6_prefix_pool`, `dhcpv6_pd_pool`,
  `dhcpv6_lease_time` (1d). Os pools são os `/ipv6 pool` que o DHCPv6 server já usa
  (`prefix_length` 64 para o enlace, 48–64 para o PD).
- **RADIUS por cima do perfil**, como no RouterOS: `Framed-IPv6-Prefix` e `Framed-IPv6-Pool`
  para o /64, `Delegated-IPv6-Prefix`, `Delegated-IPv6-Prefix-Pool` e
  `Mikrotik-Delegated-IPv6-Pool` para o PD, `DNS-Server-IPv6-Address` para o RDNSS,
  `Framed-Interface-Id` para o identificador do assinante.
- **O prefixo é da sessão** (accel-ppp, Junos): reservado quando o IPv6CP sobe, antes do
  Solicit, e devolvido no Down. O DHCPv6 da sessão (`sub6`) não tem tabela, hash nem diário: só
  responde com o que a sessão tem. Um CPE que reinicia com outro DUID recebe o mesmo prefixo.
- **RA por sessão**, unicast em resposta ao RS e periódico para `ff02::1` dentro da sessão: três
  iniciais em até 16 s, depois entre 200 e 600 s espalhados ao acaso (100 mil sessões não
  disparam juntas), nunca dois em 3 s (RFC 4861 §6.2.4/§6.2.6). PIO com L e A, MTU = o MRU
  negociado, RDNSS/DNSSL com lifetime de 1800 s (3 × 600, RFC 8106 §5.1), O ligado quando há PD
  ou DNS, M quando há IA_NA.
- **IA_NA sem pool próprio**: o endereço é o /64 do enlace + o identificador do IPv6CP do
  assinante, o mesmo que o SLAAC daria; um CPE que só faz DHCPv6 no WAN (TR-187 permite) recebe
  um endereço coerente.
- **Identificador estável e opaco** (RFC 8064/7217): hash com chave secreta da porta, das VLANs
  e do MAC do assinante; o mesmo assinante tem o mesmo link-local a cada reconexão, ninguém lê o
  MAC nele, outro roteador dá outro valor. Vale para o nosso lado e para a sugestão no Nak quando
  o CPE propõe zero ou colide.

### 9.3 Melhorias propostas

- **Entram agora:** o prefixo delegado vai no Acct-Start/Interim/Stop
  (`Delegated-IPv6-Prefix`, `Framed-IPv6-Prefix`, RFC 4818/6911), coisa que o RouterOS não
  manda; o PD reservado na subida (o RADIUS e o "Quem era?" sabem o prefixo antes do Solicit);
  `ppp.why` conta os pacotes ND/DHCPv6 descartados e por quê (hop limit, checksum, outro
  servidor); tudo testado em massa (10 mil sessões dual-stack no namespace, proptest dos codecs).
- **Viram gap depois:** contadores IPv4 e IPv6 separados no XDP (o RouterOS exige queue para
  isso; o nosso mapa de contadores pode ganhar as palavras de IPv6 — mexe no layout da G4.3c);
  `remote-ipv6-prefix-reuse` (um /64 para todos); PD-Exclude (RFC 6603); IPv6 no caminho lento
  (já é a G4.3l); prefixo fixo por secret (`remote-ipv6-prefix`).

### 9.4 O que ficou de fora e por quê

- **`dhcpv6-use-radius`:** no RouterOS o servidor DHCPv6 dinâmico faz outra consulta ao RADIUS no
  Solicit. Aqui o prefixo já vem no Access-Accept da sessão: um pedido a menos por assinante, sem
  janela em que o PPP está de pé e o PD ainda não. O parâmetro não entra.
- **Extensões de cabeçalho no ND/DHCPv6:** num enlace PPP não aparecem; um pacote com elas não é
  respondido (vai adiante como tráfego comum).
- **Relay de DHCPv6 para um servidor externo:** não é o modelo do BNG (o prefixo é da sessão);
  fica para pedido explícito.

### 9.5 O serviço (PR b)

- **Perfil** (`ppp.profile.add/set`): `use_ipv6` (`default|yes|no|require`), `remote_ipv6_prefix_pool`
  (um `/ipv6 pool` de `prefix_length` 64), `dhcpv6_pd_pool` (48–64), `dhcpv6_lease_time` (padrão 1d,
  mínimo 5m) e `dns_server_ipv6` (até 4; o perfil do RouterOS só tem DNS IPv4). O
  `ipv6.pool.remove` recusa um pool que um perfil usa.
- **Por sessão:** o servidor roda o IPv6CP em todas as portas e o `use_ipv6` do perfil vai por
  sessão antes do veredito (`Server::set_ipv6`). Quando o IPv6CP abre:
  - o serviço toma o /64 e o PD, nesta ordem de prioridade:
    1. `Framed-IPv6-Prefix` / `Delegated-IPv6-Prefix` do RADIUS (fixos; um prefixo já em uso por
       outra sessão não é dado, e o log diz);
    2. `Framed-IPv6-Pool` / `Delegated-IPv6-Prefix-Pool` ou `Mikrotik-Delegated-IPv6-Pool`;
    3. os pools do perfil;
  - o primeiro RA sai na hora.

  O alocador (`service/pppoe_bng6.rs`) é do serviço, sobre os `/ipv6 pool`. Ele percorre o pool
  sem materializá-lo, pula a primeira fatia e reusa as devolvidas.
- **Plano de controle IPv6 da sessão:**
  - RS → RA unicast;
  - NS ao nosso link-local → NA;
  - Echo ao nosso link-local → Echo Reply;
  - DHCPv6 → `sub6`, respondido do nosso link-local para o do CPE;
  - RA periódico conferido uma vez por segundo.

  O XDP já passa link-local e multicast para o AF_PACKET (`Stat::Ipv6Control`); o resto do IPv6 é
  o XDP que leva (o caminho lento de IPv6 é a G4.3l).
- **XDP:** o `PppoeSession` do HAL ganha `ipv6_prefix` e `delegated`; o `hal-linux` liga `F_IPV6`/
  `F_PD` e escreve as duas chaves LPM do `PPPOE_V6` (estruturas da G4.3c, sem mudança de layout). O
  CoA de rate-limit preserva os prefixos.
- **RADIUS:** `Framed-IPv6-Prefix`, `Delegated-IPv6-Prefix` e `Framed-Interface-Id` vão no
  Accounting-Start (o IPv6CP abre antes do Start quando vem junto) ou num Interim-Update, quando o
  IPv6 sobe depois do IPv4; também vão no Stop. O serviço RADIUS passa a codificar `ipv6prefix` e
  `ifid` (RFC 3162 §2.2/§2.3).
- **Comandos:** `ppp.active.list` ganha `ipv6_prefix`, `delegated_prefix`, `delegated_bound` e
  `link_local` (e o `find` procura nos prefixos); `interface.pppoe-server.monitor` ganha
  `ipv6_sessions`, `delegated` e `ipv6_dropped`.
- **Segredo do identificador estável:** `<config-dir>/pppoe-ipv6cp.key` (32 bytes, 0600, criado no
  primeiro uso); sem `--config-dir`, um por execução.
- **Testes:**
  - `pppoe_bng_tests` (1000 sessões dual-stack em memória: /64 e /56 distintos, RA com o prefixo e
    o RDNSS, Solicit com Rapid Commit que liga o PD, RS limitado a um por 3 s, prefixos devolvidos;
    RA periódico entre Min e Max; `use_ipv6=no`; prefixos do RADIUS e contabilização);
  - `netns_pppoe6` (10 mil CPEs dual-stack por veth, sem root);
  - `xdp_root` › `pppoe_bng_ops_reach_the_maps` (IPv6 do /64 e do /56 passa, de outro prefixo é
    falsificado), na rodada com root do CI.

### 9.6 Desempenho

`cargo bench` (**medido**, Ryzen AI Max+ 395, release, 2026-10-25): classificar um RS 8,7 ns,
montar o RA da sessão (PIO, MTU, RDNSS com 2 servidores, DNSSL) 72 ns, o identificador estável
(SHA-256) 70 ns, o DHCPv6 da sessão responder um Solicit com Rapid Commit (IA_NA + IA_PD + DNS)
444 ns. De ponta a ponta (`netns_pppoe6`, **medido**, mesma máquina, build de debug, veth): 10 mil
CPEs com IPv4, /64 pelo RA e /56 pelo DHCPv6-PD em 17,6 s (569 sessões/s). Uma reconexão de 100 mil assinantes dual-stack custa ≈ 60 ms de CPU nesses passos
(**estimado**: 100 mil × (RS + 3 RAs + Solicit)).

### 9.7 Riscos e como evitamos

- **Tempestade de RS/Solicit** numa reconexão em massa: a resposta é O(1) por sessão, sem
  alocação na tabela; o RA solicitado respeita o mínimo de 3 s; o DHCPv6 da sessão não consulta
  RADIUS.
- **Prefixo de outro assinante:** o XDP só aceita origem do /64 ou do PD da sessão (`owns_v6`) e
  o ND/DHCPv6 só sai pela sessão que perguntou; o pool nunca entrega o mesmo prefixo a duas
  sessões (o RADIUS com um prefixo já em uso recusa o login, como no IPv4).
- **Compatibilidade:** o `use_ipv6` padrão segue o RouterOS (ligado); um perfil sem pool sobe o
  IPv6CP e o link-local, mas o RA não anuncia prefixo (o ⓘ explica).

## 10. IPoE: o lease DHCP como sessão de assinante (G4.3f)

Um provedor com OLT/switch que insere a opção 82 não precisa de PPPoE: o CPE pede DHCP, o BNG
autoriza (por MAC ou pela linha), entrega o endereço e trata o lease como sessão — contabilização,
limite de banda, CoA/Disconnect, "Why?" — como uma sessão PPPoE. O CoreRouter faz isso em cima
do servidor DHCPv4 em Rust puro (G4.2a/b), do serviço RADIUS (G4.3j) e do mesmo plano de dados
XDP do PPPoE (G4.3c).

### 10.1 Pesquisa

Fontes lidas em 2026-10-24/25:

- **MikroTik RouterOS v7**, `/ip dhcp-server` ([DHCP](https://help.mikrotik.com/docs/spaces/ROS/pages/24805500/DHCP))
  e [RADIUS](https://help.mikrotik.com/docs/display/ROS/RADIUS). `use-radius` = `no` | `yes`
  (autoriza e contabiliza) | `accounting`; precisa de `/radius … service=dhcp`. O Access-Request
  leva o MAC como User-Name, senha vazia (ou `radius-password`), NAS-Port-Type Ethernet,
  NAS-Port-Id = interface, Called-Station-Id = nome do servidor. Do Accept valem
  Framed-IP-Address, Framed-Pool, Session-Timeout (vira o tempo do lease),
  Mikrotik-Rate-Limit (ou Ascend-Data-Rate), Framed-Route, Class e Acct-Interim-Interval. Enquanto
  espera, o lease aparece `authorizing`. O `rate-limit` do lease cria uma *simple queue*
  dinâmica — que o tráfego em FastTrack não atravessa. A opção 82 só vai ao RADIUS com
  `support-broadband-tr101` (7.21beta). O que acontece num Reject e se há CoA/DM para leases
  DHCP não está documentado.
- **RFC 3046** (opção 82): sub-opções 1 (circuit id) e 2 (remote id); o servidor ecoa a opção
  inteira (§2.2) e **não pode esperá-la na renovação unicast** — a chave da sessão não depende de
  a opção 82 vir em todo pacote (guardamos a do lease). §2.1/§5: só o agente confiável põe a
  opção; a do cliente é descartada (o nosso `relay_info_trusted`, G4.2b).
- **RFC 4679** (atributos DSL Forum, fornecedor 3561): Agent-Circuit-Id 26/3561/1,
  Agent-Remote-Id 26/3561/2 no Access-Request e na contabilização. **RFC 4014**: sub-opção 7 (não
  usada).
- **RFC 5176** (CoA/Disconnect): atributos que identificam a sessão (§3), Error-Cause 503 "Session
  Context Not Found" (§3.5), aplicar tudo ou nada (§2.3). **RFC 2131 §4.4.5**: sem renovação até o
  fim do lease o cliente para de usar o endereço — o fim passivo da sessão. **RFC 5227**: a sonda
  ARP (remetente 0.0.0.0) é para detectar duplicidade; um "ARP ping" de keepalive é um pedido
  normal do nosso endereço.
- **BBF TR-146** (Subscriber Sessions): sessão iniciada pelo DISCOVER (R-05), viva enquanto o
  lease (R-12/R-13), identificada por circuit/remote id e MAC (R-43/R-44), com amarração IP↔MAC
  contra spoofing (R-38), CoA/DM (R-50), Start/Interim/Stop (R-51), keepalive por ARP (R-92,
  SHOULD) e reautorização opcional antes de estender o lease (R-47). **TR-101**: a opção 82 posta
  pelo nó de acesso.
- **accel-ppp `[ipoe]`** ([accel-ppp.conf(5)](https://github.com/accel-ppp/accel-ppp/blob/master/accel-pppd/accel-ppp.conf.5)):
  `start=dhcpv4|up`, `username=ifname|lua`, `password=username|csid|empty`, `max-lease-time`
  (liveness pelo lease), `idle-timeout`, `offer-delay` (freio sob carga), `soft-terminate` (derruba
  na próxima renovação), `check-mac-change`, `l4-redirect-on-reject` (portal para inadimplente) e
  `attr-dhcp-opt82-*` (opção 82 em qualquer atributo). Sem keepalive ARP.
- **Juniper Junos** ([autenticação](https://www.juniper.net/documentation/us/en/software/junos/subscriber-mgmt-sessions/topics/topic-map/dhcp-client-external-authentication.html),
  [liveness](https://www.juniper.net/documentation/us/en/software/junos/dhcp/topics/topic-map/dhcp-liveness-detection.html)):
  `username-include` monta o User-Name com MAC, circuit id, remote id, VLAN, interface; perfil
  dinâmico por assinante; `layer2-liveness-detection` por ARP/ND (30 s, depois 10 s) que apaga a
  amarração. **Cisco ISG**: sessão por DHCP ou pacote não classificado, keepalive ARP/ICMP só
  depois de ociosa. **Nokia SR OS**: uma "IPoE session" por MAC + circuit/remote id + SAP.

### 10.2 O que adotamos

- **Nomes do RouterOS** onde existem: `ip.dhcp-server … use_radius=no|yes|accounting` e o
  `rate_limit` do lease estático (`10M/50M` com bursts, a sintaxe do RouterOS). Os nossos, quando o
  RouterOS não tem: `ipoe=yes` (sessões mesmo sem RADIUS), `ipoe_username=mac|circuit-id|remote-id|circuit-remote`
  (o `username-include` do Juniper nas formas comuns) e `ipoe_unknown=accept|reject` (o que recebe
  quem não está na lista local).
- **Lista local = `/ppp secret` com `service=ipoe`**: o nome é o que `ipoe_username` monta (o MAC
  `AA:BB:CC:DD:EE:FF`, ou o circuito `olt1/1/3`), sem senha; o perfil traz pool, `address_list` e
  `rate_limit`, como no PPPoE. `service=any` **não** casa IPoE (um login PPP com cara de MAC não
  vira concessão). Primeiro a lista local, depois o RADIUS (`use_radius=yes`), como o `/ppp aaa`.
- **Autorização no DISCOVER, como o MikroTik**: o servidor DHCP (puro, `proto-dhcp`) estaciona a
  mensagem (`Effect::Authorize`) e só oferece depois do Accept. Um Reject não oferece nada, e o
  cliente fica 30 s sem ser perguntado de novo (um DISCOVER a cada 4 s não vira um Access-Request
  cada). Um REQUEST de quem não tem concessão (renovação depois de reiniciar o daemon) é
  perguntado e depois ACK ou NAK. Sem resposta em 15 s, o cliente pergunta de novo na próxima
  retransmissão. No máximo 8192 esperando (enxurrada de MACs aleatórios).
- **O que o Accept muda**: Framed-IP-Address (só esse endereço; nunca o de outro cliente),
  Framed-Pool, Session-Timeout como tempo do lease (RouterOS) e as address lists. A concessão vale
  enquanto o cliente tiver lease; o lease que acaba a leva junto.
- **Sessão = lease** (TR-146 R-13): começa no ACK, acaba no RELEASE, no fim do lease, num
  Disconnect-Request ou no `ppp.active.remove` (o lease é encerrado e a próxima renovação recebe
  NAK: o cliente recomeça autorizado de novo).

### 10.3 Melhorias propostas

Entram agora:

- **O policer do XDP no lugar da simple queue**: o mesmo balde com burst do RouterOS do PPPoE,
  por assinante, que nenhum FastTrack pula (o problema conhecido do MikroTik), com contadores por
  sessão para a contabilização e o gráfico.
- **Amarração IP↔MAC no XDP** (TR-146 R-38): o pacote do assinante com outro endereço de origem é
  descartado e contado (`spoofed`).
- **Opção 82 para o RADIUS no padrão** (RFC 4679 Agent-Circuit-Id/Agent-Remote-Id), sem esperar a
  7.21, e o User-Name à escolha (Juniper).
- **Keepalive por ARP** (TR-146 R-92, Juniper): o assinante ocioso é pingado; sem resposta, a
  sessão cai antes do fim do lease e o "Why?" diz por quê.
- **Aviso antes do erro**: `use_radius` sem `/radius service=dhcp`, `ipoe_unknown=reject` sem
  nenhum secret, `ipoe_username` por opção 82 num servidor que não acredita na opção 82 do link, e
  `rate_limit` num servidor que não é IPoE.
- **Tudo é comando e aparece junto**: as sessões IPoE ficam em PPP › Active Connections com
  `service=ipoe`, o "Why?" e o selo de identidade; `ppp.active.remove` e o MCP servem para as duas.

Viram gap depois: reautorizar antes de estender o lease (TR-146 R-47), `soft-terminate` e
`offer-delay` do accel-ppp, portal para rejeitado (`l4-redirect-on-reject`), início por pacote não
classificado (R-08), sessões IPoE IPv6 (DHCPv6/RA com a linha da RFC 6788) e FORCERENEW (RFC 6704).

### 10.4 O que ficou de fora e por quê

- **Interface por assinante** (accel `shared=0`, Juniper perfil dinâmico): o plano de dados XDP
  dispensa um netdev por sessão, como no PPPoE.
- **BFD como keepalive**: o CPE doméstico não fala BFD.
- **Clonar a sintaxe `lua` do accel-ppp**: os quatro formatos de `ipoe_username` cobrem os
  provedores que conhecemos; um formato novo é uma variante a mais.

### 9.5 O serviço `ipoe` do daemon

`apps/corerouter-daemon/src/service/ipoe.rs` (o driver) e `ipoe_bng.rs` (o núcleo, sem E/S). No
início o serviço se registra no engine como `IpoeBackend` (o servidor DHCP pergunta e avisa) e
como a metade IPoE do `ppp.active` (`Session::set_ipoe_sessions`); no RADIUS, como dono de sessões
para CoA/Disconnect.

- **Autorização**: a lista local (`/ppp secret service=ipoe`) primeiro; senão, com
  `use_radius=yes`, um Access-Request `service=dhcp` com o nome de `ipoe_username` como User-Name,
  senha vazia (RouterOS), NAS-Port-Type Ethernet (15), NAS-Port-Id = interface (ou o circuito, com
  `ppp.aaa use_circuit_id_in_nas_port_id`), Calling-Station-Id = MAC, Called-Station-Id = servidor
  e a opção 82 em ADSL-Agent-Circuit-Id/ADSL-Agent-Remote-Id (RFC 4679). A resposta volta por um
  canal: o servidor DHCP a pega na rodada seguinte. Do Accept valem Framed-IP-Address,
  Framed-Pool, Session-Timeout, Mikrotik-Rate-Limit (ou Ascend-Data-Rate/Ascend-Xmit-Rate),
  Mikrotik-Group (o perfil e a sua taxa), Mikrotik-Address-List, Acct-Interim-Interval e Class.
- **Sessão**: no ACK; renovação = prova de vida; endereço novo = a sessão velha acaba
  (`replaced`). Taxa: a do RADIUS, senão o `rate_limit` do lease estático, senão o do perfil do
  secret. Contabilização (`use_radius=yes|accounting`): Start com a Class, interims pelo serviço
  RADIUS (Acct-Interim-Interval, senão `ppp.aaa interim_update`), Stop com
  Acct-Terminate-Cause: User-Request (RELEASE), Lost-Carrier (lease vencido, keepalive),
  Admin-Reset (`ppp.active.remove`, Disconnect-Request).
- **Fim**: `ppp.active.remove` e o Disconnect-Request viram um *revoke* no servidor DHCP: o lease
  acaba, a concessão some, a renovação recebe NAK e o CPE recomeça autorizado. CoA com
  Mikrotik-Rate-Limit muda o policer na hora (tudo ou nada, RFC 5176 §2.3; taxa inválida = NAK
  407); com Framed-IP-Address, o CPE pede DHCP de novo e recebe o endereço novo.
- **XDP**: o serviço liga `Hal::ipoe_dataplane` para as interfaces dos servidores IPoE e escreve
  cada sessão (índices do topo do mapa para baixo). Sem XDP (laboratório, NIC sem suporte, o
  namespace sem root) a sessão existe sem o policer e a linha do serviço diz por quê; a ligação é
  tentada de novo a cada 30 s.
- **Keepalive** (`ip.dhcp-server … ipoe_keepalive=60s`, desligado por padrão): o assinante calado
  por esse tempo (sem bytes de subida no XDP, sem renovação, sem resposta ARP) recebe um ARP; três
  sem resposta, 10 s um do outro, e a sessão cai com `keepalive` no "Why?". Os pings saem pela
  porta do servidor DHCP (o mesmo socket das sondas de conflito).
- **Why?**: estágios `dhcp` (o DISCOVER chegou), `auth` (RADIUS perguntado) e `up`; os motivos
  `not-authorized`, `rejected`, `radius-timeout`, `released`, `lease-expired`, `keepalive`,
  `admin-reset`, `radius-disconnect`, `replaced`, cada um com a dica em português.

Números (**medido**, 2026-10-25, 32 CPUs, build debug, veth sem XDP, `tests/netns_ipoe.rs`): 10 000
assinantes autorizados pelo RADIUS de teste (um Access-Request e um Accounting-Start cada) com
endereço em 3,0 s = 3 300 sessões/s; o daemon cresce ~4,3 kB por sessão (lease, sessão, histórico).

## 11. Vários Service-Names numa porta (G4.3k)

Um servidor PPPoE por porta de acesso com uma **tabela de Service-Names**: cada linha diz o nome,
o perfil das sessões que pedem esse nome e o que um PADI recebe (`terminate`, `delay`, `drop`),
mais as linhas fixas `empty` (o nome vazio, "qualquer serviço" pela RFC 2516) e `any` (todo nome
fora da tabela). Um espaço de SESSION_ID só, o perfil escolhido no PADR.

### 11.1 Pesquisa

Fontes lidas em 2026-10-26:

- **MikroTik RouterOS v7**, [`/interface pppoe-server server`](https://help.mikrotik.com/docs/spaces/ROS/pages/2031625/PPPoE):
  um `service-name` por servidor (vazio: atende qualquer nome e o vazio; com nome: aquele e o
  vazio); para vários nomes, vários servidores na mesma interface, e o operador não controla qual
  responde ao PADI vazio. `pado-delay` por servidor. Perfil por servidor (`default-profile`).
- **Juniper Junos**, [service-name-tables](https://www.juniper.net/documentation/us/en/software/junos/subscriber-mgmt-vlan/topics/example/subscriber-management-pppoe-service-name-table.html):
  uma tabela por interface, linhas por nome mais `empty` e `any`; ação `terminate`, `delay
  <s>` ou `drop`; `empty` começa em `terminate` e `any` em `drop`; perfil dinâmico,
  routing-instance e `max-sessions` por linha; até 512 nomes no roteador.
- **accel-ppp** (`accel-ppp.conf(5)`, seção `[pppoe]`): `service-name` (lista),
  `accept-any-service`, `accept-blank-service`, `pado-delay=d[,d1:n1,…]` crescendo com a carga
  (`-1` para de responder), `padi-limit` por interface e global.
- **RFC 2516** (sem errata sobre Service-Name; a 5634, verificada, pede que o texto de um
  `*-Error` não termine em NUL):
  - §5.1: o PADI tem exatamente um Service-Name; Apêndice A: comprimento zero = "qualquer
    serviço";
  - §5.2: o PADO leva um Service-Name **idêntico** ao do PADI, e o AC que não pode servir o PADI
    "MUST NOT respond with a PADO";
  - §5.4: PADR com nome que o AC não aceita → PADS com Service-Name-Error e SESSION_ID 0;
  - §9: o AC que não quer revelar seus serviços "SHOULD never refuse a request based on the
    Service-Name TAG" (RECOMMENDED).

### 11.2 O que adotamos

- **Tabela no servidor, como o Junos** (`services` em `interface.pppoe-server.server.add/set`,
  ou linha a linha em `interface.pppoe-server.server.service.add/set/remove/list`). As linhas
  `empty` e `any` sempre existem (não se removem; mudam de ação). Um nome repetido, duas linhas
  `empty` ou `delay` sem atraso são recusados.
- **Padrões do RouterOS e da RFC §9, não do Junos**: um servidor novo atende tudo
  (`empty` e `any` em `terminate`). O `any=drop` do Junos é escolha do operador, com aviso.
- **Migração sem passo:** uma config com só `service_name` (RouterOS, antes da G4.3k) vale como a
  tabela que ele quer dizer (`PppoeServer::service_table`): vazio = tudo; `isp` = `isp` e o
  vazio em `terminate`, `any` em `drop`. A primeira mudança por comando grava a tabela e limpa o
  `service_name`. `service_name=` continua aceito (o importador do MikroTik, G4.3n).
- **AC (`proto-pppoe::server::services`)**: o nome cai em exatamente uma linha (busca por hash);
  `drop`, linha cheia (`max_sessions`) ou acima do `padi_limit` da linha = sem PADO (§5.2);
  `delay` soma o atraso da linha ao atraso por carga do servidor; o PADO ecoa o nome byte a
  byte; no PADR, `drop` → Service-Name-Error com SID 0 (§5.4) e linha cheia → AC-System-Error. Um
  CPE que volta na mesma linha toma o lugar da sessão antiga (one-session-per-host) mesmo com a
  linha cheia.
- **Perfil no PADR:** o perfil da linha toma o lugar do `default_profile` do servidor e do
  `default` de um secret que não escolheu outro; um secret com perfil próprio continua vencendo,
  e o `Mikrotik-Group` do RADIUS também.
- **Por sessão:** o nome pedido fica na sessão, aparece em `ppp.active.list` (`service_name`) e
  vai ao RADIUS como Called-Station-Id (o que o RouterOS manda).
- **Workers (G4.3g):** `max_sessions` e `padi_limit` da linha são divididos entre os workers, como
  o `padi_limit` do servidor (os MACs se espalham por igual); o limite é aproximado em ±1 por
  worker.

### 11.3 Melhorias propostas

Entram agora (aprovadas em 2026-10-26): nome por sessão no Active, `max_sessions` e `padi_limit`
por linha, atraso por carga somado ao da linha, recusa de duas linhas para o nome vazio (que
deixaria a escolha do AC ao acaso, o problema do MikroTik com dois servidores na mesma porta) e os
avisos: `empty=drop` (a maioria dos CPEs não pede nome), `any=drop` com nomes na tabela (§9) e
tabela que não atende ninguém.

### 11.4 O que ficou de fora e por quê

- **routing-instance (VRF) por linha** (Junos): o plano de dados PPPoE ainda não tem VRF por
  sessão.
- **Linha por ACI/ARI** (Junos casa também Agent-Circuit-Id/Remote-Id): pede uma tabela de linhas
  própria; o RADIUS já recebe as duas e pode escolher o perfil (`Mikrotik-Group`).

### 11.5 Desempenho (**medido**, 2026-10-26, Ryzen AI Max+ 395, release)

| Medida | Antes | Depois |
|---|---|---|
| PADI → PADO, sem nomes (`server_padi_to_pado`) | 191 ns | 196–198 ns (+1 %, no ruído) |
| PADI → PADO, 512 nomes, o último (`server_padi_to_pado_512_names`) | — | 1,04 µs com busca linear → **209 ns** com o índice por hash |
| Simulação: 20 000 assinantes, 40 nomes + vazio + 2 recusados, 5000 VLANs QinQ, 0,2 % de perda | — | 0,67 s |

O trabalho é por PADI/PADR (nunca por pacote de dados): uma busca por hash e um contador por
linha. Um `reconfigure` com a tabela mudada reconta as sessões por linha (O(sessões), uma vez
por mudança).

## 12. QinQ e VLANs no caminho lento (G4.3l)

O servidor PPPoE atende dentro de duas tags (QinQ: a S-tag da OLT, PON ou DSLAM e a C-tag da
linha, o modelo 1:1 da TR-101), sem uma interface VLAN do kernel por assinante, no XDP e no
caminho lento. A sessão é a chave (porta, S-tag, C-tag, MAC, SESSION_ID); a do XDP
(`dataplane-ebpf-common::pppoe::SessionKey`) já tinha as duas tags desde a G4.3c.

### 12.1 Pesquisa

Fontes lidas em 2026-10-26:

- **MikroTik RouterOS v7** ([PPPoE](https://help.mikrotik.com/docs/spaces/ROS/pages/2031625/PPPoE)):
  `pppoe-over-vlan-range` é uma tag 802.1Q só, e `accept-untagged` também atende sem tag. Para
  QinQ, o servidor fica numa interface VLAN (a S-tag), com a C-tag no range: uma interface do
  kernel por S-tag.
- **Juniper Junos**, `auto-configure stacked-vlan-ranges`: faixas `externa,interna` (`any,any`,
  `100-200,1-4094`), TPID da externa configurável, interfaces dinâmicas por linha; o NAS-Port-Id
  vai como `ge-1/0/0.<unit>:<s>-<c>`.
- **accel-ppp**, `vlan-mon`: cria uma interface VLAN do kernel por VLAN que aparece, inclusive
  em duas camadas para QinQ; um socket por interface.
- **BBF TR-101**: N:1 (muitas linhas numa VLAN, a linha no Agent-Circuit-Id) e 1:1 (uma VLAN por
  linha, em geral S-tag + C-tag); o nó de acesso insere Agent-Circuit-Id/Remote-Id no PADI
  (RFC 4679 §3, Vendor-Specific 3561), que vão ao RADIUS.
- **RFC 4638**: PPP-Max-Payload ecoado no PADO/PADS só se o AC aceita mais que 1492 (§4); o MRU
  passa de 1492 só com os dois lados de acordo, e nunca acima de "MTU da interface − 8" (§5.1);
  sem a tag, vale o 1492.
- **Kernel Linux** (medido em veth, 2026-10-26): o kernel tira a tag externa antes de um socket
  `AF_PACKET` ver o quadro e a guarda ao lado (`skb_vlan_untag`); a interna fica no quadro. Um
  socket preso a 0x8863 só recebe o quadro depois que a tag foi **apagada**: o quadro da VLAN
  100 chegava ao socket "sem tag" como se não tivesse tag, e o socket da VLAN 100 não recebia
  nada. Um socket `ETH_P_ALL` vê a tag (`SKF_AD_VLAN_TAG`, `SKF_AD_VLAN_TPID`) no filtro.

### 12.2 O que adotamos

- `vlan_mode=single` (padrão, o `pppoe-over-vlan-range` do RouterOS) ou `vlan_mode=stacked`
  com `outer_vlan_range` (S-tags, no máximo 512), `inner_vlan_range` (C-tags, `any` por padrão),
  `outer_tpid` (0x88a8 ou 0x8100) e `accept_untagged`. Os dois modos não se misturam num servidor.
- **Caminho lento sem interface por assinante:** um socket `ETH_P_ALL` por S-tag (ou VLAN
  simples), com um filtro BPF clássico que confere VID, TPID e o EtherType PPPoE (atrás da C-tag
  no QinQ); a tag externa volta para dentro do quadro antes do `proto-pppoe`. Isto **corrige** a
  VLAN simples sem XDP, que nunca funcionou (ver 12.1).
- **Worker por linha:** um quadro QinQ vai ao worker pelo par de tags (os outros, pelo MAC),
  então todos os CPEs de uma linha se encontram no mesmo worker.
- `max_sessions_per_vlan` (1 = TR-101 1:1): o AC não manda PADO a um segundo CPE da linha
  (RFC 2516 §5.2) e responde AC-System-Error a um PADR atrasado (§5.4); o CPE da própria linha
  que volta toma o lugar da sessão antiga. No QinQ o limite é exato; numa VLAN simples (N:1), é
  por worker.
- **RADIUS:** ADSL-Agent-Circuit-Id e ADSL-Agent-Remote-Id (RFC 4679) no Access-Request e na
  contabilização; NAS-Port-Id = o circuit id (com `use_circuit_id_in_nas_port_id`), senão
  `<porta>:<s>-<c>` numa linha QinQ (a forma do Junos) ou a porta.
- **RFC 4638:** `max_payload=1493..1500` (padrão: nenhum, 1492); recusado se a MTU da porta
  for menor que o valor + 8.
- **Active Connections:** `vlan` e `inner_vlan` por sessão (o selo `120/3044` na janela).

### 12.3 Melhorias propostas

Entram agora: o conserto da VLAN simples, o limite 1:1, os atributos TR-101 em toda requisição,
a checagem do MTU da RFC 4638 e o worker por linha.

Viram gap (G4.3la): separar as VLANs em O(1) no caminho lento, porque o custo por socket é medido
(abaixo) e a separação pede `PACKET_FANOUT` com programa ou `PACKET_AUXDATA`, que não têm
binding seguro (o `unsafe` é proibido fora do `dataplane-ebpf`).

### 12.4 Desempenho (**medido**, 2026-10-26, Ryzen AI Max+ 395, kernel 7.0, veth)

| Medida | Valor |
|---|---|
| Custo de cada socket da porta por quadro que passa (filtro que recusa) | 35–58 ns |
| Quadro enviado e recebido num veth com 0 / 1 / 64 / 512 sockets | 0,60 / 0,65 / 2,8 / 30,5 µs |
| e2e em namespace: 400 linhas QinQ abertas (debug, caminho lento) | 0,03 s |
| Simulação em memória: 20 000 assinantes em 5000 VLANs QinQ | 0,67 s |

Com o XDP (produção) os quadros de dados nunca viram skb e não passam pelos sockets: só a
descoberta e o controle pagam o custo por socket. No caminho lento, cada quadro da porta paga
N × ~45 ns. O desenho anterior pagava o mesmo para cada quadro de sessão (N sockets presos a
0x8864); agora pagam também os quadros que não são PPPoE, que numa porta de acesso são raros.

### 12.5 IPv6 encaminhado no caminho lento (parte 2)

Sem XDP, o BNG encaminha também o IPv6 dos assinantes, como já fazia com o IPv4:

- **Subida:** um pacote para fora do enlace (nem link-local, nem multicast) vale só se a fonte
  estiver no /64 ou no prefixo delegado da sessão, e chegar no MAC e nas tags da sessão: é o
  antispoofing do XDP (G4.3e). Ele entra na pilha por um socket IPv6 cru (`IPPROTO_RAW`, cabeçalho
  como veio). O link-local e o multicast continuam com o plano de controle da sessão (RS, NS,
  DHCPv6, eco ao nosso link-local).
- **Descida:** cada /64 e cada prefixo delegado ganham uma rota para o `bng0`, que some com a
  sessão. O que o kernel manda ali volta ao worker dono pelo maior prefixo
  (`pppoe_slow6::Net6Index`: uma consulta de hash por comprimento de prefixo em uso), e o worker
  encapsula na sessão, dentro das tags da linha.
- **Medido** (2026-10-26, Ryzen AI Max+ 395, release): ~16 ns por consulta com 200 000 prefixos
  (100 000 sessões, um /64 e um /56 cada). Em namespace, um assinante QinQ dual-stack pinga o IPv6
  do `wan0` pelo caminho lento, e a resposta volta dentro das duas tags.

### 12.6 Root e laboratório (parte 3)

- **`xdp-root` na VM** (`cargo xtask vm-lab run`, kernel 7.0, 2026-10-26): os 15 testes passam. O
  diferencial kernel × host do PPPoE (`pppoe_kernel_and_host_agree`) agora tem linhas QinQ com
  TPID externo 0x8100 ao lado das 802.1ad; 6000 quadros concordam.
- **BNG Blaster** (`cargo xtask bng-lab --only qinq`, etapa nova): 4000 linhas QinQ (S-tags 802.1ad
  100–103 × C-tags 1–1000, `vlan-mode 1:1`), Service-Name `internet` numa tabela com
  `any=drop`, Agent-Circuit-Id/Remote-Id do BNG Blaster, `max_sessions_per_vlan=1`.

| Plano (VM, 8 vCPUs, release, **medido** 2026-10-26) | Sessões | Taxa | Tráfego (1 pps por sessão e sentido) |
|---|---|---|---|
| XDP (`--root`) | 4000 de 4000 | 7843–7894 sessões/s | 8000 de 8000 fluxos |
| Caminho lento | 4000 de 4000 | 7794 sessões/s | 8000 de 8000 fluxos |

Em todos os casos, `ppp.active` mostra as duas tags, o Service-Name e o circuit id, e um BNG
Blaster que pede um nome descartado (`bloqueado`) não sobe nenhuma sessão.
