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
