id: audit-dhcp

Auditoria do DHCP (servidor v4/v6, relay, histórico): 19 achados verificados no código, 18
corrigidos (um em parte), dois viram gaps. Cada correção tem um teste que falhava na `main`.

Altos:

- **DHCPv6: SOLICIT de DUIDs aleatórios enchia a memória.** Cada SOLICIT num pool IA_NA /64 criava
  um registro `offered` guardado 120 s + 7 dias, sem teto (100k SOLICITs = 100k registros, **medido**).
  Agora a tabela tem teto (`MAX_BINDINGS6` = 131.072; cheia, sai primeiro o registro livre mais
  antigo, senão o cliente é recusado com `table-full`), uma oferta não aceita some quando o prazo
  acaba (nunca foi vinculada nem escrita no diário) e o `tick` acha o que vence por um índice
  ordenado, sem percorrer a tabela. Testes `a_solicit_flood_cannot_fill_memory`,
  `the_cap_evicts_free_records_first`.
- **Opção 82 do próprio cliente era acreditada.** Um cliente na rede (`giaddr` 0) com a 82 de outro
  assinante pegava a concessão fixa dele, e o histórico (Marco Civil) gravava o circuito da vítima.
  RFC 3046 §2.1/§5: o servidor ignora a 82 sem relay, a menos que `relay_info_trusted` (novo, em
  `ip.dhcp-server`: agente L2 confiável, como uma OLT); o relay descarta o pedido que já chega com
  82 (`untrusted-82`) a menos que `relay_info_trusted` (novo, em `ip.dhcp-relay`; o Cisco faz o
  mesmo por padrão). Junto: a renovação sem relay apagava a 82 guardada na concessão, e a segunda
  renovação de uma fixa por circuito levava NAK — corrigido. Testes
  `option_82_from_a_client_is_not_believed`, `renewals_keep_the_relay_agent_information`,
  `a_clients_option_82_is_not_relayed`.
- **Tempestade: escritas síncronas por concessão, sob o lock da sessão.** Uma rodada de 128
  vinculações fazia 129 appends com fsync (o histórico, um por concessão), 256 regravações do estado
  do DNS dinâmico (A e PTR, cada uma com o estado inteiro e dois syncs) e 128 cópias da config
  inteira para a checagem de lockout das address lists: 220 ms por rodada em memória, 840 ms com
  fsync no NVMe (**medido**), tudo com o `Mutex<Session>` preso. Agora o histórico é um append por
  rodada, o DNS é salvo uma vez por rodada (o serial das zonas sobe uma vez) e as entradas de lista
  da rodada passam por uma checagem de lockout só, contra a config emprestada. Teste
  `a_storm_round_writes_once_per_journal` (2 appends e 1 save por rodada; era 129 e 256).
- **O serviço DHCP matava de fome o plano de controle.** Com mensagens chegando, o laço voltava a
  pegar o lock sem pausa (o mutex não é justo): canal de controle, MCP e GUI quase não entravam.
  Agora há sempre 1 ms entre rodadas, e cada rodada para de ler depois de 20 ms
  (`ROUND_BUDGET_US`), além do limite de 256 mensagens. Testes `a_storm_round_is_bounded_in_time`,
  `the_loop_always_rests`.

Médios:

- **Depois de reiniciar, as concessões perdiam as address lists e os nomes no DNS ficavam para
  sempre.** As entradas de lista (não guardadas) voltam ao carregar o diário, e os nomes A/PTR
  guardados são reconhecidos para sair quando a concessão acaba. Teste
  `bindings_get_their_names_and_lists_back_after_a_restart`.
- **Histórico no teto (500k): O(N) por vinculação e a compactação apagava registros legais.** Agora
  é um `VecDeque` com numeração (descartar o mais antigo é O(1): 5,2 ms → microssegundos por
  vinculação, **medido**). O que sai da memória pelo teto fica só no disco: a compactação (escrita
  da memória) não roda enquanto houver registro assim dentro da retenção, e isso é avisado uma vez no
  log (`dhcp,error`). Testes `opening_at_the_cap_is_cheap` (inclui `can_compact`). O arquivo
  segmentado que limita o disco virou a gap G4.2g.
- **Custo por DISCOVER linear em fixas, concessões e pool.** Fixas indexadas por client id, MAC,
  circuit id, remote id e endereço (65.536 fixas: 1,76 ms → µs por DORA, **medido**); reuso do
  endereço livre mais antigo por um índice ordenado; pool esgotado lembrado mesmo com endereços
  pulados (quem responde a todo ARP fazia cada resposta varrer o pool); `client_mac_limit` por
  índice de MAC; "pool cheio" no log uma vez por minuto por pool (era um aviso por DISCOVER).
  Testes `many_static_leases_are_found_by_index`, `a_full_pool_is_logged_once_a_minute`.
- **DHCPv6 PD esgotado: o pool inteiro varrido a cada SOLICIT** (2^16 prefixos: 6,4 ms por mensagem,
  **medido**). O pool cheio é lembrado até um prefixo se soltar. Teste
  `a_full_pd_pool_is_remembered_until_a_prefix_frees`.
- **Client id ou opção 82 com mais de 255 bytes (RFC 3396)** passavam no servidor e eram recusados na
  volta do diário, trazendo de volta a linha anterior do endereço (outro cliente). Agora o pedido é
  recusado (RFC 2132 §9.14, RFC 3046 §2.0). Teste `oversized_client_id_or_agent_info_is_refused`.
- **Cliente não-Ethernet sem client id levava NAK em laço** (e todos dividiam a mesma chave). A
  concessão guarda `htype` + `chaddr` (campo `hw` no diário, opcional). Teste
  `non_ethernet_clients_are_bound`.

Baixos:

- Diário com falha: o ACK continua saindo (escolha documentada: disponibilidade primeiro, o erro
  fica na linha do serviço), mas a compactação que falha só é tentada de novo depois de 60 s (era a
  cada rodada, serializando a tabela inteira). Teste `a_failing_disk_is_not_rewritten_every_round`.
- CSV do histórico: célula que começa com `= + - @ tab CR` sai como texto (`'`), OWASP. Teste
  `csv_cells_are_never_formulas`.
- `parse_time` com ano, hora ou fuso absurdos dava overflow (panic em debug); `covers` também.
  Teste `hostile_times_do_not_overflow`.
- DHCPv6: Information-request sem Client Identifier agora tem resposta (RFC 9915 §18.3.6); DUID
  vazio (ou de 1 byte) é recusado (§11.1). Teste `information_request_without_client_id_and_empty_duids`.
- A resposta ARP do próprio cliente ao endereço oferecido a ele não é conflito (RFC 5227). Teste
  `the_clients_own_arp_answer_is_not_a_conflict`.
- Relay: resposta que não vem de um dos `dhcp_server` dele é descartada (`not-from-server`). Teste
  `the_relay_only_takes_replies_from_its_servers`.
- RELEASE/DECLINE no enlace do servidor só valem vindos do MAC Ethernet e da porta do próprio
  cliente. Teste `spoofed_release_is_dropped`.
- Opção 52 (overload, RFC 2132 §9.3) agora é lida (`file` e `sname`). Teste
  `option_overload_is_honoured`. A segunda metade do achado (resposta acima da opção 57 mesmo sem as
  opções não forçadas) ficou como está: descartar a resposta transformaria uma opção forçada grande
  demais numa queda do DHCP, e os clientes reais aceitam 1500.
- Diário maior que o limite de leitura (512 MB) agora é lido pelo fim (as linhas mais novas; "a
  última vence"), e os replays de concessões v4/v6 e do histórico guardam as últimas linhas, não as
  primeiras. Testes `an_oversized_journal_keeps_its_newest_lines`, `replay_keeps_the_newest_lines`.

Verificado e certo: o que o revisor listou em "Checked, looks fine" confere. Limite de taxa por
cliente no DHCPv6 já é parte da G4.2f (não virou gap nova).

Como testar: `cargo test -p corerouter-proto-dhcp`, `cargo test -p corerouter-engine --test
dhcp_storm`; benchmarks `cargo bench -p corerouter-proto-dhcp --bench server_attack` e `cargo bench
-p corerouter-engine --bench dhcp_round` (rodada de tempestade com histórico, zona DNS e address
list; `fsync` grava arquivos de verdade).

| G4.2g | DHCP: histórico de concessões além do teto da memória | proto-dhcp, engine | Diário do histórico em segmentos (um arquivo por mês), apagados inteiros quando passam da retenção; a memória guarda a janela recente e a consulta lê os segmentos antigos sob demanda; o disco fica limitado pela retenção mesmo sob inundação de vinculações (hoje a compactação é suspensa enquanto houver registro fora da memória dentro da retenção) | 6 h | aberto |
| G4.2h | DHCP fora do lock da sessão | engine, daemon | Ler, decodificar e escolher o endereço sem o `Mutex<Session>` (só o efeito — diário, DNS, listas — sob o lock); latência p99 do canal de controle abaixo de 50 ms durante uma tempestade de DISCOVERs de MACs aleatórios, medida num teste com duas threads | 8 h | aberto |

## perf

**Medido** (AMD Ryzen AI MAX+ 395, 32 CPUs, build release, 2026-10-22; criterion, `antes` = código
da `origin/main` 19b550e com os mesmos benchmarks, `depois` = este PR):

| Benchmark | Antes | Depois | Mudança |
|---|---|---|---|
| `engine_dhcp_round/mem` (1 rodada: 128 vinculações + 128 ofertas, histórico, zona DNS + reversa, address list; 2.560 concessões antes) | 220,7 ms | 14,1 ms | −93,6 % |
| `engine_dhcp_round/fsync` (idem, arquivos sincronizados no NVMe; 640 concessões antes) | 844 ms | 8,1 ms | −99,0 % |
| escritas por rodada de tempestade (appends / saves de estado) | 129 / 256 | 2 / 1 | |
| `dhcp_attack/exhausted_pool_random_mac/16k` (1.000 DISCOVERs, pool cheio de ofertas) | 18,4 ms | 1,95 ms | −89 % |
| `dhcp_attack/statics_dora/0` (200 DORAs) | 0,90 ms | 1,02 ms | +29 % (índices novos da tabela) |
| `dhcp_attack/statics_dora/10000` | 37,9 ms | 1,30 ms | −96,6 % |
| `dhcp_attack/statics_dora/65536` | 351 ms | 3,05 ms | −99,2 % |
| `dhcp_attack/arp_spoof_probe_replies/4096` (200 DISCOVERs, cada sonda respondida 3×) | 0,93 ms | 0,51 ms | −45 % |
| `dhcp_attack/history_open_at_cap/500k` (100 vinculações com o histórico no teto, inclui soltar a cópia) | 520 ms | 14,1 ms | −97,3 % |
| `dhcp6_attack/solicit_flood_ia_na/100k` (tempo; a memória agora tem teto de 131.072 registros e as ofertas somem após 120 s) | 122 ms | 150 ms | +19 % |
| `dhcp6_attack/solicit_pd_exhausted/65536` (100 SOLICITs, pool PD cheio) | 639 ms | 0,052 ms | −99,99 % |

O lock da sessão fica com o DHCP no máximo ~20 ms de leitura por rodada (`ROUND_BUDGET_US`) e é
solto por ≥ 1 ms entre rodadas; numa rodada de tempestade o tempo total sob o lock caiu de 220–844 ms
para 8–14 ms (linhas acima).
