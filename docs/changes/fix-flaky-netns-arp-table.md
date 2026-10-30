id: fix-flaky-netns-arp-table

Testes de namespace instáveis no lote da fila: a causa comum era a tabela de vizinhos IPv4 do
kernel, que é **uma só para todos os namespaces** (`arp_tbl`, teto `gc_thresh3` = 1024 do
namespace inicial; net/core/neighbour.c `neigh_alloc`, v7.0). A tempestade de 20 000 assinantes
do `netns_nat_ipfix` mandava UDP para `192.0.2.2:9`, onde ninguém escutava; cada datagrama
voltava como ICMP port unreachable, e o roteador resolvia ARP de cada assinante em `lan0`. A
tabela chegava a 1030 entradas e ficava cheia por segundos depois do teste (**medido**:
`/proc/net/stat/arp_cache`, cada binário sozinho; nenhum outro passa de 61). Nesse tempo, todo
outro teste da máquina recebia ENOBUFS ao criar a própria entrada ARP: o ping do `netns_cgnat`
(`sendmsg: No buffer space available`), o unicast da renovação DHCP (tabelas de vizinhos vazias
nos dois lados, a próxima tentativa só em T2), o BFD e, pela mesma via, provavelmente o link de
sync do `netns_ha_pppoe` (`connect` em timeout por 15–21 s nos 14 de 14 casos do CI, **medido**
nos logs; não reproduzido localmente). O servidor agora recebe a tempestade num socket mudo:
pico de 35 entradas em vez de 1030 (**medido**).

Na mesma passada, o que cada teste supunha e a carga quebrava:

- `netns_ha_pppoe`: as esperas depois que os CPEs sobem (réplica, B ativo, CoA) atendem os
  CPEs; 30 s sem responder ao LCP echo contra o keepalive de 10 s do BNG derrubavam as sessões
  que a réplica esperava (o histórico de A mostrava `keepalive`, `uptime 14`).
- `netns_cgnat`: `lab()` espera cada veth sair da qdisc `noop` (o kernel só a troca no
  linkwatch, sob o `rtnl_lock` global: até 381 ms, **medido**; antes disso `noop_enqueue`
  descarta e conta TX dropped); as rajadas esperam até 3 s por datagrama até chegar o esperado
  e depois 300 ms de silêncio (um `recv` de 300 ms para tudo perdia a rajada); o limite de ICMP
  aceita a recarga do balde (5/s) durante os 10 envios, que sob carga passam de 200 ms.
- `netns_routes`: `route_dumps()` conta pelo processo inteiro; o teste que o confere roda
  sozinho (`RwLock`), os outros em paralelo entre si.
- `netns_bfd`: "up" e o detection time lidos na mesma linha (a sessão de 150 ms caía entre duas
  leituras); a detecção medida do fim do `ip link set down`, não do começo do comando.
- `netns_ha_bfd`: a parede (1,58 s com `active_ms` 153) contava o recolhimento do processo e o
  polling pelo canal de controle; `detected_by: bfd` já prova a detecção antes do dead interval.
  Antes de cada takeover, 1 s seguido de BFD up nos dois nós (como o `netns_bfd`): com 150 ms de
  detecção, uma pausa da máquina derruba o BFD de verdade e o par cai nos hellos.
- `netns_replug` (G1.3d): o teste espera o evento de link do `ether2` chegar ao daemon (o serviço
  mostra `link changes handled: N (last: …)` no `system.service.print`); o limite de 800 ms de
  parede não separava o evento do poll de 1 s numa máquina carregada (940–990 ms, **medido**).
  Reaplicar entre dois polls é o teste do engine (`port_absent`, relógio simulado). O log aceita
  "replugged" ou "port is back" (sob carga um poll pode cair entre o `del` e o `add`).
- `netns_dns_ddns`: espera as duas zonas autoritativas, não só a direta (a reversa dava
  NOTAUTH quando o serviço as publicava em rodadas diferentes).
- `netns_dhcp_server`, `netns_dhcp_relay`: o log do daemon vai para a pasta da execução, não
  para um nome fixo em `/tmp` compartilhado por todas.

Como reproduzir: os 62 binários netns do daemon e do hal-linux de uma vez, como o `cargo xtask
netns`, cada laço preso em 2 CPUs (`taskset -c`), 4 laços em paralelo. Falhas em 52 rodadas
(**medido** em 2026-10-30, 32 threads, build de debug):

| teste | antes | depois |
|---|---|---|
| `netns_ha_pppoe` | 0/138 aqui; 30× no CI | 0/52 |
| `netns_cgnat` | 10/32 | 0/52 |
| `netns_dhcp_server` | 9/16 | 0/52 |
| `netns_dhcp_relay` | 9/32 | 0/52 |
| `netns_notice` | 11/32 | 0/52 |
| `netns_routes` | 22/52 | 0/52 |
| `netns_bfd` | 5/32 | 0/52 |
| `netns_ha_bfd` | 7/32 | 1/52 e 1/24 (BFD caído de verdade, `dead-interval`: o daemon ficou sem CPU além do dead interval) |
| `netns_replug` | 17–33/52 | 0/24 (+1/24 corrigido: log "port is back") |
| `netns_dns_ddns` | 2/52 | 0/24 |

O `hal-linux netns` (12/18 antes) já tinha sido corrigido na `main` pelo G1.3b (#508): DAD
`tentative` na comparação de `ip addr`.

| G0.30d | `netns_nat_ipfix`: a tempestade de 20 000 blocos não cabe em 20 rodadas com pouca CPU | daemon (teste) | Com a suíte netns presa em 2 CPUs ele falha 8–11 de 16 rodadas com ou sem esta correção (A/B intercalado, **medido**): "SCTP got N of 20000"; no CI (4 vCPU) não aparece. Medir o tempo da tempestade e trocar o número fixo de rodadas por uma espera pelo progresso (registros novos), ou levar a escala para a camada lenta (`slow_`) | 2 h | aberto |
