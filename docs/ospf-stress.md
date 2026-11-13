# OSPF sob carga (G3.4m)

Laboratório de carga e estabilidade do OSPF do CoreRouter: o `ospfd` e o `zebra` do FRR 10.7.1
da imagem, comandados pelo `corerouter-daemon`, sob LSDB grande, churn de LSAs, muitos vizinhos,
muitas interfaces e operação com carga. O roteiro é `scripts/ospf-stress-lab.sh`; aqui estão os
números (**medidos**), os limites achados e os defeitos, com as correções.

## Como rodar

```sh
# no host: copia a raiz da imagem para a VM do laboratório e roda a bateria lá (root só na VM)
scripts/ospf-stress-lab.sh --host /srv/build/os-out/<id>/build/images
# só alguns testes ou outros degraus; --daemon build usa o daemon desta worktree (o FRR segue o da imagem)
scripts/ospf-stress-lab.sh --host <images> --tests lsdb,ops --steps 10000,100000 --daemon build
# fase C: o roteador é outra máquina, ligada por cabo à placa <if> da VM
cargo xtask vm-lab run -- scripts/ospf-stress-lab.sh --dut remote --iface <if> \
  --target <endereço do roteador> --mgmt <cidr do lado da VM> [--dut-iface ether1] [--user admin]
# o mesmo modo remoto contra um segundo namespace (o teste do modo remoto)
cargo xtask vm-lab run -- scripts/ospf-stress-lab.sh --selftest-remote --tests lsdb,ops,latency
```

Saída: `/srv/lab/ospf-stress/<data>/results.md` na VM (uma tabela por teste) e os CSV das
amostras. `--hold N` deixa tudo no ar N s no fim (ou no ponto de uma falha de vizinhos), para
olhar com `vtysh --vty_socket /tmp/crospfstress/dut/run/frr`; `PERF=1 PERF_PROC=ospfd` grava o
perfil do processo na remoção das interfaces.

### Montagem

- **Roteador sob teste (`--dut local`):** a raiz da imagem (squashfs + overlay) em chroot, no
  namespace `crdut`, com o que o init da imagem faria: `/var/run` → `/run`, os daemons do FRR
  com os argumentos do `plan.rs` e o mesmo limite de arquivos abertos (`DUT_NOFILE`, 16 384), e o
  `corerouter-daemon --backend linux --frr /var/run/frr --manage 'ether*'`. Comandos pelo
  `corerouter-cli` desta worktree (token local); o estado do FRR pelo `vtysh` da VM no socket do
  chroot (a imagem não tem `vtysh`).
- **Gerador:** BNG Blaster 1.0.1 no namespace `crgen` (instância OSPF `gen`, 10.0.0.11), com a
  LSDB que o `lspgen` gera atrás dele (roteadores e prefixos externos em `100.64.0.0/10`),
  carregada de uma vez com `ospf-load-mrt`. O churn é um segundo nó do `lspgen` reinjetado por
  `-S` (o socket de controle) com a métrica trocada a cada passo.
- **Modo remoto:** o gerador sai por uma placa da VM (o cabo até o notebook); os comandos vão por
  `corerouter-cli --connect tls://`; RSS e CPU por `system.resource.process.print`; LSAs e rotas
  pelos comandos do CoreRouter (sem `vtysh`). O roteador remoto não é reiniciado pelo roteiro:
  os passos de reinício do FRR e do daemon ficam de fora.

## Resultados

**Medido** em 2026-11-12 na VM do laboratório (8 vCPUs EPYC-Genoa `host-model`, 15,6 GiB, kernel
7.0 do Ubuntu; o roteador em chroot da imagem `d2a454d2` com o FRR 10.7.1 dela; o daemon desta
branch, `--daemon build`, release). O host tinha outras sessões rodando: os tempos servem para
comparar, não como número de produção. Rodadas: `/srv/build/G3.4m/run2*.log`.

### 1. Tamanho da LSDB

LSDB carregada de uma vez no gerador (`ospf-load-mrt`, um vizinho, hello 1 s / dead 4 s);
`nodes` = LSAs/20 (até 2 000 roteadores), o resto AS-external. Rotas: o FIB do `zebra` (o que o
kernel confirmou). Picos: VmHWM de cada processo no degrau; RAM: a usada na VM inteira (com o
BNG Blaster, que guarda a mesma LSDB).

| LSAs | LSDB completa (s) | 1ª rota (s) | todas (s) | rotas | instalação (rotas/s) | SPF (execuções / última ms) | `ospfd` RSS (MiB) | `zebra` | daemon | `ospfd` CPU méd/máx (%) | `zebra` CPU | daemon CPU | RAM da VM (MiB) | rotas saem (s) | passa? |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 000 | 0,0 | 1,9 | 2,9 | 1 101 | 1 163 | 4 / 0 | 12 | 17 | 66 | 0/1 | 0/0 | 1/3 | 877 | 6,2 | sim |
| 10 000 | 0,0 | 1,8 | 2,9 | 11 001 | 9 822 | 5 / 3 | 26 | 23 | 69 | 0/1 | 2/13 | 1/2 | 903 | 6,1 | sim |
| 50 000 | 0,3 | 1,8 | 3,4 | 54 003 | 34 006 | 5 / 21 | 88 | 47 | 73 | 2/8 | 11/37 | 0/1 | 1 025 | 6,2 | sim |
| 100 000 | 0,2 | 1,8 | 4,2 | 104 003 | 44 407 | 5 / 16 | 163 | 74 | 75 | 3/16 | 21/126 | 1/2 | 1 204 | 6,2 | sim |
| 200 000 | 6,1 | 1,8 | 6,4 | 204 003 | 44 865 | 5 / 16 | 308 | 128 | 77 | 6/27 | 33/137 | 1/2 | 1 491 | 6,3 | sim |

- **Limite:** nenhum até 200 000 LSAs. Memória por item: ~1,5 KiB por LSA no `ospfd` e ~0,6 KiB
  por rota no `zebra`; o daemon fica em 66–77 MiB (lê a LSDB só sob demanda). Projeção para o
  notebook de 8 GiB (**estimado**, linear): ~2,1 KiB por LSA com rota, ~2,5 milhões de LSAs antes
  de faltar memória para o resto do sistema, longe de uma rede real.
- **Instalação:** ~45 000 rotas/s no kernel (o `zebra` em um núcleo, 137 % de pico com o
  dataplane em outra thread); o SPF de 200 000 LSAs leva 16 ms (os prefixos externos não entram no
  SPF, só na tabela de rotas).
- **Retirada:** as rotas saem em ~6 s quando o gerador cai (5 s são o `teardown-time` do BNG
  Blaster); as LSAs ficam na LSDB até o purge chegar (60 s de `maxage-delay` do FRR depois) ou,
  sem purge, até o MaxAge (1 h, RFC 2328 §14). O BNG Blaster não termina o purge de 200 000 LSAs
  em 300 s: elas ficam, sem rota, até envelhecer — por isso cada teste recria a instância.

### 2. Churn

Base de 10 000 LSAs; um nó extra do `lspgen` reinjetado a cada passo (~3,1 s: o `lspgen` espera
antes de fechar o socket), com a métrica trocada (100 ↔ 200). *external*: as LSAs AS-external do
nó; *router*: os links das router-LSAs (SPF completo a cada passo). Atraso medido a cada 5º passo,
sem outro passo até ser visto.

| tipo | LSAs/s | passos | `ospfd` CPU méd/máx (%) | `zebra` | daemon | SPF | atraso LSDB p50/máx (ms) | `zebra` | CoreRouter | sondas > 20 s | passa? |
|---|---|---|---|---|---|---|---|---|---|---|---|
| external | 1,0 | 10 | 1/15 | 0/0 | 1/7 | 8 → 10 | 3 040/3 041 | 3 051/3 051 | 3 058/12 610 | 0 | sim |
| external | 85,5 | 11 | 1/13 | 0/1 | 2/7 | 11 → 12 | 3 042/3 047 | 3 053/3 059 | 3 059/10 996 | 0 | sim |
| external (120 s) | 6,7 | 25 | 1/13 | 0/0 | 1/7 | 11 → 14 | 3 044/3 054 | 3 054/3 064 | 10 531/11 366 | 2 | **não** |
| external (120 s) | 64,8 | 25 | 1/24 | 0/1 | 2/12 | 16 → 18 | 3 077/5 089 | 3 096/3 096 | 10 719/11 196 | 2 | **não** |
| router | 1,3 | 39 | 0/3 | 0/1 | 2/5 | 19 → 44 | – | – | – | – | sim |
| router | 10,4 | 39 | 0/3 | 0/1 | 1/4 | 47 → 88 | – | – | – | – | sim |
| router | 101,1 | 39 | 0/3 | 0/1 | 1/2 | 91 → 171 | – | – | – | – | sim |

- O roteador acompanha: a LSA chega à LSDB quando o `lspgen` termina de entregá-la (os ~3 s são
  do gerador) e o `zebra` instala ~10 ms depois; até ~100 LSAs/s o `ospfd` fica abaixo de 25 % de
  um núcleo e o daemon abaixo de 12 %.
- **O CoreRouter atrasa:** `routing.ospf.route.list` mostra o custo novo com p50 de 3,1 s numa
  rodada curta e de **10,5 s** nas de 120 s, e em 2 de 5 sondas passou de 20 s. A LSDB e as rotas
  são lidas sob demanda e guardadas por `FRESH_SECS` = 10 s (`crates/engine/src/ospf_state.rs`,
  G3.4n) + o tick de 2 s do laço do FRR; acima de 20 s a leitura atrasa além desse desenho. Para a
  G3.4n (anotado sem editar, como pedido): sob churn, a lista de rotas do CoreRouter fica até
  dezenas de segundos atrás do `ospfd`.
- As router-LSAs do `lspgen` (OSPFv2, sem SR) só têm links ponto a ponto sem número: não há
  prefixo para seguir; o tipo *router* mede o SPF (até 80 execuções em 120 s) e a CPU.

### 3. Muitos vizinhos

VLANs 802.1Q no `ether1` (uma adjacência por VLAN, gen instâncias 2..n+1), hello 1 s / dead 4 s,
base de 10 000 LSAs inundada a todos; 10 min de estabilidade.

| vizinhos | commit das VLANs (s) | todos Full (s) | mín. Full em 600 s | amostras abaixo | `ospfd` RSS (MiB) | `ospfd` CPU méd/máx (%) | `zebra` | daemon | remoção (s) | passa? |
|---|---|---|---|---|---|---|---|---|---|---|
| 50 | 0,1 | 6,1 | 51 | 0 | 280 | 0/48 | 0/14 | 1/5 | 0,8 | sim |
| 100 | 0,2 | 7,8 | 101 | 0 | 418 | 0/59 | 0/14 | 1/6 | 1,5 | sim |
| 250 | 0,5 | 7,8 | 251 | 0 | 652 | 2/98 | 0/11 | 2/52 | 3,5 | sim |
| 250, base de ~65 000 LSAs | – | nunca (10 min) | – | – | > 2 200 | 100 | – | – | – | **não** |

- **Limite:** com 250 vizinhos e ~65 000 LSAs (uma rodada em que a LSDB anterior não tinha saído),
  hello 1 s / dead 4 s, todas as adjacências ficaram presas em Exchange e reiniciavam a cada poucos
  segundos (lista de resumo de ~9 400 LSAs por vizinho): o `ospfd`, de uma thread, não termina a
  troca de LSDB com todos dentro do dead interval e os Hello se perdem atrás dela (é o caso da
  RFC 4222). Com 100 vizinhos e a mesma LSDB grande, o `ospfd` chegou a 2,2 GiB (~22 MiB por
  vizinho, as listas de retransmissão e de resumo).
- Antes da correção 1 (abaixo), só 20 vizinhos formavam adjacência, sempre: a 21ª VLAN ficava em
  Init.

### 3b. Muitas interfaces OSPF (G3.4p)

VLANs ponto a ponto, hello 10 s, sem vizinho: o custo do `ospfd` por interface e o do daemon que
lê `show ip ospf interface json` a cada 2 s.

| interfaces | commit (s) | no `ospfd` | sem o grupo OSPF | arquivos do `ospfd` | `show ip ospf interface json` p50/máx (ms) | tamanho (KiB) | `routing.ospf.interface.list` p50/máx (ms) | daemon CPU parado méd/máx (%) | `ospfd` CPU | remoção (s) |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 000 | 2,1 | 1 001 | 0 | 1 015 | 22/35 | 922 | 16/34 | 2/6 | 0/2 | 15,0 |
| 4 000 | 34,3 | 4 001 | 0 | 4 015 | 108/136 | 3 697 | 51/57 | 10/18 | 4/14 | 101,3 |

- A leitura das interfaces a cada 2 s custa ao `ospfd` ~55–110 ms por vez com 4 000 interfaces
  (3,7 MiB de JSON) e ao daemon 7–10 % de um núcleo parado: dado para a G3.4p.
- Onde vai a CPU no commit e na remoção (s de CPU por processo, 4 000 interfaces): commit — daemon
  4,9, `ospfd` 28,2, `zebra` 9,6; remoção — daemon 12,1 (era 43,3 antes da correção 3), `ospfd`
  28,6, `zebra` 18,1.

### 4. Operação com carga

LSDB de 10 000 LSAs e 11 001 rotas carregada (rodada 26).

| operação | comando (ms) | de volta ao normal (s) | mín. LSAs / rotas durante | nada perdido | passa? |
|---|---|---|---|---|---|
| commit (custo do template 10 → 20) | 20 | 0,0 | 10 002 / 11 001 | sim | sim |
| Safe Mode, cancelado (template desligado: a adjacência e as rotas saem) | 35 | 11,1 | 9 501 / 0 | sim | sim |
| Safe Mode, conexão perdida (o mesmo, e o cliente morto) | – | 12,0 | 9 501 / 0 | sim | sim |
| FRR morto (SIGKILL) e iniciado de novo (o daemon reinstala a config) | – | 14,0 | 0 / 0 | sim | sim |
| daemon reiniciado (responde em 0,5 s) | – | 0,5 | 10 002 / 11 001 | sim | sim |

- O Safe Mode desfaz pelo fim da conexão (`hang_up` do canal de controle) em 12 s até tudo voltar;
  a configuração fica igual à de antes (conferida pelos templates).
- Reiniciar o daemon não mexe no encaminhamento: as rotas no kernel nunca caíram.
- Os 11–14 s de volta são o OSPF (adjacência, troca da LSDB de 10 000 LSAs, SPF e instalação).

### 5. Latência dos comandos com carga

Rodada 26 (10 000 LSAs; 10 chamadas cada). CLI: um processo e uma conexão por chamada; MCP: uma
conexão quente. `lsa.list` e `route.list` respondem `pending` na primeira chamada (leitura sob
demanda da G3.4n); a coluna "1ª completa" (o tempo até a resposta com as linhas) entra na
repetição com 200 000.

| comando | resposta (bytes) | CLI p50/p99 (ms) | MCP p50/p99 (ms) |
|---|---|---|---|
| `routing.ospf.neighbor.list` | 383 | 3/4 | 3/6 |
| `routing.ospf.interface.list` | 490 | 4/4 | 2/3 |
| `routing.ospf.instance.list` | 498 | 4/7 | 2/3 |
| `ip.route.list` | 803 | 4/10 | 3/3 |
| `ip.route.page` | 1 181 | 4/8 | 2/3 |
| `system.resource.print` | 2 439 | 4/4 | 2/3 |
| `inspect` | 674 | 4/5 | 2/3 |

### 6. Convergência com tráfego (local)

BNG Blaster manda 10 000 pps de `gen1` através do roteador até `gen2`, atrás de R4; o roteador
chega a R4 por R2 (10 + 10) ou R3 (20 + 10), FRR da VM nos três. O enlace roteador–R2 é cortado
em silêncio (netem 100 % e descarte na entrada, sem queda de portadora); perda = pacotes que
faltaram / pps. Três cortes por modo.

| proteção | detecção | perda por corte (ms) | mediana (ms) | reserva no `zebra` | passa? |
|---|---|---|---|---|---|
| nenhuma | dead interval 4 s | 3 707 · 3 744 · 3 778 | 3 744 | – | sim |
| BFD | 3 × 10 ms (perfil `crfast` no template) | 35 · 32 · 25 | 32 | – | sim |
| BFD + TI-LFA | 3 × 10 ms, SR e `ti_lfa: link` | 29 · 35 · 26 | 29 | sim | sim |

- O TI-LFA põe o caminho de reserva no `zebra`, mas a perda quase não cai: no Linux a troca
  espera o `ospfd` (aviso do BFD, SPF, instalação), como a G3.4k já mediu; o ganho real é a G3.4k
  (reserva pré-programado no plano de dados).

## Defeitos achados e corrigidos

### 1. O `ospfd` não entrava no grupo OSPF a partir da 21ª interface (kernel, padrão do Linux)

- **Sintoma:** com mais de 20 interfaces OSPF ativas, as excedentes não formam adjacência
  (o vizinho fica em Init: ele recebe o nosso Hello, nós não recebemos o dele). Medido: 30
  interfaces → 11 sem o grupo; 20 de 21 vizinhos Full em 10 min, sempre o último.
- **Causa** (lida no fonte do kernel 6.18.59 da imagem e no FRR): o `ospfd` assina AllSPFRouters
  (e AllDRouters como DR/BDR) em cada interface por **um** socket; o kernel recusa com ENOBUFS
  passado `net.ipv4.igmp_max_memberships` (20 por padrão, `net/ipv4/af_inet.c:1808`;
  `net/ipv4/igmp.c:2365`) e cobra 48 B de `net.core.optmem_max` por grupo (128 KiB:
  ~2 700 grupos; `sock_kmalloc`, `net/core/sock.c:2852`). O `ospfd` loga
  `can't setsockopt IP_ADD_MEMBERSHIP … No buffer space available` uma vez e só tenta de novo
  numa mudança de estado da interface (`ospf_if_set_multicast`, `ospfd/ospf_interface.c:802`).
  O FRR pede `igmp_max_memberships=1000` na própria documentação; a imagem não ajustava.
- **Correção:** os dois entram no catálogo de Tuning e nos padrões do roteador como piso
  (`corerouter_model::tuning::DEFAULTS` e `AT_LEAST`): 16 384 grupos e 1 MiB, aplicados pelo
  `hal-linux` a cada apply antes de tudo; um valor maior no kernel fica, o do operador vence.
  Teste: `keeps_the_multicast_floors` (hal-linux). Depois: 50 vizinhos Full em 6,2 s e estáveis;
  4 000 interfaces com o grupo, nenhuma sem.

### 2. O `ospfd` ficava sem arquivos abertos com ~1 000 interfaces (init da imagem)

- **Sintoma:** com 4 000 interfaces, o `ospfd` logou `can't accept vty socket : Too many open
  files` em laço: **10 GB de log em minutos**, disco da VM cheio. Nenhum `vtysh` (nem o
  daemon) conseguia falar com ele.
- **Causa:** o `ospfd` 10.7.1 abre um socket de escrita por interface OSPF
  (`ospf_ifp_sock_init`, `ospfd/ospf_network.c:259`) e o laço de eventos do FRR usa o
  `RLIMIT_NOFILE` do processo (`lib/event.c:766`). O init da imagem iniciava o FRR com o padrão
  do kernel para o PID 1 (1 024): com 1 100 interfaces o `ospfd` já estava em 1 023 arquivos.
- **Correção:** o init sobe `RLIMIT_NOFILE` para 16 384 (nunca abaixa) antes de iniciar o FRR e
  o daemon, que herdam (`plan::NOFILE`, `plan::nofile_limits`, teste
  `open_files_are_raised_never_lowered`). Depois: 4 000 interfaces, 4 015 arquivos abertos no
  `ospfd`, `vtysh` e daemon normais.
- **No FRR:** o laço em si é defeito do FRR (`vtysh_accept`, `lib/vty.c:2081`: rearma a escuta
  antes do `accept` e, em EMFILE, a conexão fica na fila e o evento volta na hora). Relato para o
  projeto de origem em `docs/frr-upstream/lib-vty-accept-emfile-loop.md` (o envio é do usuário).
  O roteiro do laboratório corta um log do roteador acima de 256 MiB e diz que cortou.

### 3. Remover milhares de interfaces num lote custava O(n²) no daemon (hal-linux)

- **Sintoma:** remover 4 000 VLANs num lote atômico levava 116 s, 43 s de CPU no daemon
  (1 000: 2,0 s; 2 000: 7,5 s; 4 000: 43,3 s).
- **Causa** (perfil do daemon com `perf` na remoção): 69 % do tempo num dump completo dos links
  do kernel (`link_dump::dump`, `RTM_GETLINK` com as estatísticas IPv6 de cada link), feito por
  **cada passo**: `interface.remove` e outros 29 comandos perguntam ao `hal-linux` quais links não
  são do CoreRouter (`Hal::unmanaged`), e cada pergunta lia todos os links. O lote em si, no
  laboratório virtual, leva 0,11 s para 4 000.
- **Correção:** o `hal-linux` guarda a resposta até o próximo apply ou por 1 s
  (`UNMANAGED_TTL`); a checagem do comando é uma recusa antecipada, o apply reclassifica tudo e
  nunca toca link alheio. Teste em namespace: `unmanaged_reads_the_links_once_per_batch`
  (1 000 perguntas, um dump). Depois: CPU do daemon na remoção de 4 000: **43,3 s → 8,0 s**;
  2 000: 7,5 s → 1,8 s; 1 000: 2,0 s → 0,8 s (**medido**).

### 4. O OSPF rodava em todos os endereços da interface (render do `proto-ospf`)

- **Sintoma** (modo remoto, onde o `ether1` do roteador tem o endereço de gerência e o do enlace
  OSPF): a adjacência com o gerador caía a cada ~1 s (`Full -> ExStart (SeqNumberMismatch)` no
  log do `ospfd`), as rotas da LSDB não se instalavam (2 rotas com 10 000 LSAs) e 30 vizinhos
  tinham quedas em 2 minutos.
- **Causa:** um template casado por rede (`networks 10.0.1.0/30`) virava `ip ospf area 0.0.0.0`
  na interface, e o `ospfd` liga o OSPF em **todos** os endereços dela: o 10.99.0.1/24 de gerência
  também virou interface OSPF ponto a ponto no mesmo enlace (`show ip ospf interface`: duas), com
  dois Hellos de origens diferentes para o mesmo vizinho, e a sub-rede de gerência anunciada sem
  ninguém pedir. O RouterOS v7 casa `networks` por endereço.
- **Correção:** quando o template casou por rede e a interface tem endereços IPv4 fora das redes
  dele, o render usa a forma por endereço do FRR, `ip ospf area <área> <endereço>`, só para os de
  dentro (`bind::Binding::addresses`); nos outros casos (a maioria) o texto não muda, nada é
  reaplicado na atualização. Testes: `a_network_match_takes_only_the_addresses_inside` e
  `a_second_address_outside_the_networks_stays_out`; no laboratório, a operação "segundo endereço
  na porta" (tabela 4) e o modo remoto.

## Achados sem correção neste PR

- **`ip.route.list` não mostra rotas do OSPF** (só conectadas, estáticas, DHCP e RA): virou a
  G3.4o (registrada pela G3.4n).
- **`ospfd` com milhares de interfaces numa área (FRR):** commit de 4 000 interfaces em 15–34 s,
  remoção em ~90–100 s; o `ospfd` cresce quase ao quadrado (CPU no commit: 0,7 s → 3,2 s → 11,8 s
  para 1 000, 2 000 e 4 000). Perfil: `route_top`/`route_next` (8 %), `ospf_if_lookup_by_lsa_pos`
  (busca linear nas interfaces da área, `ospfd/ospf_interface.c:426`, chamada por link da
  router-LSA no SPF e na instalação de rotas: `ospf_spf.c:832`, `ospf_route.c:691` e `:876`),
  `ospf_router_lsa_body_set` e o `libyang` do northbound. Gap G3.4q.
- **Para a G3.4n (os leitores e o laço do FRR, anotados sem editar):**
  - sob churn, `routing.ospf.route.list` fica de ~10 s a mais de 20 s atrás do `ospfd` (cache
    `FRESH_SECS` = 10 s em `crates/engine/src/ospf_state.rs` + o tick de 2 s; tabela 2);
  - com 204 003 rotas no `ospfd`, a lista mostra `total` 200 000: o leitor guarda no máximo
    `MAX_ROUTES` = 200 000 (`crates/hal-frr/src/ospf.rs`) e a resposta não diz que cortou;
  - a primeira resposta completa de `lsa.list` com 200 000 LSAs levou 16,1 s numa rodada e ~6 s
    em outra (leitura sob demanda); numa rodada a lista de rotas respondeu `total 1` uma vez (não
    se repetiu);
  - com 200 000 LSAs, até os comandos pequenos (`neighbor.list`, 384 bytes) passam de 3 ms para
    12–17 ms de p50 (tabela 5).
- **Commit com a LSDB grande:** com 200 000 LSAs o comando de commit levou de 88 ms a 1,2 s; o
  perfil do daemon no commit mostra só threads paradas: a espera é o `ospfd`, de uma thread,
  ocupado com o SPF e as 200 000 rotas externas antes de responder ao vty.
- **Sem proteção de LSDB:** o `ospfd` aceita qualquer número de LSAs (nenhum `max-lsa`); uma
  redistribuição errada num vizinho leva o roteador à falta de memória. Cisco (`max-lsa`) e Junos
  (`database-protection`) protegem. Gap G3.4r.

## Fase C: o que rodar no notebook

O notebook (i5-12450H, 8 GiB) roda a imagem `dev.628`, **anterior às três correções**: com ela,
mais de 20 interfaces OSPF ficam sem adjacência e ~1 000 esgotam os arquivos do `ospfd`. Antes da
fase C, instale uma imagem com este PR (ou, só para o teste de vizinhos, `system.tuning.set`
não serve: a imagem antiga não tem os dois parâmetros no catálogo; o roteiro avisa no cabeçalho).

1. Mover o cabo para a VM (macvtap do `eno1`, sessão principal) e dar ao notebook um endereço de
   gerência no `ether1` (ex. `10.99.0.1/24`).
2. Bateria, do jeito que o operador usa (TLS, `admin`):

   ```sh
   cargo xtask vm-lab run -- env COREROUTER_PASSWORD=<senha> scripts/ospf-stress-lab.sh \
     --dut remote --iface <placa do cabo na VM> --target 10.99.0.1 --mgmt 10.99.0.2/24 \
     --tests lsdb,churn,neighbors,interfaces,ops,latency
   ```

   Os degraus padrão vão a 200 000 LSAs (~1,5 GiB no roteador, **estimado** pela tabela 1); o
   notebook tem folga. Vizinhos: 50/100/250 com 1/4 e, à parte, `NEIGH_HELLO=10 NEIGH_DEAD=40`.
3. No remoto, CPU e RSS vêm de `system.resource.process.print`; SPF e camada `zebra` ficam de fora
   (sem `vtysh`); os reinícios do FRR e do daemon pedem o console do notebook (anotar à mão:
   `kill -9` do `ospfd` e do daemon, e o tempo até `routing.ospf.neighbor.list` voltar a Full).
4. Convergência (item 6) no notebook pede R2/R3/R4 atrás dele; o laboratório local já mediu
   (tabela 6). Com dois cabos, dá para repetir com o BNG Blaster como R2/R3.
5. Comparar com as tabelas acima: o que muda é CPU de verdade (sem virtio, sem as outras sessões).

## Desempenho e paralelismo

- **Onde está o trabalho por item:** por LSA, no `ospfd` (instalação e SPF; ~1,5 KiB de RSS por
  LSA) e no `zebra`/kernel por rota (~0,6 KiB por rota no `zebra`); o daemon não cresce com a LSDB
  (RSS de 62–63 MiB de 1 000 a 200 000 LSAs: lê a LSDB só sob demanda). Por interface: o
  `ospfd` (busca linear por interface, acima), o `zebra` e, antes da correção 3, o daemon
  (um dump de todos os links por passo do lote: O(n²), corrigido).
- **Threads:** o `ospfd` e o `zebra` são de uma thread para o SPF e a instalação (o `zebra`
  tem o dataplane numa thread à parte); o gargalo medido é a CPU de um núcleo do `ospfd` no commit
  de milhares de interfaces e de um núcleo do `zebra` instalando ~42 000 rotas/s. Dividir não é
  nosso: o FRR roda um `ospfd` por instância. Do nosso lado, a leitura de estado já roda fora do
  lock (G3.4n) e a aplicação no kernel é em lote; a correção 3 tirou o O(n²), e o que sobra
  (8 s de CPU para 4 000 remoções) é a aplicação no kernel, uma vez por commit.

## Pesquisa

- **MikroTik RouterOS v7** ([OSPF](https://help.mikrotik.com/docs/spaces/ROS/pages/9863229/OSPF)):
  não expõe temporizadores de SPF nem limite de LSAs; lembra que o OSPF gasta CPU e memória com o
  SPF e as cópias da LSDB, refresca LSAs a cada 30 min (MaxAge 60 min) e sugere áreas grandes só
  até onde a CPU aguenta o SPF. `/routing/ospf/lsa print` lista a LSDB; não há um teste de carga
  documentado.
- **FRR 10.7.1** (o `ospfd` da imagem, lido no fonte): SPF com `timers throttle spf 0 50 5000`
  (`lib/libospf.h:87-89`), `MinLSArrival` 1 s e `MinLSInterval` 5 s (`libospf.h:30-31`, RFC 2328
  §13 e §12.4), LSA com MaxAge mantida 60 s antes de sair (`maxage-delay`,
  `OSPF_LSA_MAXAGE_REMOVE_DELAY_DEFAULT`), LSA externa recalculada na hora
  (`ospf_external_lsa_install` → `ospf_ase_incremental_update`, `ospf_lsa.c:2948`), **sem
  limite de LSAs** (nenhum `max-lsa` no `ospfd`). A própria documentação do FRR pede
  `net.ipv4.igmp_max_memberships=1000` (`doc/user/Useful_Sysctl_Settings.md`) e os topotests
  exigem pelo menos isso (`tests/topotests/lib/topotest.py:1385`).
- **Cisco IOS-XE**: `timers throttle spf 50 200 5000`, `timers throttle lsa`, e `max-lsa <n>`
  (proteção da LSDB: aviso, ignorar o vizinho e desligar a adjacência acima do limite).
- **Juniper Junos**: `spf-options delay/holddown/rapid-runs` e `database-protection
  maximum-lsa` (com `warning-only`, `ignore-time`, `reset-time`), o mesmo cuidado contra uma
  redistribuição errada que inunda a LSDB.
- **VyOS / OPNsense**: usam o FRR; os mesmos temporizadores, nenhum limite de LSDB próprio.
- **RFCs**: RFC 2328 (§12.4 MinLSInterval, §13 MinLSArrival, §14 MaxAge, §16 SPF), RFC 8405 (SPF
  back-off), RFC 4222 (priorizar Hello e LSAck sob carga para não perder adjacência), RFC 1765
  (estouro da LSDB: o `ospfExtLsdbLimit`, origem do `max-lsa`), RFC 6987 (stub router).
- **Kernel Linux 6.18.59** (o da imagem, lido no fonte): `ip_mc_join_group` recusa com ENOBUFS
  passado `igmp_max_memberships` por socket (`net/ipv4/igmp.c:2365`, padrão 20 em
  `net/ipv4/af_inet.c:1808`) e cobra 48 B de `optmem_max` por grupo (`sock_kmalloc`,
  `net/core/sock.c:2852`; padrão 128 KiB por namespace em `net/core/net_namespace.c:395`).
- **Ferramentas**: [BNG Blaster](https://rtbrick.github.io/bngblaster/routing/ospf.html)
  1.0.1 (emulação OSPFv2, `ospf-load-mrt`, streams RAW) e
  [`lspgen`](https://rtbrick.github.io/bngblaster/routing/lspgen.html) (topologia e MRT,
  injeção por `-S` no socket de controle).

**O que adotamos:** a bateria (degraus de LSDB, churn, vizinhos, interfaces, operação, latência,
convergência) com critério de passa/falha em cada linha; os pisos de kernel que o FRR pede, como
padrão do roteador; o limite de arquivos do init. **Melhorias propostas:** proteção de LSDB como
o `max-lsa`/`database-protection` (G3.4r, com aviso no CoreRouter antes do limite e o stub router
da RFC 6987 como reação, em vez de derrubar adjacência); expor no CoreRouter os temporizadores de
SPF do FRR (o RouterOS não tem; Cisco e Junos têm) só se o laboratório mostrar necessidade; o
diagnóstico "interface sem o grupo OSPF" no `neighbor.diagnose` (a contagem que o roteiro faz).
