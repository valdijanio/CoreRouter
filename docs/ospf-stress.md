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

RESULTS

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

## Achados sem correção neste PR

- **`ip.route.list` não mostra rotas do OSPF** (só conectadas, estáticas, DHCP e RA): virou a
  G3.4o (registrada pela G3.4n).
- **`ospfd` com milhares de interfaces numa área (FRR):** commit de 4 000 interfaces em 15–34 s,
  remoção em ~90–100 s; o `ospfd` cresce quase ao quadrado (CPU no commit: 0,7 s → 3,2 s → 11,8 s
  para 1 000, 2 000 e 4 000). Perfil: `route_top`/`route_next` (8 %), `ospf_if_lookup_by_lsa_pos`
  (busca linear nas interfaces da área, `ospfd/ospf_interface.c:426`, chamada por link da
  router-LSA no SPF e na instalação de rotas: `ospf_spf.c:832`, `ospf_route.c:691` e `:876`),
  `ospf_router_lsa_body_set` e o `libyang` do northbound. Gap G3.4q.
- **Sem proteção de LSDB:** o `ospfd` aceita qualquer número de LSAs (nenhum `max-lsa`); uma
  redistribuição errada num vizinho leva o roteador à falta de memória. Cisco (`max-lsa`) e Junos
  (`database-protection`) protegem. Gap G3.4r.

FASEC

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
