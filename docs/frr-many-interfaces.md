# O FRR com milhares de interfaces OSPF (G3.4q)

O laboratório de carga do OSPF (G3.4m, `docs/ospf-stress.md`, seção 3b) mediu que o commit de
4 000 interfaces OSPF levava 15–34 s e a remoção ~100 s, quase ao quadrado no `ospfd`. Esta página
diz onde o tempo ia (lido no fonte do FRR 10.7.1 e do `master` de 2026-11-12, `622c8322d2`, e
medido com `perf`), o que foi corrigido no FRR (os patches `0002`–`0006` de `os/patches/frr/`, os
mesmos enviados ao projeto de origem em `docs/frr-upstream/ospfd-many-interfaces/`) e o que ficou
para depois, com os números.

## Como medir

`scripts/frr-ospf-many-ifaces.sh` sobe `mgmtd`, `zebra` e `ospfd` num namespace de usuário, rede e
montagem (sem root), cria N VLANs com um /30 cada e mede, por fase, o tempo e a CPU do `ospfd` e do
`zebra`:

```sh
scripts/frr-ospf-many-ifaces.sh --frr <make install DESTDIR> --n 4000 --out /tmp/x [--kdel group] [--perf]
```

O FRR é compilado com `--prefix=/opt/frr-q --sbindir=/opt/frr-q/lib/frr --sysconfdir=/etc/frr-q
--localstatedir=/run/frr-q` (o roteiro monta o prefixo só dentro do namespace). As fases:

| fase | o que faz |
|---|---|
| `kernel-add` | as N VLANs e seus endereços (`ip -batch`) |
| `ospf-add` | `interface X / ip ospf network point-to-point / ip ospf area 0` das N num lote só (`vtysh -f`, entre `XFRR_start/end_configuration`, como o `hal-frr` digita) |
| `spf` | 5 vezes: o custo de uma interface muda e se lê a duração do último SPF |
| `ospf-del` | o mesmo com `no ip ospf …` |
| `kernel-del` | as VLANs saem: um `RTM_DELLINK` por VLAN (`--kdel one`, como o `hal-linux` faz) ou todas num só, por grupo (`--kdel group`) |

Os números abaixo vieram de uma variante do roteiro que digita a config no vty do `ospfd` linha a
linha e espera cada resposta, exatamente como o `hal-frr` (`crates/hal-frr/src/lib.rs`, `push`).

## Onde o tempo ia

Perfil do `ospfd` e do `zebra` (`perf record -g` e `--call-graph dwarf`, FRR com `-O2 -g
-fno-omit-frame-pointer`), 4 000 interfaces, FRR 10.7.1:

1. **O northbound fazia um commit por interface** (`lib`, a maior parte). O comando `interface X`
   grava a mudança na hora (`nb_cli_apply_changes_clear_pending`, `lib/if.c:1314`), e um comando
   clássico (não YANG) grava o que estiver pendente antes de rodar (`lib/command.c:1011`). Cada
   commit valida e compara a config candidata **inteira** (`nb_candidate_commit` →
   `lyd_validate_all`, `nb_config_diff`, `lyd_dup`): O(n) por interface, O(n²) no lote. Medido no
   cliente vty: as linhas `interface` custavam 8,7 s dos 12,4 s da subida e 12,0 s dos 16,4 s da
   remoção. O motivo do commit imediato (commit `fd396924d6`, 2021) é que os comandos seguintes
   precisam do objeto da interface; quando a interface já existe no sistema, ele já está lá.
2. **Uma router-LSA nova por interface** (`ospfd`). Cada interface que sobe ou desce gera a
   router-LSA na hora (`ism_change_state` → `ospf_router_lsa_update_area`, `ospfd/ospf_ism.c:551`),
   e montar, instalar e inundar a LSA percorre todas as interfaces da área
   (`router_lsa_link_set`, `ospf_ls_retransmit_delete_nbr_area`, `ospf_discard_from_db`,
   `ospf_flood_through_area`): 50–66 % do que sobrou depois do item 1. Com 10 000 interfaces, a
   subida levava 22 s e gerava 10 000 instâncias da LSA (seq `0x80002710`).
3. **A busca linear por `lsa_pos`** (`ospfd`). `ospf_if_lookup_by_lsa_pos`
   (`ospfd/ospf_interface.c:426`) percorre as interfaces da área para achar a de um link da
   router-LSA; o SPF a chama para cada stub da raiz (`ospf_intra_add_stub`, `ospf_route.c:691`) e
   para o next hop de cada vizinho dela (`ospf_spf.c:832`). Cada SPF fica O(n²): 45–50 ms com
   4 000 interfaces, em operação normal, a cada mudança de LSA na área.
4. **O aviso de router-LSA cheia, por link** (`ospfd`). A router-LSA cabe ~5 330 links (o stream
   cresce uma vez só, até `OSPF_MAX_PACKET_SIZE - OSPF_MAX_LSA_SIZE`). Acima disso,
   `link_info_set` (`ospfd/ospf_lsa.c:495`) loga `Out of space in LSA stream` para **cada link que
   ficou de fora, em cada instância nova**: com 10 000 interfaces, **21,8 milhões de linhas e
   2,5 GB de log em ~2 min** (**medido**), o bastante para encher o disco do roteador.
5. **A fila early do `zebra`** (`zebra`). Cada endereço novo varre a subfila inteira de rotas
   "early" atrás de uma rota do kernel igual (`rib_meta_queue_early_route_cleanup`,
   `zebra/zebra_rib.c:4329`, chamada por `connected.c:198`); numa rajada de interfaces a fila tem
   as rotas de todas: O(n²). Com 10 000 VLANs, o `zebra` gastou 37 s de CPU só para criá-las.

O que o perfil mostrou e **não** foi corrigido aqui (seção "Fica para depois").

## As correções (no FRR)

| patch | o quê |
|---|---|
| `0002-lib-batch-existing-interfaces.patch` | Dentro de um lote (`XFRR_start_configuration`) e sem mais nada pendente, entrar numa interface **que já existe** espera o fim do lote, inclusive atravessando os comandos clássicos seguintes, que não dependem do commit (`lib_interface_create` só marca a interface como configurada). Qualquer outra mudança pendente mantém o comportamento de antes. Função nova `nb_cli_apply_changes_classic_safe()`. |
| `0003-ospfd-router-lsa-link-index.patch` | Índice por área: a interface de cada link da última router-LSA montada, preenchido onde `lsa_pos_beg/end` são definidos; a interface sai dele ao cair e ao ser liberada. Busca O(1). |
| `0004-ospfd-full-router-lsa-log-once.patch` | Conta os links que não couberam e loga uma vez quando a router-LSA da área enche (quantos links tem e quantos ficaram de fora) e uma vez quando volta a caber. |
| `0005-ospfd-router-lsa-per-batch.patch` | Durante um lote de config (`ospf_config_start`/`ospf_config_end`, os ganchos que o `ospfd` já tinha), a router-LSA nova espera o fim do lote, no máximo 1 s. Fora de lote, nada muda. Os vizinhos descartariam a maior parte das instâncias de qualquer jeito (MinLSArrival, RFC 2328 §13 (5a)), e §12.4 limita a uma instância por MinLSInterval. |
| `0006-zebra-early-route-queue-by-type.patch` | Conta as rotas early da fila por tipo e pula a varredura quando não há rota do tipo procurado. |

Testes (todos **medidos** em 2026-11-12/13):

- **Do FRR, unitários** (`tests/runtests.py` de `tests/lib`, `tests/ospfd` e `tests/zebra`, como o
  `make check`): `master` com os patches 119 passed, 5 skipped (igual ao `master` sem eles);
  10.7.1 com os patches 68 passed, 5 skipped (igual à 10.7.1 da imagem).
- **Topotest novo** `tests/topotests/ospf_many_interfaces` (vai no envio): 300 interfaces dummy
  configuradas pelo `vtysh -f`; confere que cada rota stub do r1 sai pela interface dona do prefixo
  (é o que o índice por `lsa_pos` resolve), que a router-LSA tem todos os links, que o r2 aprende
  todos os prefixos e o mesmo depois de um lote que tira o OSPF de 100 interfaces (as posições dos
  links que ficam mudam) e outro que o devolve, sem uma instância da router-LSA por interface.
  Com os patches: 3 passed, 1 skipped; sem eles, falha onde deve (`router-LSA 0x80000006 ->
  0x8000006a`, uma instância por interface).
- **Topotests do FRR que tocam o código** (`ospf_many_interfaces ospf_topo1 ospf_p2mp
  ospf_unnumbered ospf_gr_topo1 ospf_tilfa_topo1 ospf_shutdown ospf_dual_stack`, `master` com e
  sem os patches, FRR com todos os daemons): 43 passed, 8 skipped nos dois. Rodam na VM do
  laboratório com `scripts/frr-topotests.sh` (o FRR do `.deb` da VM não é tocado: cada build roda
  num namespace de montagem próprio).
- **`checkpatch`** (`tools/checkpatch.pl` do FRR): 0 erros, 0 avisos nos 6 commits;
  **`clang-format`** 18 com o `.clang-format` do FRR e **`black`** no topotest: sem diferenças.
- **Na imagem:** o log do `cargo xtask os build` mostra `Applying 0002-lib-batch-existing-interfaces.patch`
  a `0006-zebra-early-route-queue-by-type.patch`, o `.applied_patches_list` do FRR tem os seis, e o
  `ospfd` da imagem traz as mensagens novas. A bateria `scripts/ospf-stress-lab.sh --tests
  interfaces --daemon build` passa com a imagem nova: 4 000 interfaces, commit 34,3 → 6,1 s, CPU do
  `ospfd` 28,2 → 1,6 s no commit e 28,6 → 2,5 s na remoção (`docs/ospf-stress.md`, 3b).

## Números

Todos **medidos** em 2026-11-12/13 numa máquina compartilhada (outras sessões compilando: carga
4–64, anotada). Tempo de parede até o `ospfd` e o `zebra` ficarem parados, e entre parênteses a CPU
do `ospfd` (s), que a carga afeta menos. 1 000 e 4 000 na 10.7.1: mediana de 3 rodadas; o resto, uma.

**Config OSPF num lote, como o `hal-frr` digita** (VLANs já criadas):

| versão | interfaces | subida sem → com | remoção sem → com | um SPF sem → com (mediana, ms) |
|---|---|---|---|---|
| 10.7.1 | 1 000 | 0,6 (0,5) → 0,3 (0,1) | 0,9 (0,8) → 0,1 (0,1) | 3 → 0 |
| 10.7.1 | 4 000 | 17,8 (15,9) → 0,6 (0,4) | 35,7 (27,9) → 1,3 (1,1) | 48 → 3 |
| 10.7.1 | 10 000 | 307 (298) → 1,1 (0,9) | 604 (553) → 5,1 (4,7) | 121 → 4 |
| `master` | 4 000 | 74,8 (47,0) → 0,4 (0,3) | 53,3 (50,4) → 0,8 (0,7) | 56 → 6 |
| `master` | 10 000 | 237 (229) → 1,1 (0,9) | 686 (566) → 4,4 (4,1) | 136 → 4 |

Sem os patches as rodadas de 10 000 pegaram carga 33–56 e as com patch, 4–5; numa rodada com
patch sob carga 18–64 a 10 000 deu subida 2,3–16,5 s e remoção 10,5–34,9 s, ainda ~30× menos.

**Com `vtysh -f`** (`scripts/frr-ospf-many-ifaces.sh`, 10.7.1, 4 000, máquina quieta, carga ~2,
2 rodadas cada): subida 9,8–11,3 s (8,2) → 0,4 s (0,3); remoção 13,0 s (12,8) → 0,8 s (0,7); SPF
40–48 → 1–2 ms; router-LSA seq `0x80000fa0` (uma instância por interface) → `0x80000001`;
`zebra` criando as VLANs 4,0 → 2,9 s.

**Log com 10 000 interfaces** (a router-LSA enche em 5 334 links): 21 794 886 linhas `Out of space
in LSA stream` e 2,53 GB de log sem o patch; uma linha `router-LSA is full with 5334 links, 4666
more left out` e 2,5 MB de log com ele. Router-LSA depois da subida: seq `0x80002710` (10 000
instâncias) sem, `0x80000003` com.

**`zebra` criando as VLANs** (CPU, mediana de 3, base e correção alternadas): 10.7.1 com 4 000,
5,3 → 3,9 s; `master` com 10 000, 28,2 → 21,4 s (no `master` a fila early fica mais curta e a
varredura pesa menos: 3,6 % do perfil contra 39 % na 10.7.1).

**Só o kernel** (sem FRR, 4 000 VLANs com um /30): criar 2,3 s; apagar uma a uma (um
`RTM_DELLINK` cada, como o `hal-linux`) **80,6 s**; apagar todas por grupo 1,4 s (G3.4s).

## Fica para depois (gaps novas)

- **G3.4s — `hal-linux`: remover links num lote só.** O kernel leva ~20 ms por `RTM_DELLINK`
  (um período de graça do RCU por link): apagar 4 000 VLANs uma a uma levou **80,6 s** só no
  kernel, sem FRR (**medido**); por grupo (`ip link del group`, `unregister_netdevice_many`),
  **1,4 s**. É quase todo o tempo da remoção que a G3.4m mediu. O `hal-linux` apaga uma por uma
  (`crates/hal-linux/src/netlink.rs:1099`, `delete`). Cuidado: o grupo apaga todo link que o tem,
  então o lote só pode marcar links nossos e conferir o grupo antes.
- **G3.4t — `zebra` da imagem: a varredura da RIB por interface (backport).** Na 10.7.1,
  `if_up`/`if_down` chamam `rib_update_handle_vrf_all` na hora (`zebra/interface.c:1052` e
  `1106`) para achar rotas do kernel pela interface: O(rotas) por interface. Com a remoção em
  grupo, é o que sobra: o `zebra` gasta **107,8 s** para tirar 10 000 VLANs na 10.7.1 e **8,5 s**
  no `master` (**medido**, carga 4–5). O `master` já agrupou essas varreduras num evento
  (`2b16c71752`, "zebra: Use an event for rib_update_handle_vrf_all", 2026-09-10, e o que veio
  junto); falta trazê-lo para a 10.7.1 da imagem e medir. Pular a varredura quando não há rota do
  kernel não bastava: na bateria ficaram 3–4 rotas do kernel com o prefixo de uma conectada (uma
  corrida entre a rota `proto kernel` e a conectada), e um DHCP na caixa também mantém uma (o patch
  foi descartado).
- **G3.4u — `lib`: `event_cancel_event(master, arg)` é O(eventos).** O `ospfd` o chama ao liberar
  cada interface e cada vizinho (`ospf_interface.c:410`, `ospf_neighbor.c:138`), e ele percorre
  todos os timers e sockets: 35 % do que sobrou da remoção com os patches (1,1 s para 4 000). É a
  rede de segurança contra uso depois de liberar; trocá-lo pede auditar todos os eventos com esses
  `arg`.
- **G3.4v — CoreRouter: avisar antes de a router-LSA encher.** Com mais de ~5 330 interfaces OSPF
  numa área, os links a mais não são anunciados (RFC 2328 A.4.2: o tamanho da LSA é de 16 bits). O
  FRR agora loga uma linha; o CoreRouter deveria mostrar isso na checagem do template (quantas
  interfaces casam numa área) e na saúde, com ⓘ.

## Pesquisa

- **RFC 2328:** §12.4 (MinLSInterval, 5 s: no máximo uma instância nova de uma LSA a cada 5 s),
  §13 passo (5a) (MinLSArrival, 1 s: uma instância que chega antes disso é descartada), A.4.2
  (router-LSA: número de links e tamanho em 16 bits). Errata (29 no rfc-editor.org): nenhuma
  sobre MinLSInterval, MinLSArrival ou o tamanho da router-LSA; a 4023 só corrige referências
  cruzadas da §12.4.1.
- **Cisco IOS:** `timers throttle lsa all <start> <hold> <max>` (0/5000/5000 ms; 50/200/5000 ms
  com `default optimize`, os mesmos do IOS-XR): a primeira LSA sai na hora e as seguintes esperam,
  com espera que dobra. É o mesmo princípio do patch `0005`, que só agrupa durante um lote de
  config para não mudar a convergência fora dele.
- **FRR:** já tem `timers throttle lsa all` (`min_ls_interval`), mas só as LSAs opacas o usam; a
  router-LSA sai sem ritmo nenhum. O `ospf6d` agenda a router-LSA por evento
  (`OSPF6_ROUTER_LSA_SCHEDULE`). O PR aberto FRRouting/frr#22331 (next hop de virtual link) mexe no
  mesmo `ospf_if_lookup_by_lsa_pos` e continua compatível com o índice (a função e a assinatura
  ficam).
- **MikroTik RouterOS v7:** a página de OSPF não documenta ritmo de geração de LSA nem limite de
  interfaces ("o número máximo de roteadores numa área depende da CPU").
- **Envio:** `docs/frr-upstream/ospfd-many-interfaces/README.md` (três PRs: `lib`, `ospfd`,
  `zebra`), a publicar pelo usuário (`docs/upstream.md`).
