# O `ospfd` abortava com TI-LFA (G3.4l)

Com `fast-reroute ti-lfa`, o `ospfd` do FRR 10.7.1 abortava no laboratório com

```
ospfd/ospf_spf.c:1269: get_reverse_distance(): assertion (w_lsa && w_lsa->data) failed
```

e o watchfrr o reiniciava, derrubando todas as adjacências. O defeito está no FRR (10.7.1 e
`master` de 2026-10-29, `4ac34f1afa`), foi lido no código, reproduzido de forma determinística no
teste unitário do próprio FRR e ao vivo na VM do laboratório, e tem correção de uma linha.

## O que acontece dentro do FRR

O TI-LFA do `ospfd` (`ospfd/ospf_ti_lfa.c`) calcula, para cada recurso protegido (link ou nó):

1. o **P-space**: uma cópia da árvore SPF do roteador sem o recurso
   (`ospf_ti_lfa_generate_p_space`);
2. para cada destino dessa árvore, um **Q-space**: uma árvore SPF **reversa** com raiz no
   destino (`ospf_ti_lfa_generate_q_spaces` liga `area->spf_reversed` e chama
   `ospf_spf_calculate`).

No SPF reverso, o custo de um link ponto a ponto V→W é o do link **de volta**, W→V, lido da
router-LSA de W. O `ospf_spf_next` (`ospfd/ospf_spf.c`) faz, para cada link de V:

```c
w_lsa = ospf_lsa_lookup(area->ospf, area, OSPF_ROUTER_LSA, l->link_id, l->link_id);
...
if (type == LSA_LINK_TYPE_POINTOPOINT && area->spf_reversed)
        link_distance = get_reverse_distance(v, l, w_lsa);   /* assert(w_lsa && w_lsa->data) */
...
if (w_lsa == NULL) {            /* RFC 2328 §16.1 (2b): sem LSA, examine o próximo link */
        continue;
```

A checagem da RFC 2328 §16.1 (2b) ("se a LSA não existe… examine o próximo link") vem **depois**
da leitura do custo reverso. No SPF normal, uma router-LSA que cita um vizinho sem LSA no LSDB só
faz pular o vizinho; no SPF reverso, o `assert` derruba o daemon antes de chegar ao `continue`.
O próprio `get_reverse_distance` já trata a LSA incompleta (cai no custo de ida), mas não a LSA
ausente.

### Quando a LSA de W falta no LSDB

Uma router-LSA de V cita W enquanto a router-LSA de W não está no LSDB de quem calcula:

- **W apagou a própria LSA** (flush: MaxAge, confirmado pelos vizinhos e retirado do LSDB) enquanto
  a adjacência V–W ainda está de pé dos outros lados, até o dead-interval. Acontece quando W
  **troca de router-id** (a LSA do id antigo é descartada) ou **tira o `router ospf`** — é o que o
  `hal-frr` faz no R1 entre os testes do `scripts/frr-sr-live.sh`, e por isso os que abortavam
  eram R2 e R4, os vizinhos do R1;
- a LSA de W ainda não chegou, enquanto a de V (que já cita W) chegou: corrida na subida (a
  hipótese inicial; possível pelo código, mas não foi o gatilho medido).

### A prova

**Teste unitário do FRR, determinístico.** `tests/ospfd/test_ospf_spf` ganhou a `topo6`: o
triângulo da `topo1` mais o RT4, que o RT3 anuncia por um link ponto a ponto mas cuja router-LSA
não é injetada (campo novo `no_router_lsa`). `test ospf topology topo6 root rt1 ti-lfa` aborta
no 10.7.1 e no `master`, sempre:

```
#3  _zlog_assert_failed (xref=..., extra=0x0) at lib/zlog.c:801
#4  get_reverse_distance (v=..., l=..., w_lsa=0x0) at ospfd/ospf_spf.c:1269
#5  ospf_spf_next (v=..., area=..., candidate=...) at ospfd/ospf_spf.c:1432
#6  ospf_spf_calculate (..., is_dry_run=true, is_root_node=false) at ospfd/ospf_spf.c:1770
#7  ospf_ti_lfa_generate_q_spaces (..., recursive=true, pc_path=0x0) at ospfd/ospf_ti_lfa.c:686
#8  ospf_ti_lfa_generate_p_space (...) at ospfd/ospf_ti_lfa.c:841
#9  ospf_ti_lfa_generate_p_spaces (..., protection_type=OSPF_TI_LFA_LINK_PROTECTION) at ospfd/ospf_ti_lfa.c:952
```

(gdb no 10.7.1 compilado com `-O0 -g3`; `w_lsa = 0x0`.)

**Ao vivo, na VM.** `scripts/frr-tilfa-repro.sh` monta só OSPF e TI-LFA (sem LDP, sem BFD, sem o
CoreRouter): cada roteador é um `zebra` + `ospfd` num namespace, os quatro no quadrado do
`frr-sr-live.sh`, partidos em sequência, um flap de link e, conforme `--churn`, a troca de
router-id ou a remoção do `router ospf` no R1. O FRR é o nosso build de depuração com logs
`G34L` no SPF reverso (vértice, router-id procurado, se a LSA existe, idade) e nos P/Q-spaces.
Em todo abort, a linha anterior é do tipo

```
G34L reverse-spf: root 10.255.0.4 V 10.255.0.2 (distance 30) link to W 10.255.0.1 metric 10:
  W router-LSA ABSENT age 0 seq 0x00000000 stat -1; router-LSAs in LSDB 4
```

e o backtrace que o próprio FRR grava no log é o mesmo do teste unitário.

Rodadas na VM, **medido** em 2026-10-29 (8 vCPUs, Ubuntu 24.04, build `-O0 -g3`), quadrado com
SR e TI-LFA de link; cada iteração monta tudo do zero (~20–25 s):

| FRR | gatilho no R1 | iterações | aborts | passagens por LSA ausente | rotas faltando |
|---|---|---|---|---|---|
| 10.7.1 | só subida + flap de link | 50 | **0** | 0 | 0 |
| 10.7.1 | troca de router-id + flap | 40 | **15** (37 %) | 15 (todas abortaram) | 0 |
| 10.7.1 + correção | troca de router-id + flap | 40 | **0** | 27 (todas puladas) | 0 |
| master `4ac34f1afa` | (no teste unitário: aborta sempre sem a correção, passa com ela) | — | — | — | — |
A hipótese inicial (corrida na subida, LSA do vizinho ainda não chegou) não se confirmou: a
subida sozinha não deixou nenhuma LSA ausente em 50 iterações. O que reproduz é uma LSA que
**sai** do LSDB enquanto outras ainda a citam.

## A correção

`os/patches/frr/0001-ospfd-ti-lfa-missing-router-lsa.patch` (aplicado pelo Buildroot ao FRR
da imagem; o `cargo xtask os build` faz `frr-dirclean` quando os patches do FRR mudam):

```c
if (type == LSA_LINK_TYPE_POINTOPOINT
    && area->spf_reversed && w_lsa)
        link_distance = get_reverse_distance(v, l, w_lsa);
```

Sem a LSA, o custo de ida vale só até a checagem logo abaixo, que pula W como no SPF normal.
Nada muda quando a LSA existe. Com a correção, a `topo6` dá exatamente os caminhos de reserva da
`topo1` (o RT4 só some), e as outras cinco topologias do teste não mudam.

Reportado ao FRR, a pedido do usuário e pela conta dele: issue
[FRRouting/frr#24091](https://github.com/FRRouting/frr/issues/24091) e PR
[FRRouting/frr#24092](https://github.com/FRRouting/frr/pull/24092). O texto e os dois patches
ficam em `docs/frr-upstream/`.

## O que muda para a produção

- O FRR da imagem passa a levar a correção. O `.deb` 10.7.1 da VM do laboratório **não** a tem:
  os roteiros que ligam TI-LFA na VM (`frr-sr-live.sh`) ainda podem abortar quando o R1 muda.
- O TI-LFA **continua desligado por padrão**: a perda medida de um corte no Linux não cai com
  ele (G3.4k). A prévia deixa de falar em abort do `ospfd` e passa a dizer isso.

## Como repetir

```sh
# fonte e build de depuração (container Ubuntu 24.04 com libyang 3.13.6, como a VM)
git clone https://github.com/FRRouting/frr.git && cd frr && git checkout frr-10.7.1
git am docs/frr-upstream/0002-*.patch      # só o teste: aborta
./bootstrap.sh && ./configure --enable-dev-build CFLAGS="-O0 -g3" && make
printf 'test ospf topology topo6 root rt1 ti-lfa\n' | tests/ospfd/test_ospf_spf
# ao vivo, na VM (tarball de um FRR instalado em /opt/frr-dbg)
cargo xtask vm-lab put frr-dbg.tar.gz
cargo xtask vm-lab run -- scripts/frr-tilfa-repro.sh --frr /srv/lab/inbox/frr-dbg.tar.gz \
  --topo square --sr on --runs 40 --churn rid
```
