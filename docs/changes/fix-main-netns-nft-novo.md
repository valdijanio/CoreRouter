id: fix-main-netns-nft-novo

`netns` verde com o `nft` antigo e com o novo. Os lotes da fila de 2026-11-10 rodaram no GitHub
(imagem `ubuntu-26.04` 20261101.186.1, nftables 1.1.6), sem o runner próprio (nftables 1.0.9),
e o job `netns` quebrou em `netns_fw_nfnl` e `netns_fastpath` (runs 42926374234 e 42927427905).
Duas mudanças do nftables, achadas no fonte (`git.netfilter.org/nftables`, em
`/srv/build/nftables-src`):

- **Faixa `a-b` num `range`** (commit `50741c52`, "netlink_linearize: use range expression for
  OP_EQ and OP_IMPLICIT", entrou na v1.1.2): `netlink_gen_range` (`src/netlink_linearize.c`)
  grava `== a-b` como `range eq` em vez de `cmp gte` + `cmp lte`. O leitor do `nft` continua
  juntando o par antigo (`expr_may_merge_range`, `src/netlink_delinearize.c`, desde a v0.7, commit
  `3ed93291`), e a v1.0.9 já lê `range eq` (`netlink_parse_range_op`). O kernel tem `nft_range`
  desde o 4.9 e o avalia por chamada direta (`expr_call_ops_eval`, `nf_tables_core.c`, 6.18).
- **Nomes de dispositivo entre aspas** no `nft list` (commit `eb30f236`, "rule: print chain and
  flowtable devices in quotes", v1.1.4): `devices = { "e0", "i0" }`.

A imagem embarca o nftables 1.1.0 (Buildroot 2025.02.19, `os/buildroot.lock`), que ainda grava o
par e não põe aspas.

O que mudou:

- **Codificador** (`corerouter_firewall::bytecode`): uma faixa vira `range eq`, como o nftables
  ≥ 1.1.2 (antes: o par). Medido: +33% de pps com o quadro acima da faixa, empate abaixo (`## perf`).
- **Leitor** (`hal_linux::nft_read`): o par `cmp gte` + `cmp lte` no mesmo registrador, com o
  mesmo tamanho e um logo depois do outro, é lido como `range eq` (os dois casam os mesmos
  pacotes). Assim a tabela que o kernel tem, venha do `nft` < 1.1.2, do ≥ 1.1.2 ou de um
  CoreRouter anterior a esta mudança, é comparada com o que carregamos sem diferença falsa. Sem
  isso, o commit seguinte trocava a tabela inteira (31 regras, perdendo os contadores): conferido
  desligando a junção, o teste novo falha com `replaced: true` nos dois `nft`.
- **Testes:** `netns_fw_nfnl::a_table_with_either_range_form_is_diffed_not_replaced` (tabela
  carregada pelo `nft -f` e na forma antiga; o bytecode no kernel é conferido com
  `nft --debug=netlink`; o commit seguinte sai por diff, 1 regra trocada, as outras com o mesmo
  handle); `nft_read::tests::a_cmp_pair_reads_as_one_range` (o par vira `range`; ordem trocada,
  registradores, tamanhos, `gt`, um limite só ou expressão no meio ficam como estão);
  `netns_fastpath` aceita os nomes com e sem aspas.

Como testar: `cargo xtask ci --only netns` (o `nft` do sistema) e, com o nftables 1.1.6
compilado em `/srv/build/nft-new` (libmnl 1.0.5, libnftnl 1.3.1, jansson 2.14.1, tarballs
oficiais com assinatura GPG conferida),
`PATH=/srv/build/nft-new/bin:$PATH COREROUTER_NFT=/srv/build/nft-new/bin/nft cargo xtask ci --only netns`.
Os dois verdes (**medido**, 2026-11-10).

## perf

- 2026-11-10, fix-main-netns-nft-novo (**medido**): faixa de porta como `range eq` × `cmp gte` +
  `cmp lte`. Kernel 7.0.0-42, build release (`cargo bench`), netns sem root, máquina compartilhada
  (carga 18–52), `netns_forward` "500 port ranges": 500 regras `udp dport A-B drop` no forward
  que nenhum quadro casa, quadros UDP de 64 bytes para as portas 9000–9255, as duas formas
  alternadas no mesmo processo (mediana de 15 rodadas de 20 000 quadros; duas execuções):

  | quadro | `range eq` | par `cmp` | range/par |
  |---|---|---|---|
  | acima da faixa (1000-2000) | 72,5 / 77,9 kpps | 54,4 / 58,3 kpps | 1,33 / 1,34 |
  | abaixo da faixa (20000-30000) | 74,6 / 76,1 kpps | 75,1 / 78,1 kpps | 0,99 / 0,97 |

  Acima, o par avalia as duas expressões e o `range` uma (com as duas `memcmp`); abaixo, o par
  para no primeiro `cmp`. Medir as formas em execuções separadas não serviu: com a carga da
  máquina mudando (carga 52 → 33), o `range` saiu com −58% e −47% (`--baseline`); alternadas,
  a diferença é a de cima.
