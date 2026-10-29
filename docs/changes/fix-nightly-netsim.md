id: fix-nightly-netsim

CI noturno verde de novo (issue "CI noturno quebrado", #393): o proptest
`corerouter-netsim tests::decision_matches_proto_bgp` descartava com `prop_assume!` os pares em
que os dois lados são rotas locais (~1 caso em 4). Com os 4096 casos do noturno isso passa do
limite de 1024 descartes globais do proptest e o teste aborta sem achar divergência nenhuma. O
filtro foi para a estratégia (`prop_filter`, que conta como descarte local, limite 65 536). Testar:
`PROPTEST_CASES=4096 cargo test -p corerouter-netsim --lib decision_matches_proto_bgp` (passa,
**medido**, 0,17 s).
