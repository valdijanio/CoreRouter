id: valida-bgp-history-flap

`routing.bgp.session.history` perdia a sessão que sobe e cai entre duas amostras do serviço `frr`
(a cada 2 s). Achado na validação das rodadas 1 e 2 (`scripts/bgp-crcr-userns.sh maxprefix`,
CoreRouter × FRR 10.7.1 no host): o `max_prefix_ipv4=3` com `shutdown` fecha a sessão com o R3
logo depois do Established; as duas amostras dizem `idle` e só o contador `flaps` anda (0 → 1),
e o histórico ficava vazio, justo no evento que o operador procura. Agora `flaps` maior com a
sessão fora nas duas amostras entra como `down`, com o motivo (`Reached received prefix count`)
e sem uptime (não se sabe quanto ficou de pé). Teste
`bgp_history::tests::up_and_down_between_two_samples_is_a_down` (o código antigo reprova).

Como testar: `cargo test -p corerouter-engine --lib bgp_history`.

Desempenho e paralelismo: uma comparação a mais por sessão por amostra, O(1); nada muda no
custo da amostra (O(sessões), uma thread, a do serviço `frr`).
