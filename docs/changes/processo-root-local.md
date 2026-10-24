id: processo

Teste que precisa de root (`cargo xtask xdp-root`): o usuário roda na máquina dele, num namespace
descartável, e o `sudo` pede a senha dele. A receita está em `AGENTS.md`, "Acesso root e testes de
rede". O agente continua sem `sudo`. Uma rodada local leva segundos; um `workflow_dispatch` no
runner leva cerca de 15 min (**medido**, 2026-10-24). A saída local traz o `Verifier output`
inteiro, que o log do CI corta. A primeira rodada local mostrou que o verificador aceita o
programa da G2.5b e isolou a única falha restante (`perf_fast_nat`).

## perf

Primeira rodada local do `xdp-root` (**medido**, AMD Ryzen AI Max+ 395, 32 threads, kernel
7.0.0-38, objeto XDP do prebuilt, 2026-10-24). Custo por pacote (`BPF_PROG_TEST_RUN`): liberado
42 ns (134 no runner do CI), bloqueado com 1 milhão de prefixos 126–134 ns (271 no runner),
carga de 1 milhão de prefixos 698–702 ms. Envio em veth, em kpps: sem filtro 2027, nftables
raw 2116–2171, XDP generic 1855–1889, XDP native 1785–1811 (duas rodadas).
