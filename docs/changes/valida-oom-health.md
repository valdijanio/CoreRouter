id: valida-oom-health

Saúde: "OOM kills" dizia "ok" dez minutos depois de o kernel matar o próprio daemon. Achado na
validação das rodadas 1 e 2 na VM `corerouter-teste` (imagem `cb5867de`, 2 GiB): um
`ip.route.list` de 60 000 rotas levou o daemon a 1,85 GiB, o OOM killer o matou e o
`corerouter-init` o reiniciou; System › Resources mostrava "nenhum processo morto por falta de
memória na última hora". A checagem só contava o `oom_kill` do `/proc/vmstat` (contagem desde o
boot) quando ele subia entre duas leituras do mesmo processo, e o daemon novo começava com a
morte já contada. Agora a primeira leitura conta o que o kernel já contou quando a máquina subiu
há menos de uma hora (`OOM_WINDOW`): essas mortes são recentes por definição. Numa máquina ligada
há mais tempo elas não têm data e continuam fora (gap G1.6qj).

Como testar: `cargo test -p corerouter-engine --lib health_check` (teste novo
`kills_before_the_daemon_started_count_when_they_are_recent`: máquina com 700 s, morte de antes do
daemon contada, saída da janela, máquina ligada há dias, primeira leitura sem morte).

Desempenho e paralelismo: uma comparação a mais por leitura de saúde (a cada 5 s), fora de
qualquer caminho quente; nada a dividir.

| G1.6qj | Saúde: datar pelo kmsg as mortes por OOM de antes do daemon | engine, daemon | Numa máquina ligada há mais de uma hora, um daemon reiniciado depois de morto pelo OOM killer não sabe quando foi a morte (o `oom_kill` do `/proc/vmstat` só conta) e a checagem "OOM kills" fica "ok". As linhas "Out of memory: Killed process" do kmsg trazem o instante desde o boot: o serviço do OS Log as lê; usar esse instante na checagem e dizer qual processo morreu (o próprio daemon, o FRR) | 2 h | aberto |
