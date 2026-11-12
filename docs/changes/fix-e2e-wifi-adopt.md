id: fix-e2e-wifi-adopt

O teste `e2e::config_and_history_survive_sigterm_and_kill_9` falhava no runner lento com
"SIGTERM lost config or history". Não era perda de config: o rádio `wifi1` do laboratório entra
pela adoção do tick (~2 s depois do início, **medido**), e o retrato antes do SIGTERM saía antes
dela (0,3 s), enquanto o do daemon reiniciado, no runner lento, saía depois — uma interface e um
commit `interface.wifi.adopt` a mais. O teste agora espera a adoção antes de montar a config.
Reproduzido com 2 s de espera depois do reinício (falha 1/1 sem a correção, passa com ela).
