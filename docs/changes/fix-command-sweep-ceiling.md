id: fix-command-sweep-ceiling

O teste `command_sweep::no_command_panics_on_garbage` passou do teto de 10 s da camada rápida
no runner do GitHub (10,23 s, **medido**, run 40988400131) e tirou o #489 da fila. Ele cresce
com cada comando novo, então agora são 16 testes (`no_command_panics_on_garbage::shard_00…15`,
comando de índice `i` módulo 16), que o nextest roda lado a lado, mais um que confere que os
shards cobrem todos os comandos. Cada shard leva 0,25–0,46 s num build dev da máquina de
desenvolvimento (**medido**, 2026-10-30); a cobertura não muda.
