id: processo-ci-runner-registrado

Os runners próprios do CI (`corerouter-ci-1…3`, VM `corerouter-ci`) foram registrados pelo dono e
estão `online`; a política de PR de fork ficou em `all_external_contributors`. A partir de agora o
lote da fila manda `test`, `bench-check` e `netns` para eles (255 s por lote contra 445 s nos
runners do GitHub, **medido** no #465). `docs/ci-runner.md` diz o estado e quando um token novo é
preciso.
