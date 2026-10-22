id: processo

Binários sempre atuais: a fila de entrada leva o checkout principal para a `main` nova e
recompila daemon, GUI e CLI depois de cada lote (só na `main` e sem alterações; `LAND_REBUILD=0`
desliga). Crate novo `corerouter-buildinfo` (L0) com o commit do build: o `server.info` o informa
e a barra da GUI avisa "daemon <commit> ≠ GUI <commit>" quando o daemon rodando é de outro build
(o usuário testou correções contra um daemon velho). O `plan/hw-lab.sh` local também recompila
antes de subir o daemon, a GUI e o terminal.
