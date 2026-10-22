id: processo

Pontos quentes que sobravam viram arquivos (pedido do usuário, depois da rodada de 7 agentes):
os `pub mod` do engine, do model e do mcp são gerados de `src/` (`build-support/root_modules.rs`);
estado de execução de feature no `Session` por tipo (`s.ext_mut::<T>()`, `crates/engine/src/ext.rs`)
em vez de campo novo; serviços do daemon em `apps/corerouter-daemon/src/service/<nome>.rs` com
`SERVICE` (opções de linha de comando e `start`) — NTP, syslog remoto e métricas migrados, o
`main.rs` não muda mais por serviço; módulos do kernel do CI em `ci/kernel-modules/<módulo>`.
De quebra, duas falhas de pasta de build compartilhada entre worktrees: o `xtask` acha a raiz do
workspace a partir do diretório atual (não do `CARGO_MANIFEST_DIR` do build), e os geradores
vigiam `src/` por caminho absoluto (senão reaproveitavam a lista de outra worktree).

## perf

**Conflitos da rodada de 7 agentes** (**medido**, 2026-10-22): 6 arquivos em conflito em 3 PRs;
5 eram linha acrescentada no fim de lista compartilhada (`pub mod`, campo do `Session`, `spawn`
do daemon, passo do `ci.yml`), 1 era código de verdade (`hal-linux/src/plan.rs`, drift × bonding).
Simulação dos merges de cada par de PRs nas listas de módulos: acrescentando no fim, 7 de 7 pares
conflitam; em ordem alfabética, 2 de 7; geradas dos arquivos, 0. Com as listas geradas, só 1 dos
7 PRs (o do conflito de código) teria ficado fora do primeiro lote, em vez de 3.
