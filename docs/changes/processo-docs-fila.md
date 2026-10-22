id: processo

AGENTS.md e template de PR descrevem a fila como ela é: o usuário aprova ao pedir a rodada e a
fila contínua (`--watch`, rótulo `fila`) integra sozinha, com o resultado do CI lido dos runs do
Actions. Números das rodadas no `docs/perf.md`.

## perf

**Rodada 2 de agentes** (**medido**, 2026-10-22, horário de Brasília): 4 features pequenas
(G0.5c, G1.8d, G4.4c, G4.6e) de 13:35 a 13:53 — sessões prontas em 4 a 12 min, dois lotes de
3,4 min (3 PRs) e 5,3 min (1 PR), zero conflito, zero teste instável travando, nenhuma intervenção.

**Fila contínua com lote especulativo** (**medido**, 14:47–14:52): lote de 4 PRs (#93 DNS, #94,
#95, #96) entrou 4,5 min depois de o lote começar; o #97 (log), que ficou pronto com o lote já no
CI, foi testado num lote especulativo em cima dele e entrou **44 s** depois, sem esperar outro CI.
Antes disso, o lote do #94 ficou 20 min parado: o GitHub manteve o check-run do job Linux em
"in_progress" depois de o job terminar verde; a fila passou a ler os runs do Actions.
