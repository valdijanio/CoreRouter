id: regra-vm-lab
history: G0.26c criada (segunda VM de laboratório, pedido do usuário)

Regra nova no `CLAUDE.md`/`AGENTS.md` ("A VM é uma só: ocupe-a pouco", pedido do usuário em
2026-11-20): conferir funcionamento primeiro no host sem root, bateria curta na VM enquanto
ajusta, a bateria inteira uma vez só no fim e compilação com `vm-lab run --shared`. Motivo: na
rodada da fase C a fila de entrada levou 8–10 min do PR à `main` (**medido**, #697, #699,
#700, #702), e o que atrasou as sessões foi a VM única: a G3.4z esperou a rodada do DNS, que já
segurava a VM havia 919 s (**medido**).

Registra a G0.26c: uma segunda VM de laboratório para testes de funcionamento.

| G0.26c | Segunda VM de laboratório para testes de funcionamento (pedido do usuário) | xtask | O `vm-lab` aceita mais de uma VM (opção `--vm` ou variável de ambiente), cada uma com a própria trava, disco, chave e snapshots. A `corerouter-lab` (8 vCPU, 16 GB) fica para as medições de desempenho; a `corerouter-lab2` (4 vCPU, 8 GB, **estimado**) para os testes de funcionamento. CPUs separadas por VM (`cputune`/`vcpupin`), sem sobrepor as do runner do CI (16 vCPU), para a medição não sofrer ruído; `vm-lab run` usa a livre quando a rodada não pede medição (`--perf` pede a 1); `status` e `unlock` mostram as duas; `docs/vm-lab.md` e a regra do `CLAUDE.md` atualizados. Conferir: duas rodadas ao mesmo tempo, uma em cada VM, e a variação de uma medição na VM 1 com e sem rodada na VM 2 (**medido**). Host: 32 CPUs e 62 GB, 21 GB disponíveis em 2026-11-20 (**medido**) | 4 h | aberto |
