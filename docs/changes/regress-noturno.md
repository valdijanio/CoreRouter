id: regress-noturno
history: G0.30k criada (regressão noturna dos laboratórios, pedido do usuário)

Registra a G0.30k: regressão de desempenho e de carga no CI noturno, em vez de uma bateria em
cada gap. Decisão do usuário (2026-11-20), depois de comparar três caminhos:

- bateria por gap (`xtask regress --affected`) mais um subagente revisor: 15–40 min a mais por
  gap típica, mais a disputa pela VM do laboratório (**estimado**);
- só o noturno: zero minutos por gap, ~1 h de runner por noite (**estimado**);
- deixar como está: o CI pega teste quebrado, mas não pega desempenho pior nem defeito que só
  aparece com carga (os da fase C: o p99 de 404 ms do DNS e a rota que cortou a gerência só
  apareceram no notebook).

Ficou o noturno. O custo é achar a regressão até 24 h depois, apontando o dia (a lista de PRs
que entraram) e não o PR.

| G0.30k | CI noturno de regressão: laboratórios inteiros comparados com a noite anterior (pedido do usuário) | `.github/`, xtask, scripts | Job novo no `nightly.yml`, no runner próprio (`corerouter-ci`, só a `main`), que roda os laboratórios que já existem: `dns-stress-lab.sh` (`ops`, `qps`, `hostile`), `ospf-stress-lab.sh`, `cargo xtask os boot-test` e `install-test`. Grava os números de cada noite (artefato ou branch de dados) e compara com a última noite verde, com margem por métrica (p99, consultas/s, CPU, RSS, tempo de boot) calibrada pela variação medida entre noites sem mudança. Piora acima da margem abre (ou comenta) a issue "Regressão noturna" com a métrica, os dois valores, os logs e a lista dos PRs que entraram desde a última noite verde; a issue fecha sozinha quando a métrica volta. Nada muda no portão do PR nem no tempo das gaps; ~1 h de runner por noite, **estimado** | 4 h | aberto |
