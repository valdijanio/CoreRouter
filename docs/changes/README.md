# Arquivos de mudança (um por PR)

Cada PR grava **um arquivo só seu** aqui, `docs/changes/<id>.md` (ou `<id>-<slug>.md`, quando a
mesma gap tem mais de um PR), em vez de editar `docs/log.md`, `docs/gaps-history.md` ou a coluna
Status de `docs/gaps.md`. Um arquivo que só um PR toca nunca conflita.

Quem consolida é a fila de entrada (`scripts/land.sh`, rodada pela sessão principal), de tempos
em tempos (com `--fold` ou 10 arquivos pendentes, como o towncrier/changesets no release):
`cargo xtask docs fold` aplica os arquivos nos documentos e os apaga, num PR só de docs. Até lá,
`cargo xtask docs pending` mostra os status de gap ainda não consolidados. O `cargo xtask ci`
confere o formato (passo `docs`).

## Formato

```text
id: G4.7c
status: feito (`stream/G4.7c-dhcp-resilience`): endereço reserva, checagem do gateway, lease lembrado
history: G4.7c feito (resiliência do cliente DHCP)

Cliente DHCP, parte 3: o que entrou, como testar (comandos ou cliques) e os números, marcados
como **medido** ou **estimado**. Pode ter várias linhas e parágrafos.

| G4.7d | Gap nova que este PR descobriu | proto-dhcp | Critério de aceite | 4 h | aberto |
```

- **Cabeçalho** (até a primeira linha em branco):
  - `id:` obrigatório: o id da gap (`G4.7c`) ou, para trabalho sem gap, uma etiqueta minúscula
    (`processo`, `docs`, `audit-e2e`: letras minúsculas, dígitos e `-`, começando por letra). O
    nome do arquivo começa com ele.
  - `status:` opcional: o texto novo da coluna Status da linha `id` em `docs/gaps.md`.
  - `history:` opcional: uma linha para `docs/gaps-history.md` (criou, redefiniu ou mudou o
    status de um item).
- **Corpo:** o texto da entrada de `docs/log.md`. O fold prefixa `- AAAA-MM-DD — <id>: ` com a
  data do merge.
- **Linhas de tabela** no corpo (`| G… |`) são gaps novas: entram em `docs/gaps.md` logo depois
  da linha anterior da mesma fase. O id tem de ser novo; confira na `origin/main`.
- **`## perf`** (opcional, no fim): tudo depois dessa linha vai para o fim de `docs/perf.md`
  (medições **medidas**, com máquina, build e data). Não edite o `perf.md` à mão: todo PR de
  desempenho acrescentava no fim dele, e PRs paralelos conflitavam.

`cargo xtask docs` confere todos os arquivos (sem gravar). `cargo xtask docs fold [--date
AAAA-MM-DD]` aplica e apaga.
