id: processo-unsafe-revisao

A regra do `unsafe` no `CLAUDE.md`/`AGENTS.md` foi atualizada: o crate `dataplane-ebpf` já existe
e tem programas XDP e tc, e o caminho da revisão humana, que só existia na prática (G3.9db,
#505), ficou escrito: o PR com `unsafe` abre sem o rótulo `fila` e com a seção
`## Revisão humana necessária`; a sessão principal resume cada bloco ao usuário; só depois do
"aprovo" dele ela põe o rótulo e registra a aprovação no PR. Todo bloco novo ou alterado passa
pela revisão, sem catálogo de padrões já aprovados (decisão do usuário, 2026-10-30).
