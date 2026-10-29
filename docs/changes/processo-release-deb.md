id: processo

O `.deb` do gerenciador (GUI + CLI, G0.28) no GitHub Releases. `.github/workflows/release.yml`:
uma tag `v*` gera, num runner Ubuntu 22.04 do GitHub (sem cache, não no self-hosted), o
`corerouter-gui_<versão>_amd64.deb`, o `SHA256SUMS` e as notas da versão, e cria a Release em
**rascunho** (o dono revisa e publica). `workflow_dispatch` com uma versão e PR que mexe no
workflow ou em `xtask/src/package*` só geram os arquivos, como artifact do run. Actions fixadas
por SHA; `permissions: {}` no topo, `contents: read` no build e `contents: write` só no job que
roda o `gh release create` (sem checkout nem código do repositório).

`cargo xtask package gui --version <v>`: a versão do `.deb` vem da tag (`v0.2.0` → `0.2.0`,
`v0.2.0-rc.1` → `0.2.0~rc.1`) e tem de ser a do workspace, para o pacote e o `server.info`
dizerem o mesmo. `cargo xtask package notes [--since <tag>]`: uma linha por entrada do
`docs/log.md` que a tag anterior não tinha (300 caracteres cada, 100 kB no total; o log inteiro
dá 98 kB, **medido**). A imagem do roteador fica fora (assinada com a chave do dono, que não vai
para o CI); `docs/install-gui.md` diz como baixar, conferir o SHA-256 e anexar a imagem assinada
localmente.

Testar: `cargo xtask package gui --version 0.1.0-test.1` e `cargo xtask package notes --since
HEAD~5`; no GitHub, o job `build (.deb)` roda no próprio PR. Primeira versão, depois do merge:
`git tag -a v0.1.0 -m "CoreRouter 0.1.0" origin/main && git push origin v0.1.0`.
