id: processo

CI completo do lote em jobs paralelos: de ~23 min para ~6,5 min por lote (**medido**), sem
tirar nenhum passo.

- `.github/workflows/ci.yml`: o job serial `xtask ci (linux)` virou cinco jobs paralelos, cada
  um com `cargo xtask ci --only <passos>`: `lint` (fmt, clippy, docs, ebpf-check, layers,
  agents-sync, wasm), `test`, `bench-check`, `netns` e `xdp-root`. O PR (`--fast`) roda só
  `lint` e `test`; os três lentos rodam no lote da fila (workflow_dispatch) e na `main`. O
  check exigido pela proteção da `main` continua com o nome `xtask ci (linux)`: agora é o job
  final (`if: always()`) que confere o resultado de todos e só aceita "pulado" onde é de
  propósito (PR, PR só de documentação). Os outros dois checks exigidos não mudaram. O
  `scripts/land.sh` lê a conclusão do run inteiro, que já espera todos os jobs; o `main-red`
  também.
- `.github/actions/setup`: a preparação comum (pacotes apt, toolchain, rust-cache, nextest,
  módulos do kernel) numa action local. O cache do cargo é por job (cada um guarda só o que
  compila: 0,2–0,5 GB cada, 1,6 GB os cinco, contra 1,1 GB do job único).
- `cargo xtask ci --only a,b` roda só esses passos, na ordem do `ci` (`--fast` junto tira os
  lentos). `cargo xtask ci` sem opção continua igual.
- `bench-check`: compila no perfil novo `bench-check` (`opt-level = 1` com as debug assertions e
  a checagem de overflow de um build de teste) e roda os binários em paralelo, um por CPU, os
  mais lentos primeiro. Continua provando que todo benchmark compila e roda uma vez no modo de
  teste do criterion. Em debug e um depois do outro, eram 9 min 55 s no CI, quase tudo
  rodando montagens grandes (1M de rotas, 100 mil sessões); o maior, `ui frames`, levava 177 s.
- `scripts/land.sh`: os testes instáveis (FLAKY do nextest, "flaky netns test") do CI de cada
  lote vão para o log da fila (`instável (run …): …`), para serem corrigidos antes de causarem
  uma bisseção.

Como testar: `cargo xtask ci --only fmt,wasm`; `cargo xtask ci --only bench-check`;
`cargo xtask ci` (completo, como antes). No GitHub, Actions → ci → Run workflow numa branch.

Atenção: depois do merge, o primeiro CI de PR roda com o cache frio (as chaves novas só são
salvas pela `main`): ~7 min no lote, **medido**; o push na `main` que segue o merge salva os
cinco caches.

## perf

### CI do lote em jobs paralelos (processo, 2026-10-26)

**Medido** no GitHub Actions (`ubuntu-latest`, 4 vCPU), lote da fila (`workflow_dispatch`).

Antes: um job, passos em série. Os últimos 8 lotes verdes levaram de 18,2 a 26 min no job
`xtask ci (linux)` (mediana ~23 min). Um deles por passo (run 40395078035, 21,8 min): fmt 2 s,
clippy 35 s, test 4 min 49 s (compilação 91 s, execução 198 s), bench-check 9 min 55 s
(compilação 21 s, execução ~9,5 min), netns 1 min 42 s, xdp-root 3 min 25 s,
docs/layers/agents-sync/wasm ~20 s, preparação ~1 min.

Depois (runs 40406439545, cache frio, e 40407532159, cache quente):

| Job | Frio | Quente | Onde vai o tempo (quente) |
|---|---|---|---|
| `lint` | 3 min 8 s | 86 s | clippy 34 s, wasm 17 s |
| `test` | 7 min 9 s | 6 min 6 s | compilação 96 s, execução 235 s |
| `bench-check` | 5 min 33 s | 4 min 51 s | compilação (opt-level 1) 2 min 40 s, execução 104 s |
| `netns` | 2 min 54 s | 2 min 55 s | compilação 24 s, execução 70 s |
| `xdp-root` | 4 min 27 s | 4 min 33 s | compilação 16 s, execução ~3 min 54 s |
| build macOS / Windows | 1 min 54 s / 2 min 18 s | 90 s / 187 s | (não mudou) |
| **run inteiro** | **7 min 29 s** | **6 min 25 s** | o caminho crítico é o `test` |

`bench-check` local (AMD Ryzen AI MAX+ 395, 32 CPUs), só a execução: debug em série 353 s
(`ui frames` 126 s); perfil `bench-check` em série 108 s (`frames` 57 s); perfil
`bench-check` em paralelo ~61 s (limitado pelo `frames`). A montagem de 1M de rotas do
`ui_frame/routes_1m` é o que sobra: ~100 s no CI mesmo otimizado.

Paralelismo: os passos não dependem um do outro, então cada job compila o que precisa no
próprio runner (4 vCPU cada) em vez de dividir um runner. O que fica em série é o `test`
(compilação + 2613 testes no nextest); próximo passo, se precisar: dividir o `test` em duas
partições do nextest (`--partition count:i/2`), ~1,5 min a menos **estimado**.
