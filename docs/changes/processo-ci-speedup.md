id: processo

CI completo do lote em jobs paralelos: de ~23 min para 5 min 24 s a 7 min 28 s por lote
(**medido**), sem tirar nenhum passo. O lote mais lento é o do `bench-check`, depois que o #268
deixou o benchmark `config_store` lento.

- `.github/workflows/ci.yml`: o job serial `xtask ci (linux)` virou cinco jobs paralelos, cada
  um com `cargo xtask ci --only <passos>`: `lint` (fmt, clippy, docs, ebpf-check, layers,
  agents-sync, wasm), `test`, `bench-check`, `netns` e `xdp-root`. O PR (`--fast`) roda só
  `lint` e `test`; os três lentos rodam no lote da fila (workflow_dispatch) e na `main`. O
  check exigido pela proteção da `main` continua com o nome `xtask ci (linux)`: agora é o job
  final (`if: always()`) que confere o resultado de todos e só aceita "pulado" onde é de
  propósito (PR, PR só de documentação). Os outros dois checks exigidos não mudaram. O
  `scripts/land.sh` lê a conclusão do run inteiro, que já espera todos os jobs; o `main-red`
  também.
- **8 núcleos nos testes, somando runners:** o `test` e o `xdp-root` rodam em duas partes,
  cada uma num runner de 4 vCPU (`COREROUTER_CI_PARTITION=i/2`). O `test` passa
  `--partition hash:i/2` ao nextest (um teste fica na mesma parte quando outros entram; os
  doctests só na parte 1); `.config/nextest.toml` começa primeiro os três testes de mais de
  60 s, que antes, começando por último, seguravam sozinhos o fim de uma parte. O `xdp-root`
  divide os testes de root pelo tempo medido de cada um (o mais longo para a parte mais leve),
  e cada parte continua rodando um por vez, porque eles medem vazão e precisão. Dentro de cada
  job, o nextest e o cargo já usam todos os núcleos (o padrão é o número de CPUs). Runner maior
  é pago e runner próprio na máquina do usuário rodaria código de PR de fork (repositório
  público): nenhum dos dois.
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

Depois, com as partes (runs 40410630612, 40411738352 e 40413648189, cache quente):

| Configuração | `test` (maior parte) | `xdp-root` (maior parte) | `bench-check` | Run inteiro |
|---|---|---|---|---|
| test 1 job, xdp-root 1 job | 366 s | 273 s | 291 s | 6 min 25 s |
| test 2 partes `count`, xdp-root 2 | 304 s (outra: 161 s) | 134 s | 249 s ¹ | **5 min 24 s** |
| test 2 partes `hash` + lentos primeiro | 267 s (outra: 174 s) | 142 s | 429 s ¹ | 7 min 28 s ¹ |
| test 3 partes `hash` | 237 s (outras: 231, 188 s) | 164 s | 397 s ¹ | 6 min 53 s ¹ |

¹ Desde o #268 (mesclado da `main` antes das três medições com partes), o `config_store` do
`bench-check` leva de 104 s a 211 s no CI, contra 12 s antes: montar 10 mil filas
`queue.simple` numa transação leva 117 s localmente, mesmo otimizado. A variação entre runners
(104 s contra ~210 s) decide se o caminho crítico é o `test` ou o `bench-check`. Corrigida
essa montagem, o `bench-check` volta a ~4,3 min e o lote fica em ~5 min 30 s (**estimado**).

Escolha: 2 partes. Com a contagem (`count`), os três testes longos (97, 64 e 62 s) caíram
todos na mesma parte, e o de 97 s começou por último (parte 1 em 174 s de execução, parte 2 em
55 s). Por hash, com os lentos primeiro, a execução das partes ficou em 141 s e 66 s: o limite é
o teste de ~100 s do `proto-pppoe::sim`. Uma terceira parte tirou só 30 s do maior job (237 s
contra 267 s), num job que já não é o caminho crítico, e custa mais uma compilação inteira
(~100 s de runner). Compilar uma vez e distribuir os binários (`cargo nextest archive` +
artifact) não ganha tempo de relógio: o job de build ainda compila 96 s, e soma compactar,
enviar e baixar os binários de teste, antes de as partes começarem (**estimado** ≥ 5 min, contra
~4,5 min compilando em cada parte).

Paralelismo: os passos não dependem um do outro, então cada job compila o que precisa no
próprio runner (4 vCPU cada) em vez de dividir um runner. O `bench-check` ficou em série num
runner só, de propósito: cada parte compilaria de novo quase todo o workspace em `opt-level 1`
(2 min 40 s), e a execução já é limitada por um binário só (`config_store`, depois `ui frames`).
