# Fuzzing (G0.5)

Toda entrada que chega de fora é hostil: o arquivo de config salvo, as linhas do canal de
controle (TCP, TLS, WebSocket) e as mensagens MCP. Cada uma tem um **oráculo** — uma função que
recebe bytes, percorre o caminho de verdade e devolve `Err` dizendo o que quebrou — e o mesmo
oráculo roda de dois jeitos:

| Rodada | Onde | Como | Tempo |
|---|---|---|---|
| Curta, determinística | `cargo xtask ci` (passo `test`) | proptest com semente fixa, sem arquivos de falha | ~2 s nos três crates (**medido**) |
| Longa, aleatória, sem nightly | máquina do desenvolvedor | `COREROUTER_FUZZ_CASES=N` nos mesmos testes | o que couber |
| Longa, guiada por cobertura | máquina do desenvolvedor | `cargo +nightly fuzz run` (libFuzzer), crate `fuzz/` | 10 min por alvo |

## Alvos

| Alvo (`fuzz/fuzz_targets`) | Oráculo | O que confere |
|---|---|---|
| `config_file` | `corerouter_engine::fuzz::config_file` | `persist::decode` não entra em pânico; um arquivo que decodifica volta igual depois de salvar → ler → salvar; o roteador **dá boot** a partir dele e responde a todas as consultas (comandos sem journal) sem pânico — o decode confere o formato, não o significado, então um arquivo editado à mão chega ao motor |
| `wire` | `corerouter_control::fuzz::wire` | `read_line_bounded` com limite (1..=64) e blocos de leitura (1..=4 bytes) escolhidos pelo primeiro byte: toda linha cabe no limite e não tem `\n`, a leitura sempre termina, e sem linha longa demais as linhas reconstroem a entrada |
| `control_line` | `corerouter_control::fuzz::control_line` | uma linha de requisição como TCP/TLS/WebSocket a respondem (`server::answer`), num lab virtual novo; um objeto JSON sem `token` recebe o token local, para o fuzzer passar do portão e chegar aos comandos; resposta sempre com `ok`, nenhum pânico |
| `mcp_messages` | `corerouter_mcp::fuzz::messages` | várias linhas no servidor MCP (`serve`) num lab novo: cada resposta é um objeto JSON-RPC 2.0 (ou lote) com exatamente um de `result`/`error`, nenhum pânico |

**Pânico capturado também é falha.** O guarda do motor (`engine::guard`) transforma um pânico em
`Internal` e a resposta parece normal; por isso `corerouter_engine::fuzz::panics` instala um
hook que conta os pânicos da thread. Sob o libFuzzer o hook anterior (o do `libfuzzer-sys`)
aborta, então até um pânico capturado vira crash com o arquivo em `fuzz/artifacts/`.

Os testes de CI ficam em `crates/{engine,control,mcp}/tests/fuzz.rs`. Eles geram entradas com
estrutura (JSON com ids de comando reais, referências `$1.id` de lote, configs salvas com edições
que preservam o tipo, para o arquivo ainda decodificar e o config hostil chegar ao boot) e
**reexecutam** todos os arquivos de `fuzz/seeds/<alvo>/` e `fuzz/regressions/<alvo>/`.

## Rodada longa

Sem nightly (aleatória, mesma geração estruturada da CI; a falha imprime a entrada mínima):

```sh
COREROUTER_FUZZ_CASES=20000 cargo test -p corerouter-engine -p corerouter-control -p corerouter-mcp --test fuzz
```

Com libFuzzer (precisa de `rustup toolchain install nightly` e `cargo install cargo-fuzz`; `-s
none` porque o código é Rust seguro, sem `unsafe`, e o sanitizador só deixaria mais lento):

```sh
cd fuzz
cargo +nightly fuzz run -s none config_file corpus/config_file seeds/config_file -- \
    -dict=json.dict -max_total_time=600 -timeout=10
```

Troque `config_file` por `wire`, `control_line` ou `mcp_messages`. O primeiro diretório
(`corpus/<alvo>`, fora do git) cresce com as entradas novas; `seeds/<alvo>` (no git) só é lido.
`json.dict` traz os tokens JSON e os nomes de chaves, métodos e comandos.

## Achou um crash

1. Reproduza: `cargo +nightly fuzz run -s none <alvo> artifacts/<alvo>/crash-…` e, de preferência,
   minimize: `cargo +nightly fuzz tmin -s none <alvo> artifacts/<alvo>/crash-…`.
2. Copie a entrada para `fuzz/regressions/<alvo>/<nome-que-diga-o-bug>` (no git): a partir daí o
   `cargo xtask ci` a reexecuta para sempre.
3. Corrija no crate dono, com a causa no commit.
