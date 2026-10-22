# Servidor MCP

`crates/mcp`: JSON-RPC 2.0 por stdio, escrito à mão (sem SDK, sem runtime assíncrono). Não tem
lógica de roteador: cada tool vira uma chamada de método do canal de controle num `Backend`, que
termina no mesmo `Session::execute` da UI. stdout é só protocolo; logs vão para stderr.

## Backends

| Modo | Como iniciar | Quando usar |
|---|---|---|
| Remote | `corerouter-gui --control 7979` (ou `corerouter-daemon`), depois `corerouter-cli mcp --connect 127.0.0.1:7979` | Ver o agente trabalhar ao vivo; `ui_screenshot` funciona com a GUI |
| Headless | `corerouter-cli mcp --headless` | Automação e CI: virtual lab em processo, tudo menos tools de UI |
| Sem flag | `corerouter-cli mcp` | Tenta 127.0.0.1:7979 e cai para headless |

```sh
cargo install --path apps/corerouter-cli --locked
claude mcp add corerouter -- corerouter-cli mcp
```

## Tools

| Tool (aliases) | Faz | Annotations |
|---|---|---|
| `list_commands` / `command_list` | Registro inteiro (id, `params`, enabled + motivo); `prefix` filtra | read-only |
| `run_command` / `command_run` | `{command, params}` → `Session::execute` | destrutiva |
| `command_batch` | Até 256 passos, `"$N.chave"` referencia resultados; `atomic` (padrão true) = um commit | destrutiva |
| `inspect_state` / `state_inspect` | Resumo, ou uma subárvore por `path` (`interfaces`, `routing.bgp`, `running.ip`, `journal`) | read-only |
| `ui_screenshot` / `screenshot` | PNG da janela (só Remote com GUI) | read-only |

Erros de tool voltam como texto com `isError: true` ("unknown parameter 'adress'; did you mean
'address'?"), nunca como erro de protocolo — o agente lê e corrige.

Limites: linha de até 16 MiB, lote JSON-RPC de até 64 mensagens, `command_batch` até 256 passos.
Faltando (G0.7): resources, prompts, completions, progresso/cancelamento, `-32003` (ocupado).

## Histórico de revisão

- 2026-10-21 — versão inicial.
