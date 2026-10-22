# Servidor MCP

`crates/mcp`: JSON-RPC 2.0 por stdio, escrito à mão (sem SDK, sem runtime assíncrono). Não tem
lógica de roteador: cada tool vira uma chamada de método do canal de controle num `Backend`, que
termina no mesmo `Session::execute` da UI. stdout é só protocolo; logs vão para stderr.

## Backends

| Modo | Como iniciar | Quando usar |
|---|---|---|
| Remote | `corerouter-gui --control 7979` (ou `corerouter-daemon`), depois `corerouter-cli mcp --connect 127.0.0.1:7979` | Ver o agente trabalhar ao vivo; `ui_screenshot` funciona com a GUI |
| Remote TLS | `COREROUTER_PASSWORD=… corerouter-cli mcp --connect 10.0.0.1:8729 --user admin [--fingerprint SHA256:…]` | Roteador em outra máquina (`corerouter-daemon --listen`) |
| Headless | `corerouter-cli mcp --headless` | Automação e CI: virtual lab em processo, tudo menos tools de UI |
| Sem flag | `corerouter-cli mcp` | Usa 127.0.0.1:7979 se houver algo ouvindo (erro claro se faltar credencial), senão headless |

**Autenticação (G0.3).** Em `127.0.0.1` o MCP manda o **token local** que o daemon (ou a GUI
com `--control`) gravou num arquivo legível só pelo usuário do sistema que o rodou
(`control-<porta>.token`, veja `docs/control-protocol.md`): rodando como o mesmo usuário, não há
senha a configurar. Outro usuário, ou um roteador remoto (sempre TLS), usa `--user` com a senha
em `$COREROUTER_PASSWORD` (o stdin é o protocolo, não há prompt). O certificado de um roteador
novo precisa estar em `known_hosts` (conecte uma vez com `corerouter-cli --connect … --user …`
num terminal, que pergunta) ou ser dado com `--fingerprint`. O que o agente pode fazer é o que o
grupo do usuário permite: `list_commands` mostra `enabled: false` com o motivo.

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
| `run_task` / `task_run` | Inicia uma ferramenta em segundo plano (`tool.ping.start`, `tool.ping.mtu`…), junta eventos até terminar ou `wait_secs` (≤ 60), para se preciso; devolve `summary` + últimos 50 eventos (`docs/tools.md`) | read-only |
| `ui_screenshot` / `screenshot` | PNG da janela (só Remote com GUI) | read-only |

Erros de tool voltam como texto com `isError: true` ("unknown parameter 'adress'; did you mean
'address'?"), nunca como erro de protocolo — o agente lê e corrige.

Limites: linha de até 16 MiB, lote JSON-RPC de até 64 mensagens, `command_batch` até 256 passos.
Faltando (G0.7): resources, prompts, completions, progresso/cancelamento, `-32003` (ocupado).

## Histórico de revisão

- 2026-10-21 — versão inicial.
- 2026-10-22 — G0.3: token local, Remote TLS com usuário e senha.
- 2026-10-22 — tool `run_task` (G6.1).
