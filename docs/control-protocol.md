# Canal de controle

TCP **só em loopback** (`127.0.0.1`, porta padrão 7979), uma requisição JSON por linha:

```
→ {"id": 1, "method": "engine.execute", "params": {"command": "interface.list"}}
← {"id": 1, "ok": true, "result": [...]}
← {"id": 2, "ok": false, "error": "unknown parameter 'adress'; did you mean 'address'?"}
```

| Método | Params | Resultado |
|---|---|---|
| `ping` | — | `{pong: true}` |
| `server.info` | — | `{name, version, backend, has_ui}` |
| `engine.list` | — | registro de comandos |
| `engine.execute` | `{command, params?}` | resultado do comando |
| `engine.batch` | `{steps: [{command, params?}], atomic?: bool = true}` | `{results}` |
| `state.inspect` | `{path?}` | resumo ou subárvore |
| `ui.screenshot` | — | `{mimeType: "image/png", width, height, data: base64}` (só GUI) |

Servido por: GUI (`--control`), daemon e, com os mesmos nomes, pelo backend MCP headless
(`control::dispatch` sobre uma `Session`). Por isso as tools MCP são escritas uma vez.

Segurança e limites: bind só em loopback e checagem do peer; no máximo 16 conexões; linha de até
16 MiB (resposta até 256 MiB no cliente); **qualquer linha que não seja JSON fecha a conexão**
(isso bloqueia um `fetch`/form HTTP de uma página web). Autenticação/TLS para gerência remota é
G0.3.

## Histórico de revisão

- 2026-10-21 — versão inicial.
