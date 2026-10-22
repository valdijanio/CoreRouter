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

Com `corerouter-gui --connect HOST:PORT --control P`, a porta `P` da GUI responde `ping` e
`ui.screenshot` e **repassa** todo o resto ao daemon (uma conexão própria por cliente, via
`Host::forward`). `server.info` responde mesmo com o daemon fora (`has_ui: true`,
`router`, `router_error`), para que MCP e `corerouter-cli screenshot` continuem enxergando a janela.

Segurança e limites: bind só em loopback e checagem do peer; no máximo 16 conexões; linha de até
16 MiB (resposta até 256 MiB no cliente); **qualquer linha que não seja JSON fecha a conexão**
(isso bloqueia um `fetch`/form HTTP de uma página web). Autenticação/TLS para gerência remota é
G0.3: **até lá, TCP e WebSocket são só loopback e sem autenticação** — qualquer processo local
pode comandar o roteador (o daemon diz isso no log de inicialização). Para gerenciar de outra
máquina hoje, use um túnel (`ssh -L 7979:127.0.0.1:7979 roteador`).

## Conexões e Safe Mode (G1.4)

Cada conexão TCP ou WebSocket é um cliente (`Caller`, ex. `tcp 127.0.0.1:50412`). O
`config.safe-mode.enter` pertence à conexão que o executou; quando ela fecha, o daemon desfaz
tudo o que mudou desde a entrada. Por isso `corerouter-cli --connect … run
config.safe-mode.enter` não serve para nada (a conexão fecha logo depois): use a GUI, o MCP
(conexão persistente) ou um cliente que fique conectado. `state.inspect` mostra
`safe_mode: {active, owner, yours, since, entry_revision, pending_revisions, timeout_secs,
expires_in, last}` — `yours` é relativo à conexão que pergunta. A GUI com `--control` repassa
cada cliente por uma conexão própria ao daemon, então o dono é esse cliente, não a janela.

## WebSocket (GUI no navegador)

`corerouter-daemon --ws <porta>` serve os **mesmos métodos** por WebSocket em
`ws://127.0.0.1:<porta>/ws` (`control::ws`, `tungstenite` síncrono, uma thread por conexão,
sem runtime async). Uma requisição por mensagem de texto, mesmo JSON do TCP; a resposta vem
como mensagem de texto com o mesmo `id`.

| Flag | Efeito |
|---|---|
| `--ws <porta>` | liga o endpoint em `127.0.0.1:<porta>` |
| `--ws-origin <origem>` | permite também páginas de `<origem>` (repetível), ex. `http://127.0.0.1:8080` do `trunk serve` |
| `--web-root <dist>` | serve a GUI web compilada (`trunk build`) por HTTP `GET` na mesma porta (modelo WebFig) |

**Origin.** O navegador deixa qualquer página abrir um WebSocket para `127.0.0.1`, então o
handshake é recusado com `403` quando o header `Origin` não está na lista. Padrão: só
`http://127.0.0.1:<porta>` e `http://localhost:<porta>`, a origem que serve a GUI com
`--web-root`. Comparação exata (esquema, host e porta); `null` (iframe sandbox, `file://`) é
recusado. Sem `Origin` não é página de navegador (todo navegador envia) e é aceito como um
cliente TCP. Recusas vão para o log (`ws: refused origin …`).

**Limites**, como no TCP: só peers loopback; no máximo 16 conexões WebSocket/HTTP simultâneas
(`503` acima disso); cabeçalho HTTP até 16 KiB em até 10 s; mensagem e frame até 16 MiB
(acima disso a conexão cai); texto que não é JSON ou mensagem binária fecha a conexão.

**Arquivos estáticos** (`--web-root`): só `GET`/`HEAD`; `/` → `index.html`; segmentos com
`..`, nome oculto (`.x`), `\`, `%`, `:` ou NUL são `404`; o caminho canônico precisa ficar dentro
da raiz (symlinks não escapam); arquivo até 64 MiB; MIME correto para `.wasm`/`.js`/`.html`;
`X-Content-Type-Options: nosniff`. Sem `--web-root`, HTTP comum recebe `404`.

Na GUI web: `?connect=ws://127.0.0.1:7980` usa esse daemon; `?lab` roda o laboratório virtual
dentro da página; sem parâmetro, conecta em `ws(s)://<host da página>/ws` (o daemon que serviu
a página).

## Histórico de revisão

- 2026-10-21 — versão inicial.
- 2026-10-21 — G0.4: WebSocket (`--ws`, Origin, `--web-root`), repasse da GUI remota.
- 2026-10-22 — G1.4: conexão como dona do Safe Mode.
