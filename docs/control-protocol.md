# Canal de controle

Uma requisição JSON por linha, sobre TCP puro **só em loopback** (`--control`, porta padrão
7979) ou sobre **TLS em qualquer endereço** (`--listen`, sugestão 8729). Toda requisição, exceto
`ping`, `server.info` e `auth.login`, leva um `token` (G0.3):

```
→ {"id": 1, "method": "auth.login", "params": {"user": "admin", "password": "…"}}
← {"id": 1, "ok": true, "result": {"token": "9f…", "user": "admin", "group": "full", "idle_timeout_secs": 1800}}
→ {"id": 2, "method": "engine.execute", "params": {"command": "interface.list"}, "token": "9f…"}
← {"id": 2, "ok": true, "result": [...]}
← {"id": 3, "ok": false, "error": "unknown parameter 'adress'; did you mean 'address'?"}
← {"id": 4, "ok": false, "error": "unauthorized: invalid or expired token; log in again"}
```

| Método | Params | Resultado |
|---|---|---|
| `ping` | — | `{pong: true}` (sem token) |
| `server.info` | — | `{name, version, backend, has_ui, auth: "required"}` (sem token) |
| `auth.login` | `{user, password}` | `{token, user, group, idle_timeout_secs}` (sem token) |
| `auth.logout` | — | `{}`: o token de sessão deixa de valer |
| `auth.whoami` | — | `{user, group, via}` |
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

Segurança e limites: o TCP puro faz bind só em loopback e confere o peer; no máximo 16 conexões
por endpoint; linha de até 16 MiB (resposta até 256 MiB no cliente); **qualquer linha que não
seja JSON fecha a conexão** (isso bloqueia um `fetch`/form HTTP de uma página web).

## Autenticação, usuários e TLS (G0.3)

**Usuários e grupos** (estilo RouterOS, comandos `user.*` no engine): `read` só consulta,
`write` consulta e muda a configuração, `full` também gerencia usuários. O grupo exigido por
comando: id começando com `user.` → `full`; ação com journal (e `config.mode.set`) → `write`;
o resto (consultas, `state.inspect`) → `read`. O engine confere a cada comando o grupo **atual**
do usuário (rebaixar, desativar ou remover vale na hora) e, em `engine.list`, marca o que o
grupo não pode com `enabled: false` e `disabledReason` (`needs group write; noc is in group
read`), o mesmo mecanismo do G1.16 que deixa os botões da GUI cinza.

| Comando | Params | Resultado |
|---|---|---|
| `user.list` | `{}` | `[{name, group, disabled, comment}]` (nunca o hash) |
| `user.active.list` | `{}` | `[{id, user, via, since, last_seen}]` |
| `user.add` | `{name, group, password, disabled?, comment?}` | `{name, group}` |
| `user.set` | `{name, password?, group?, disabled?, comment?}` | `{name, group, disabled}` |
| `user.remove` | `{name}` | `{}` |

Senhas: mínimo 8 caracteres, guardadas só como **Argon2id** (PHC, sal aleatório) no mesmo
arquivo da config (G0.6, `running.json` 0600), **fora das revisões**: `config.rollback` nunca
traz de volta uma conta removida ou uma senha antiga, e `config.diff`/`state.inspect` não as
mostram. O journal troca `password`/`token` por `***`; mensagens de erro nunca repetem a senha.
Mudanças de usuário valem na hora (sem candidate/commit), são recusadas em Safe Mode (ele não as
desfaria) e nunca deixam o roteador sem um usuário `full` ativo. Senha nova ou conta desativada
encerra as sessões daquela conta.

**Primeiro `admin`.** Sem nenhuma conta, o daemon cria `admin` (grupo `full`) com senha
aleatória de 20 caracteres (100 bits) e a imprime **uma vez** no stderr. Perdeu? Reinicie com
`corerouter-daemon --reset-admin-password …`: nova senha impressa, `admin` volta ativo e `full`,
e o daemon segue rodando.

**Login e tokens.** `auth.login` devolve um token de sessão (256 bits aleatórios; o servidor
guarda só o SHA-256, compara em tempo constante). Ele acaba com `auth.logout`, após 30 min sem
uso, 12 h após o login, ou quando a conta muda (senha, desativada, removida). Erros de
autenticação começam com `unauthorized:` (o cliente sabe que deve logar de novo). Login errado,
usuário inexistente ou desativado dão a **mesma** resposta, `invalid user or password`, no mesmo
tempo (um usuário inexistente gasta uma verificação Argon2 falsa). Contra força bruta, falhas
contam por endereço de origem e por nome de usuário (janela de 15 min): 3 falhas livres, depois
cada tentativa espera 250 ms dobrando até 8 s, e um endereço com 20 falhas é recusado até a
janela passar. Segredo nunca vai em URL: o token anda no corpo JSON.

**Token local (CLI e MCP na mesma máquina).** Quem serve uma porta de controle (daemon, GUI
com `--control`) grava ao iniciar um token aleatório em `control-<porta>.token`, legível só pelo
usuário do sistema que o rodou (diretório 0700, arquivo 0600), e o apaga ao encerrar. Diretório:
`$COREROUTER_RUNTIME_DIR`, senão `$XDG_RUNTIME_DIR/corerouter`, senão `~/.corerouter/run`
(Windows: `%LOCALAPPDATA%\corerouter\run`); `corerouter-daemon --token-file <caminho>` muda o
arquivo. `corerouter-cli --connect 127.0.0.1:<porta>` e o MCP leem esse arquivo e mandam o
token: o mesmo usuário do sistema entra sem senha (grupo `full`), **outro usuário da máquina
não consegue ler o arquivo e precisa logar** como qualquer um. O token local só vale no TCP de
loopback e no `--ws` de loopback, nunca nos endpoints TLS.

**TLS (`--listen`, `--ws-listen`).** `rustls` com o provedor `ring` (sem OpenSSL). Na primeira
vez o daemon gera um certificado autoassinado em `--config-dir` (`tls-cert.pem`, e
`tls-key.pem` com 0600) e loga a impressão digital SHA-256 (`TLS certificate fingerprint:
SHA256:AB:CD:…`) a cada início. Sem `--config-dir` o certificado é novo a cada início (aviso
no log). Handshake até 10 s. Qualquer endereço que não seja loopback é **sempre** TLS + login.

**Confiança no primeiro uso (clientes).** Sem CA para conferir, GUI nativa, CLI e MCP fixam o
certificado como o SSH: na primeira conexão mostram a impressão digital e pedem confirmação
(compare com a do log do daemon); a resposta fica em `known_hosts`
(`$COREROUTER_KNOWN_HOSTS`, senão `~/.config/corerouter/known_hosts`, `%APPDATA%` no
Windows; uma linha `host:porta SHA256:…`). Se o certificado mudar, a conexão é **recusada
antes de enviar qualquer coisa**, com as duas impressões na mensagem; apague a linha se a
mudança for legítima. As assinaturas do handshake continuam verificadas. Endereço no cliente:
`HOST:PORTA` (loopback: TCP puro) ou `tls://HOST:PORTA`; um host que não é loopback implica
`tls://`.

```sh
corerouter-daemon --config-dir /config --listen 0.0.0.0:8729         # ou [::]:8729
corerouter-cli --connect 10.0.0.1:8729 --user admin inspect          # pergunta a senha e o certificado
COREROUTER_PASSWORD=… corerouter-cli mcp --connect 10.0.0.1:8729 --user admin \
    --fingerprint SHA256:AB:…                                          # MCP: stdin é o protocolo
```

## Conexões e Safe Mode (G1.4)

Cada conexão TCP ou WebSocket é um cliente (`Caller`, ex. `tcp 127.0.0.1:50412`). O
`config.safe-mode.enter` pertence à conexão que o executou; quando ela fecha, o daemon desfaz
tudo o que mudou desde a entrada. Por isso `corerouter-cli --connect … run
config.safe-mode.enter` não serve para nada (a conexão fecha logo depois): use a GUI, o MCP
(conexão persistente) ou um cliente que fique conectado. `state.inspect` mostra
`safe_mode: {active, owner, yours, since, entry_revision, pending_revisions, timeout_secs,
expires_in, last}` — `yours` é relativo à conexão que pergunta. A GUI com `--control` repassa
cada cliente por uma conexão própria ao daemon, então o dono é esse cliente, não a janela.

## Descoberta (CRDP)

O anúncio CRDP leva também as portas TLS (`TLS_PORT` 14 = `--listen`, `WSS_PORT` 15 =
`--ws-listen`; `mgmt.tls`/`mgmt.wss` em `ip.neighbor.list`). A tela de conexão da GUI mostra um
vizinho de outra máquina como conectável (`tls://IP:porta`) quando ele anuncia porta TLS; sem
ela, segue cinza com o motivo.

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
| `--ws-listen <end:porta>` | o mesmo sobre TLS (`wss://`, e `https://` para `--web-root`) em qualquer endereço; aceita a página servida por ela mesma (`Origin` = `https://` + `Host`) |

**Origin.** O navegador deixa qualquer página abrir um WebSocket para `127.0.0.1`, então o
handshake é recusado com `403` quando o header `Origin` não está na lista. Padrão: só
`http://127.0.0.1:<porta>` e `http://localhost:<porta>`, a origem que serve a GUI com
`--web-root`. Comparação exata (esquema, host e porta); `null` (iframe sandbox, `file://`) é
recusado. Sem `Origin` não é página de navegador (todo navegador envia) e é aceito como um
cliente TCP. Recusas vão para o log (`ws: refused origin …`).

Cada mensagem leva o `token`, como no TCP (a GUI web faz `auth.login` a cada conexão e guarda a
senha só na memória da aba, nunca em `localStorage`).

**Limites**, como no TCP: `--ws` só peers loopback; no máximo 16 conexões WebSocket/HTTP simultâneas
(`503` acima disso); cabeçalho HTTP até 16 KiB em até 10 s; mensagem e frame até 16 MiB
(acima disso a conexão cai); texto que não é JSON ou mensagem binária fecha a conexão.

**Arquivos estáticos** (`--web-root`): só `GET`/`HEAD`; `/` → `index.html`; segmentos com
`..`, nome oculto (`.x`), `\`, `%`, `:` ou NUL são `404`; o caminho canônico precisa ficar dentro
da raiz (symlinks não escapam); arquivo até 64 MiB; MIME correto para `.wasm`/`.js`/`.html`;
`X-Content-Type-Options: nosniff`. Sem `--web-root`, HTTP comum recebe `404`.

Na GUI web: `?connect=ws://127.0.0.1:7980` abre a tela de conexão com esse daemon (pede login);
`?lab` roda o laboratório virtual dentro da página; sem parâmetro, a tela de conexão aponta para
`ws(s)://<host da página>/ws` (o daemon que serviu a página).

## Histórico de revisão

- 2026-10-21 — versão inicial.
- 2026-10-21 — G0.4: WebSocket (`--ws`, Origin, `--web-root`), repasse da GUI remota.
- 2026-10-22 — G1.4: conexão como dona do Safe Mode.
- 2026-10-22 — G0.3: usuários/grupos, `auth.*`, token local, TLS (`--listen`, `--ws-listen`),
  confiança no primeiro uso, portas TLS no CRDP.
