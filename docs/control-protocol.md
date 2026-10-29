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
| `server.info` | — | `{name, version, commit, backend, has_ui, auth: "required"}` (sem token em loopback; da rede, sem login, só `{name, auth}`) |
| `auth.login` | `{user, password}` | `{token, user, group, idle_timeout_secs, no_password}` (sem token) |
| `auth.logout` | — | `{}`: o token de sessão deixa de valer |
| `auth.whoami` | — | `{user, group, via, no_password?}` (`no_password`: contas `full` sem senha, só para quem é `full`) |
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

Conexões ainda sem login (auditoria do controle, `control::conn`): no máximo 8 das 16 vagas, 4 por
origem de rede (endereço IPv4 ou /64 IPv6; loopback não tem limite por origem); 30 s ociosas e
caem, e nenhuma fica mais de 60 s sem login no total (como o `LoginGraceTime` do SSH: quem pinga
ou manda um byte a cada 29 s sem nunca logar também cai); o handshake TLS e o cabeçalho HTTP do WebSocket têm **prazo total** de 10 s (não por
`read`: quem manda um byte a cada 9 s também cai). Da rede, antes do login, a linha vai até
64 KiB; os `params` só viram JSON depois de conferido o token. Acima do limite: linha JSON no
TCP, `503` no WebSocket, nada no TLS. Toda conexão tem TCP keepalive (15 s + 3 × 5 s) e, no
Linux, `TCP_USER_TIMEOUT` de 30 s; escrita sem progresso por 30 s derruba a conexão. Depois do
login não há limite de ociosidade (GUI e MCP ficam horas parados): o keepalive acha o par morto.
O cliente (`dial`) resolve `localhost` como `127.0.0.1` e só manda o token local para
`127.0.0.1` (o único endereço em que o roteador escuta em claro), nunca para `[::1]`.

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
| `user.list` | `{}` | `[{name, group, disabled, no_password, comment}]` (nunca o hash) |
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

**Primeiro `admin`, sem senha (G0.3b, como o RouterOS 7).** Sem nenhuma conta, o daemon cria
`admin` (grupo `full`) **sem senha** e loga isso; nenhuma senha é impressa. "Sem senha" é um
estado explícito (`password_hash: null` no arquivo, `no_password: true` no `user.list`), nunca o
hash de uma string vazia. Regras enquanto uma conta `full` ativa estiver sem senha:

- O login dela com senha **vazia** só vale de **loopback** (`127.0.0.1`/`::1`, inclusive o TLS
  e o `--ws` em loopback); de qualquer outro endereço é recusado.
- **Todo** login vindo da rede (endereço não-loopback, de qualquer conta) é recusado com
  `login from the network is refused while an account of group full has no password: set the
  admin password first …`, antes de conferir senha (não conta como falha). `--listen` /
  `--ws-listen` fora do loopback sobem assim mesmo, com um aviso no log.
- O token local (CLI/MCP na mesma máquina) segue igual.
- Logo após entrar, a GUI (nativa e web) abre **"Set a password for admin"** com **"Not now"**,
  e a barra superior mostra `admin has no password — set one` (clicável) até haver senha; o
  terminal (`corerouter-cli shell`, janela New Terminal) pergunta `New password for admin:` sem
  eco e fora do histórico (linha vazia = agora não). Definir é o `user.set {name, password}`
  normal, pelo engine; quem define continua logado (as outras sessões da conta acabam).

Nenhum comando tira a senha de uma conta. Perdeu a senha? Reinicie com
`corerouter-daemon --reset-admin-password …`: `admin` volta ativo, `full` e **sem senha** (as
sessões dele acabam, as outras contas não mudam), a rede fica fechada de novo até definir uma, e
o daemon segue rodando.

**Login e tokens.** `auth.login` devolve um token de sessão (256 bits aleatórios; o servidor
guarda só o SHA-256, compara em tempo constante). Ele acaba com `auth.logout`, após 30 min sem
uso, 12 h após o login, ou quando a conta muda (senha, desativada, removida). Erros de
autenticação começam com `unauthorized:` (o cliente sabe que deve logar de novo). Login errado,
usuário inexistente ou desativado dão a **mesma** resposta, `invalid user or password`, no mesmo
tempo (um usuário inexistente gasta uma verificação Argon2 falsa). Contra força bruta, falhas
contam por origem (endereço IPv4 ou /64 IPv6) e por nome de usuário (janela de 15 min): 3 falhas
livres, depois cada tentativa espera 250 ms dobrando até 8 s, e uma origem com 20 falhas é
recusada até a janela passar. A tentativa conta ao começar e é perdoada se der certo, então
tentativas em paralelo não escapam do limite; no máximo 2 verificações Argon2 (19 MiB cada)
rodam ao mesmo tempo (`too many logins at once` após 5 s de espera). Cada usuário tem no máximo
16 sessões: o 17º login derruba o mais antigo **dele**, nunca o de outra conta. Segredo nunca
vai em URL: o token anda no corpo JSON.

**Token local (CLI e MCP na mesma máquina).** Quem serve uma porta de controle (daemon, GUI
com `--control`) grava ao iniciar um token aleatório em `control-<porta>.token`, legível só pelo
usuário do sistema que o rodou (diretório 0700, arquivo 0600), e o apaga ao encerrar. Diretório:
`$COREROUTER_RUNTIME_DIR`, senão `$XDG_RUNTIME_DIR/corerouter`, senão `~/.corerouter/run`
(Windows: `%LOCALAPPDATA%\corerouter\run`); `corerouter-daemon --token-file <caminho>` muda o
arquivo. `corerouter-cli --connect 127.0.0.1:<porta>` e o MCP leem esse arquivo e mandam o
token: o mesmo usuário do sistema entra sem senha (grupo `full`), **outro usuário da máquina
não consegue ler o arquivo e precisa logar** como qualquer um. O token local só vale no TCP de
loopback e no `--ws` de loopback, nunca nos endpoints TLS.

**Tela de conexão da GUI (G0.3c).** Login vem preenchido com `admin`. Em `127.0.0.1`/`::1` a
GUI nativa primeiro pergunta `server.info` sem credencial: sem o campo `auth` é um roteador
anterior ao G0.3 (sem usuários nem login), e a tela diz "This router runs an old version
(without login). Update and restart corerouter-daemon." com o botão **Connect anyway** (só em
loopback: lá esse daemon já aceita qualquer processo da máquina, então conectar não abre nada
novo; a barra superior mostra `old router: no login` e o que ele não tem fica cinza, como no
G1.16). Num roteador atual, tenta o token local; se o arquivo não for legível (daemon de outro
usuário do sistema, p. ex. root com `sudo`) ou o roteador o recusar, faz `auth.login` com Login
e Password (senha vazia vale em loopback enquanto o `admin` não tiver uma, G0.3b). Só se isso
também falhar aparece um erro, curto ("Invalid user or password", "Set the admin password
first…", "Too many failed logins…", "Nothing answers at that address…"), com o texto técnico (o
caminho do token, a resposta do roteador) em **Details** e no tooltip. Fora do loopback é TLS +
Login/Password como antes. Na GUI web o motivo da desconexão usa as mesmas frases (`unknown
method 'auth.login'` vira a de roteador antigo; a web não oferece "Connect anyway").

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
tudo o que mudou desde a entrada. Isso vale também quando o caminho morre em silêncio (rota,
endereço ou firewall cortam a gerência: nenhum FIN ou RST chega): o keepalive TCP derruba a
conexão em ~30 s e o desfazer roda. Por isso `corerouter-cli --connect … run
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
(`503` acima disso); cabeçalho HTTP até 16 KiB em até 10 s no total; mensagem e frame até 16 MiB
(64 KiB da rede antes do login; acima disso a conexão cai); arquivos estáticos vão em fluxo,
sem carregar o arquivo inteiro na memória; texto que não é JSON ou mensagem binária fecha a conexão.

**Arquivos estáticos** (`--web-root`): só `GET`/`HEAD`; `/` → `index.html`; segmentos com
`..`, nome oculto (`.x`), `\`, `%`, `:` ou NUL são `404`; o caminho canônico precisa ficar dentro
da raiz (symlinks não escapam); arquivo até 64 MiB; MIME correto para `.wasm`/`.js`/`.html`;
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (a GUI do roteador nunca dentro de
outra página) e `Referrer-Policy: no-referrer`. Um `<arquivo>.gz` ao lado do arquivo (feito no
build, como o `gzip_static` do nginx) vai com `Content-Encoding: gzip` para quem manda
`Accept-Encoding: gzip` (RFC 9110 §12.5.3; `q=0` recusa); se só o `.gz` existe (a imagem guarda
assim o `.wasm` e o JS), quem não aceita gzip recebe `406`. Sem `--web-root`, HTTP comum recebe `404`.

**Pela config: `ip.service.www-ssl.*` / `ip.service.www.*` (G1.6o).** O mesmo endpoint TLS, mas
ligado, movido e desligado por comando, sem reiniciar (o `/ip service` do RouterOS; detalhes em
`docs/os-image.md`, "Acesso web"). O daemon segue a config em execução: `--web-files <dist>` diz
onde está a GUI, `--web-factory-on` liga o `www-ssl` numa config nova. `available_from` derruba,
antes do TLS e sem resposta, quem não está na lista (`Endpoint::with_allow`); `www` é HTTP só
para `301` → `https://<host>/` (senha nunca em texto claro).

Na GUI web: `?connect=ws://127.0.0.1:7980` abre a tela de conexão com esse daemon (pede login);
`?lab` roda o laboratório virtual dentro da página; sem parâmetro, a tela de conexão aponta para
`ws(s)://<host da página>/ws` (o daemon que serviu a página).

## Histórico de revisão

- 2026-10-21 — versão inicial.
- 2026-10-21 — G0.4: WebSocket (`--ws`, Origin, `--web-root`), repasse da GUI remota.
- 2026-10-22 — G1.4: conexão como dona do Safe Mode.
- 2026-10-22 — G0.3: usuários/grupos, `auth.*`, token local, TLS (`--listen`, `--ws-listen`),
  confiança no primeiro uso, portas TLS no CRDP.
- 2026-10-22 — G0.3b: primeiro `admin` sem senha, login vazio só em loopback, rede recusada até
  definir a senha, `no_password` em `auth.login`/`auth.whoami`/`user.list`.
- 2026-10-22 — G0.3c: tela de conexão (token local → Login/Password em loopback, `admin` por
  padrão, roteador anterior ao G0.3 pelo `server.info` sem `auth`).
