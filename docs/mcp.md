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
num terminal, que pergunta) ou ser dado com `--fingerprint`. Certificado que mudou (roteador
reinstalado) é recusado com a mensagem e as duas impressões; confira e rode com
`--accept-new-cert` (ou `--fingerprint <a nova>`), que troca a linha no `known_hosts` (G0.3d). O que o agente pode fazer é o que o
grupo do usuário permite: `list_commands` mostra `enabled: false` com o motivo.

**Segredos (G4.3n).** O agente nunca lê um segredo: toda resposta de tool e de resource passa
por `auth::mask_secrets` (`password`, `secret`, `token`… viram `***`), mesmo quando o comando os
devolveria ao token local (grupo `full`), como `ppp.secret.list show_sensitive=yes`. O agente
pode importar secrets (`ppp.secret.import`); o relatório não traz senhas.

**Reconexão (audit-e2e).** O MCP vive mais que o processo do roteador: se o daemon reiniciou (ou a
sessão de login expirou), a próxima chamada reconecta sozinha — relê o token local, loga de novo
com `--user`, e no TLS só aceita o mesmo certificado da primeira conexão. Pedido que chegou ao
roteador mas cuja resposta se perdeu não é reenviado: o erro diz "may or may not have run" e o
agente confere o estado antes de repetir.

```sh
cargo install --path apps/corerouter-cli --locked
claude mcp add corerouter -- corerouter-cli mcp
```

## Tools

| Tool (aliases) | Faz | Annotations |
|---|---|---|
| `list_commands` / `command_list` | Registro inteiro (id, `params`, enabled + motivo); `prefix` filtra | read-only |
| `run_command` / `command_run` | `{command, params}` → `Session::execute` | destrutiva |
| `command_batch` | Até 32 768 passos, `"$N.chave"` referencia resultados; `atomic` (padrão true) = um commit | destrutiva |
| `inspect_state` / `state_inspect` | Resumo, ou uma subárvore por `path` (`interfaces`, `routing.bgp`, `running.ip`, `journal`) | read-only |
| `run_task` / `task_run` | Inicia uma ferramenta em segundo plano (`tool.ping.start`, `tool.ping.mtu`…), junta eventos até terminar ou `wait_secs` (≤ 60), para se preciso; devolve `summary` + últimos 50 eventos (`docs/tools.md`). Só comandos `tool.*` (outro id é recusado antes de rodar) | read-only |
| `ui_screenshot` / `screenshot` | PNG da janela (só Remote com GUI) | read-only |

Erros de tool voltam como texto com `isError: true` ("unknown parameter 'adress'; did you mean
'address'?"), nunca como erro de protocolo — o agente lê e corrige.

Limites: linha de até 16 MiB, `command_batch` até 32 768 passos (`engine::session::MAX_BATCH`).

Lote JSON-RPC (um array na linha) é recusado (G0.5c): a revisão MCP 2025-06-18, a única que o
servidor negocia, removeu o batching. A resposta é **um** objeto `-32600` com `id: null` e nenhum
item do array roda (nada aplica pela metade). Para várias mudanças de uma vez, use a tool
`command_batch`, que é atômica.

## Resources (G0.7)

Leituras que o cliente anexa como contexto sem chamar tool (no Claude Code: `@corerouter:…`).
Todas são `application/json` e passam pelos mesmos métodos do canal de controle das tools, com as
permissões do usuário conectado.

| URI | Conteúdo |
|---|---|
| `corerouter://state` | Resumo: identidade, backend, modo, revisão, mudanças pendentes, Safe Mode, contagens |
| `corerouter://commands` | Registro inteiro (o mesmo de `list_commands`) |
| `corerouter://diff` | `config.diff`: o que o `config.commit` aplicaria |
| `corerouter://command/{id}` (template) | Um comando: `params`, resultado, enabled + motivo |
| `corerouter://state/{path}` (template) | Uma subárvore: `interfaces`, `ip.addresses`, `running.ip`, `journal` |

Recurso inexistente → erro `-32002` ("Resource not found", MCP 2025-06-18) com `data: {uri}`; um
id de comando errado sugere os mais próximos. URI acima de 512 bytes → `-32602`. Sem
`subscribe` nem `listChanged` por enquanto (G0.7b).

## Prompts (G0.7)

Fluxos prontos (no Claude Code viram `/mcp__corerouter__<nome>`). Só montam a mensagem que guia o
agente; nada roda até o agente chamar as tools.

| Prompt | Argumentos | Fluxo |
|---|---|---|
| `configure_address` | `interface`, `address`, `gateway?`, `dst_address?` | Confere interface e sobreposição, modo transacional, `command_batch` atômico (endereço + rota), mostra o diff, sugere Safe Mode se for a interface de gerência, commit só com o "sim" |
| `review_and_commit` | `comment?` | Embute `corerouter://state` e `corerouter://diff`, explica cada mudança e o risco (lockout, sobreposição, regra inútil), commit só com o "sim" |
| `diagnose_connectivity` | `target` | Rota, interface, endereço, `run_task` ping e MTR; não muda a configuração |

Nome ou argumento inválido (faltando, desconhecido, não-string, mais de 128 bytes, aspas ou
quebra de linha) → `-32602` com a mensagem dizendo o que corrigir.

## Completions (G0.7)

`completion/complete` sugere ids de comando (`corerouter://command/{id}`), caminhos de estado
(`corerouter://state/{path}`) e nomes de interface (argumento `interface` de
`configure_address`), até 100 valores com `total` e `hasMore`.

Faltando (G0.7b): progresso e cancelamento (`notifications/progress`, `notifications/cancelled`),
erro `-32003` (motor ocupado), `resources/subscribe` e `list_changed`.

## Histórico de revisão

- 2026-10-21 — versão inicial.
- 2026-10-22 — G0.3: token local, Remote TLS com usuário e senha.
- 2026-10-22 — tool `run_task` (G6.1).
