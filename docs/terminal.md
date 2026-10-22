# CoreRouter — terminal (G0.8)

Terminal com a sintaxe da CLI do MikroTik RouterOS, **gerado do registro de comandos**. O mesmo
terminal (crate `corerouter-shell`, L4) roda em três lugares:

| Onde | Como abrir | Observações |
|---|---|---|
| GUI | menu lateral › **New Terminal** (várias janelas ao mesmo tempo) | usa o backend da GUI (lab local ou `--connect`, G0.4); maximiza (G1.12), segue o tema (G1.11) |
| CLI | `corerouter-cli shell [--connect HOST:PORT] [--user NOME]` | editor `rustyline`, histórico em `~/.local/share/corerouter/shell_history`; sem `--connect`, lab descartável em processo (como `run`) |
| SSH | `corerouter-daemon --ssh <porta>` | **pendente do G0.3** (autenticação); veja "SSH" abaixo |

Filosofia Talos: o terminal **nunca** dá acesso ao bash do sistema. Ele só conhece os comandos do
registro e alguns verbos próprios (`print`, `export`, `import`, `quit`).

## O shell nunca contorna o engine

O crate `shell` é puro (sem I/O, compila em wasm32). Uma linha vira um `Job` que pede ao front
end chamadas do canal de controle — `engine.execute`, `engine.batch`, `engine.list`,
`state.inspect` — e, para `file=`, leitura/escrita de arquivo do lado do cliente. O front end
manda essas chamadas pelo caminho que já usa (TCP/WebSocket, `Local` da GUI) e devolve as
respostas a `Shell::step`. Por isso valem igual a qualquer cliente: validação do `params`,
permissões (G0.3), Safe Mode (G1.4), journal, modo transacional. Os erros do engine aparecem como
vêm (inclusive o "did you mean").

## Mapeamento automático

Nenhuma tabela de sintaxe por comando: a árvore de menus é montada do `engine.list` em tempo de
execução. Comando novo no engine aparece no terminal sozinho (há um teste que percorre
`cmd::all()` e exige que todo id seja alcançável e que as chaves lidas batam com
`cmd::doc_keys`).

| Engine | Terminal |
|---|---|
| id `ip.address.add` | menu `/ip address`, comando `add` |
| `interface.bridge.port.list` | `/interface bridge port print` |
| verbo `list` | `print` (`list` também é aceito) |
| verbo `get` num menu sem `list` | `print` (menus de um objeto só: `/ip neighbor discovery print`, `/system identity print`) |
| demais verbos (`add`, `set`, `remove`, `enter`, `commit`, `rollback`, …) | o mesmo nome |
| chave `vlan_id` | `vlan-id=` |
| tipo `bool` no doc | `yes`/`no` (ou `true`/`false`) |
| tipo `u32`/`int` | número (`u32 \| asdot string` aceita texto também) |
| tipo `[string]` | lista `a,b,c` (vira array JSON; `[string] \| string` vai como texto) |
| tipo `a\|b\|c` | valores oferecidos pelo Tab |

### Metadados do registro para o terminal

Três campos opcionais do `CommandSpec`, com construtores `const` (`cmd!(…).alias("ping")
.positional("address").task()`), saem no `engine.list` como `alias`, `positional` e `task`:

| Metadado | Efeito no terminal |
|---|---|
| `alias("ping")` | atalho válido em qualquer menu e na raiz: `ping …` e `/ping …` = `/tool ping start …`; aparece no Tab e no `?` da raiz. Nunca esconde um menu da raiz (teste no engine) |
| `positional("address")` | a primeira palavra sem `=` vai para esse parâmetro: `ping 8.8.8.8 count=3` |
| `task()` | o comando inicia uma tarefa: o terminal lê o `id` do resultado e acompanha com `tool.task.poll {id, after_seq}` (o `after_seq` é o `next_seq` da resposta anterior), imprimindo cada evento numa linha assim que chega (cabeçalho uma vez; colunas na ordem de um `columns` opcional no resultado ou na resposta, senão `seq` e as chaves do primeiro evento; `status` diferente de `ok`/vazio em amarelo), até `done`; então mostra `reason` e o `summary`. Entre polls sem novidade espera 250 ms (`Request::Sleep`). **Ctrl+C** chama `tool.task.stop {id}` uma vez e continua até o resumo |

O `tool.ping.start` (sessão Tools › Ping, ainda fora da main) liga-se a isso sozinho quando entrar
com esses metadados; os testes usam um roteador simulado com o mesmo contrato
(`crates/shell/tests/tasks.rs`, e um teste headless da janela da GUI).

### Custo em requisições

O canal de controle paga latência por requisição, então o terminal pede pouco: conectar = 4
(`server.info`, `engine.list`, `state.inspect` e um `engine.batch` não atômico com todas as
leituras que o Tab usa); `print` e consultas = 1; ação = 3 (o comando, `state.inspect` para o
prompt e o mesmo `engine.batch` de leituras). O `engine.list` só é pedido de novo quando o roteador
responde "unknown command" (daemon trocado ou atualizado).

Verbos do RouterOS **sem** comando equivalente no engine não são improvisados: `find`/`[find …]`
(substituição de comando), `enable`/`disable` (use `set … disabled=yes|no`), `comment` (use
`set … comment=…`), `edit`, `move`, `reset`, `unset`, `monitor`, `/system reboot`,
`:put`/`:foreach` (scripting). Eles respondem "bad command name" com sugestão. Viram comandos
quando o engine os ganhar.

## Sintaxe

```text
[admin@CoreRouter] > /ip address add address=10.0.0.1/24 interface=ether1 comment="uplink A"
[admin@CoreRouter] > /ip address                  # entra no menu
[admin@CoreRouter] /ip/address> print where interface=ether1
[admin@CoreRouter] /ip/address> set 0 comment=novo          # número da última listagem
[admin@CoreRouter] /ip/address> remove *1                   # id interno
[admin@CoreRouter] /ip/address> ..                          # sobe; "/" vai à raiz
[admin@CoreRouter] /ip> addr pr                             # abreviação sem ambiguidade
[admin@CoreRouter] > /ip/route/print detail                 # caminho com "/" (RouterOS v7)
[admin@CoreRouter] > /system identity set name=edge-1; /system identity print
```

- **Caminho**: `/` no início começa da raiz; sem ele, relativo ao menu atual. Só caminho = entra no
  menu. `..` sobe.
- **Abreviação**: menus, comandos, parâmetros e propriedades aceitam qualquer prefixo sem
  ambiguidade; nome exato sempre ganha (o Tab do RouterOS também casa "letras em ordem", `mt` →
  `monitor-traffic`; aqui ainda não). Ambíguo: "ambiguous command name 'a': add, address".
  Desconhecido: "bad command name 'adress'; did you mean 'address'? (column 5)".
- **Valores**: `chave=valor`; aspas para espaços (`comment="POP 2"`), escapes `\"`, `\\`, `\n`,
  `\t`. `;` separa comandos numa linha (para no primeiro erro). `#` no início é comentário.
- **Itens** (`set`, `remove`, … em menus com `print`): a primeira palavra sem `=` pode ser
  - números da **última `print` daquele menu** (`0`, `0,2`; a numeração segue o filtro `where`, como
    no RouterOS): o terminal copia da linha as chaves obrigatórias do comando (`id`, `name`,
    `bridge`+`interface`…). Vários itens viram um `engine.batch` atômico;
  - ids `*1`, `*1,*2` quando o comando tem `id`;
  - um nome (`/interface set ether1 mtu=1400`).
  Palavras sem `=` restantes preenchem as chaves obrigatórias em ordem (`/config rollback 3`).
- **`?`** no fim da linha (ou as teclas `?` e F1 — a de ajuda do RouterOS v7 — na GUI e na CLI
  interativa, que mostram na hora e mantêm a linha) mostra a ajuda: submenus e comandos de um menu; ou label, parâmetros (obrigatório/
  opcional, tipo do doc), motivo de indisponibilidade e retorno de um comando.
- **Prompt** (RouterOS v7): `[usuário@identity] /ip/address>`; enquanto esta conexão segura o Safe
  Mode, `<SAFE>` toma o lugar do `>`: `[admin@CoreRouter] /ip/address<SAFE>`.
- `/cmd` ou `.. cmd` roda um comando em outro nível sem mudar o menu atual.

### print

```text
print [detail] [as-json] [count-only] [show-ids] [proplist=a,b] [chave=valor…] [where <cond>]
cond := termo (and|or termo)*      termo := [!]prop[(=|!=|~|<|>|<=|>=)valor]
```

- Tabela numerada com legenda e coluna de flags. Flags: campo `flags` com legenda no próprio doc
  (`flags (X disabled, A active, …)`, como em `ip.route.list`); sem ele, os booleanos
  convencionais `disabled`→X, `invalid`→I, `dynamic`→D, `running`→R, `active`→A. Comentário vira
  linha `;;; texto` acima do item; item desativado em cinza.
- Colunas: campos do doc de resultado, na ordem do doc, sem `id`, `comment`, flags e colunas
  vazias. `proplist=` escolhe; `show-ids` troca o número pelo `*id`.
- `detail`: `chave=valor` por item; `as-json`: JSON das linhas (após `where`/`proplist`);
  `count-only`: quantas.
- `chave=valor` antes de `where` são parâmetros do próprio `list` (`print interface=ether1`).
- `where`: `~` é "contém" (no RouterOS é regex; aqui não há motor de regex). `and` liga mais forte
  que `or`. Booleanos: `where disabled`, `where !disabled`, `disabled=yes`. Números comparam como
  números.
- Menus de um objeto (`get`) imprimem `chave: valor` alinhado.

### Teclas

| Tecla | GUI | CLI |
|---|---|---|
| Enter | executa | executa |
| ↑ / ↓ | histórico da janela | histórico persistente (sem linhas com `password`/`secret`/`token`/`psk`) |
| Tab | completa; vários candidatos: prefixo comum + lista clicável | completa; lista |
| `?` / F1 | ajuda na hora, mantém a linha | idem |
| Ctrl+X | Safe Mode: entra; de novo, sai **mantendo** as mudanças (RouterOS) | idem |
| `/quit` | fecha a janela | sai; com Safe Mode desta conexão, **mantém** as mudanças (`exit`) antes |
| Ctrl+D (linha vazia) | — | sai **desfazendo** o Safe Mode (`cancel`), como no RouterOS |
| Ctrl+C | durante uma tarefa: para (`tool.task.stop`) | limpa a linha; durante uma tarefa: para |
| Esc | esconde as sugestões | — |
| botão direito na saída | Copy All, Clear | — |

O Tab completa menus e comandos, nomes de parâmetro (`interface=`), opções do `print`,
propriedades do `where`, e valores: enumerações do doc, `yes`/`no`, nomes de interface (chaves
`interface`, `interfaces`, `parent`, `bridge` e tipos que citam `interface`), valores da própria
listagem do menu (nomes, `*ids`) e o mesmo campo em outras listagens (`routing-table=`). Listas
completam depois da última vírgula.

### Cores

Menus azul, comandos ciano, chaves verde, itens magenta, flags amarelo, erros vermelho,
comentários cinza itálico, `<SAFE>` branco sobre vermelho. ANSI na CLI/SSH, cores do tema na GUI.

## /export e /import

`/export` (ou `export` em qualquer menu, só aquele ramo; `file=nome` grava no computador do
cliente) gera um script que recria a configuração inteira a partir do running, também derivado do
registro:

- para cada menu com `print` sem parâmetro obrigatório: cada linha vira o `add` do menu — ou o
  `add` do submenu do seu `type` (`/interface` tipo `vlan` → `/interface vlan add`) — com as chaves
  que esse `add` declara; o que o `add` não aceita mas o `set` do menu aceita vem num `set` em
  seguida (`/interface set name=vlan30 disabled=yes`). Sem `add` (portas físicas, instâncias BGP):
  `set`. Linhas dinâmicas (flag D) e links que o roteador não gerencia (`managed=no`, G1.18) ficam
  de fora. Menus de um objeto (`get`): um `set`;
- **ordem segura**: cada linha vem depois das que criam os nomes que ela cita (bridge antes da VLAN
  sobre ela, VLAN antes da VLAN empilhada, VRF antes dos endereços e rotas da sua tabela);
- **determinístico**: sem data/hora, ordem estável (o mesmo running dá o mesmo texto);
- **segredos nunca em texto puro**: campo com nome de segredo (`password`, `secret`, `psk`,
  `token`, `private`) não sai; uma linha que precisaria dele vira comentário
  `# add name=x: password is not exported` (o engine não devolve senhas). Quando o G0.3 entrar,
  usuários seguem essa regra até existir um hash exportável.

`/import file=nome` lê o arquivo do lado do cliente e **colar várias linhas** no terminal faz o
mesmo: o script inteiro é traduzido antes (erro de sintaxe → "line N: …", nada aplicado) e vai
num único `engine.batch` atômico (`atomic: true`): ou tudo entra numa revisão, ou nada. Números de
item não valem em script (use nomes ou `*ids`); `print`/`export` também não. Linhas terminadas em
`\` continuam na seguinte. Limites: 1 MiB de script; o engine aceita até 256 passos por batch
(`MAX_BATCH`) — configurações maiores precisam ser importadas em partes por enquanto.

Teste de ida e volta: config com bridge, portas, VLAN sobre bridge e sobre VLAN, loopback, VRF com
membros, endereços (um desativado, comentários com aspas), rotas (VRF, distance, desativada), BGP,
descoberta e identity → export → import num lab novo → export igual, running igual.

A GUI não lê nem grava arquivos (roda também no navegador): lá, cole o script; o `export` aparece
na janela e pode ser copiado (botão direito › Copy All).

## Safe Mode (Ctrl+X)

Ctrl+X manda `config.safe-mode.enter`; com Safe Mode desta conexão, `config.safe-mode.exit`
(mantém). "[Safe Mode taken]" / "[Safe Mode released]". Se outro cliente segura, o engine diz quem
e desde quando. Como no RouterOS: `/quit` mantém, Ctrl+D desfaz, e a conexão cair (rede, SSH) desfaz
pela regra do G1.4. Na GUI o
terminal compartilha a conexão da janela: Safe Mode do terminal e o botão da barra são o mesmo.

## SSH

Pendente do G0.3 (autenticação/TLS em outra sessão). Plano: `corerouter-daemon --ssh <porta>`
(desligado por padrão) com `russh` (sem `unsafe` nosso), autenticando com os usuários do G0.3 e
entregando **este mesmo shell** (ANSI, mesmo completar via eventos de tecla); nenhum canal
`exec`/`subsystem`/encaminhamento, nunca bash. Vira um segundo PR.

## Conferido com a documentação da MikroTik

Comparado com a página "Command Line Interface" e a seção Safe Mode de "Configuration Management"
em help.mikrotik.com (comportamento reproduzido, texto próprio): prompt v7 com `/` e `<SAFE>` no
lugar do `>`; `..`, `/`, `/cmd`; abreviação por prefixo; números da última `print` por menu e lista
`0,1,2`; nomes no lugar de números; Tab (um candidato completa com espaço, vários completam o
prefixo comum e listam); F1/`?`; Ctrl+X liga/desliga mantendo; Ctrl+D desfaz, `/quit` não;
legenda `Flags:` e coluna de flags. Diferenças conscientes: `where` com `~` = contém (sem regex);
sem `from`, `follow`, `interval`, `file` no `print`; sem busca Ctrl+R de menus; sem o "hijack"
interativo do Safe Mode (o engine diz quem segura; `force=yes` em `exit`/`cancel` libera ou desfaz).

## Primeiro login sem senha (G0.3b)

Ao conectar, o terminal pede `auth.whoami`. Se o roteador listar uma conta `full` sem senha
(`no_password`, o `admin` de um roteador novo), ele avisa e pergunta `New password for admin:` e
`Repeat new password:`, como o RouterOS 7. Essas linhas não aparecem (a CLI lê sem eco, a janela
New Terminal mascara) e não entram no histórico; linha vazia é "agora não". A senha vai pelo
`user.set` normal; erro do engine (curta demais) pergunta de novo. Com a entrada vinda de um
script (`echo … | corerouter-cli shell`) a pergunta é pulada.

## Histórico de revisão

- 2026-10-22 — criado (G0.8: terminal na GUI e na CLI, export/import; SSH pendente do G0.3).
- 2026-10-22 — atalhos (`alias`), parâmetro posicional e acompanhamento de tarefas ao vivo a partir de metadados do registro; custo em requisições reduzido.
- 2026-10-22 — G0.3b: pergunta da senha no primeiro login.
