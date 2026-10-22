# VectorCraft: arquitetura, MCP e agentes

Oct 21, 2026 · @Sundown

## Resumo

O VectorCraft é um editor de ilustração vetorial (alvo: paridade com o Adobe Illustrator) escrito 100% em Rust, que roda nativo em macOS, Windows e Linux e na web via WASM. Ele usa exatamente a mesma estrutura do WordCraft e dos outros apps *craft* da ArtCraft: um motor de comandos em camadas, uma UI fina em egui e um servidor MCP que expõe o app inteiro para agentes de IA. O código também é escrito majoritariamente por agentes (Claude Code), guiados por arquivos de instrução e por portões de qualidade automáticos.

As cinco ideias que valem copiar:

1. **Tudo é um comando.** Cada ação do usuário é um comando registrado (id, label, menu, atalho, parâmetros, `run`). Menus, atalhos, ferramentas, CLI, canal de controle e MCP chamam o mesmo registro.
2. **MCP como camada fina sobre o registro.** Poucas tools genéricas (`list_commands`, `execute`, `batch`) dão ao agente acesso a centenas de comandos, mais tools que devolvem imagem para o agente ver o resultado.
3. **Camadas impostas por código.** Um `cargo xtask layers` falha o build se uma camada baixa depender da UI.
4. **Instruções para agentes versionadas no repo.** `AGENTS.md` / `CLAUDE.md` dizem onde começar, o que é proibido e como verificar.
5. **Verificação objetiva e progresso medido.** `cargo xtask ci` antes de cada commit, proibição de panics via clippy, fuzzing de entradas e documentos de paridade com números.

## Stack de tecnologias

Tudo é Rust (edição 2024, Rust 1.95), sem JavaScript ou TypeScript escrito à mão. Um único workspace Cargo (`crates/*`, `apps/*`, `xtask`) gera o app desktop, a CLI e a versão web. A versão publicada na página do app é a 0.13.1; o repositório já está na 0.14.0.

| Área | Tecnologia | Para quê |
| --- | --- | --- |
| Interface | egui / eframe 0.36, egui\_kittest | UI imediata, a mesma no desktop e na web; testes de UI headless |
| GPU e janela | wgpu (Metal, DX12, Vulkan/GL; WebGPU/WebGL2 na web), winit | Composição na tela |
| Renderização 2D | vello\_cpu (multithread) | Desenha o documento em pixels na CPU |
| Geometria | kurbo, peniko, linesweeper | Curvas, transformações, booleanas |
| Texto | harfrust (shaping), skrifa (fontes) | Tipografia sem depender de fontes do sistema |
| Formatos | usvg (SVG), krilla e hayro (PDF), image, tiff, zune-jpeg | Importar e exportar SVG, PDF, EPS, DXF, EMF/WMF, PNG, JPEG, WebP |
| Plug-ins | wasmi (interpretador WebAssembly em Rust puro) | Plug-ins de terceiros em sandbox |
| Serialização | serde, serde\_json | Documento nativo em JSON, protocolo de controle e MCP |
| Erros e logs | thiserror, log, chrono | Erros tipados, logs, datas |
| Testes | proptest, testes de fuzz, egui\_kittest | Entradas hostis nunca derrubam o app |
| Desktop nativo | rfd, arboard, objc2 (macOS), windows / winsafe | Diálogos, área de transferência, fontes do sistema |
| Web | wasm-bindgen, web-sys, js-sys | Build `wasm32` para o navegador |
| Libs da suíte | craft-libs (craft-pdf, craft-print, craft-ui, craft-window, craft-docpath) | Código compartilhado entre todos os apps *craft*, fixado por commit |
| Ferramentas de build | `cargo xtask` (layers, assets, cleanroom, wasm, ci) | Verificações automáticas que o agente roda antes de cada commit |
| CI e distribuição | GitHub Actions, SonarCloud, CodeRabbit, Flatpak, AppImage, MSI, DMG, Nix, FreeBSD | Build multiplataforma, análise e revisão automática de PRs |

Duas decisões de configuração merecem cópia direta. No `Cargo.toml` do workspace, `unsafe_code = "deny"` e os lints `clippy::unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented` e `unreachable` estão em `deny`. E as dependências pesadas entram com `default-features = false`, ativando só o necessário.

## Estrutura e organização do código

O código é dividido em 24 crates de biblioteca, 3 apps e o xtask, organizados em oito camadas. A regra central: nada abaixo da L6 pode depender de egui, eframe, winit ou rfd. Por isso o mesmo motor serve ao desktop, à web, à CLI e ao MCP.

&#91;embedded content: camadas do VectorCraft · L0 a L7, motor no centro\]

### Tudo é um comando

Cada ação visível ao usuário é um `CommandSpec` em `crates/engine/src/cmd/*.rs` (cerca de 95 arquivos, um por área). Uma macro `cmd!` mantém cada definição em uma linha:

```rust
pub type Run = fn(&mut Session, &Value) -> Result<Value>;
pub type Enabled = fn(&Session) -> std::result::Result<(), String>;

pub struct CommandSpec {
  pub id: &'static str,              // "shape.rectangle"
  pub label: &'static str,           // "Rectangle"
  pub menu: &'static [&'static str], // ["Object", "Arrange"]; vazio = fora do menu
  pub shortcut: Option<&'static str>,
  pub params: &'static str,          // doc legível por humano E por agente
  pub enabled: Enabled,              // Err("nothing selected") explica o porquê
  pub run: Run,
  pub journal: bool,                 // false para consultas
}

cmd!("shape.rectangle", "Rectangle", [], None,
     "{x, y, width, height, radius?: pt, rotation?: deg} → {id}", has_doc, rectangle)
```

Três detalhes tornam isso bom para agentes:

- O campo `params` é uma assinatura compacta com tipos, padrões e retorno. Ele aparece no `list_commands` do MCP. Os testes do crate checam se cada chave passada a um comando está descrita no `params` (issue #1442), então a documentação não fica desatualizada.
- `enabled` devolve o motivo em texto ("no document open", "select at least two objects"). O agente recebe esse motivo como erro e sabe o que fazer antes de tentar de novo.
- `Session::execute(id, params)` é "O ponto de entrada de toda frente". Ele acha o comando, checa `enabled`, roda dentro do *guard* de panic, agrupa o undo e grava no journal. `command.batch` roda vários comandos como um único passo de undo.

As ferramentas de desenho (Pen, seleção direta) também emitem comandos, em três fases: begin, preview e commit. A UI é fina: os painéis só leem o estado do motor e agem com `app.run(id, params)`.

### xtask: verificações como código

`cargo xtask ci` roda, em ordem, e para no primeiro erro com um resumo de ok, FAIL e skip:

| Passo | O que garante |
| --- | --- |
| fmt | `cargo fmt --all -- --check` |
| clippy | `--workspace --all-targets -- -D warnings`, incluindo os lints sem panic |
| test | todos os testes do workspace |
| no-bundled-fonts | as bibliotecas compilam sem as fontes embutidas |
| pdf-deps | as libs de PDF compartilhadas estão na mesma revisão |
| assets / brands | todo asset tem linha em `ASSETS.md` com autor e licença |
| cursors | todo cursor está no catálogo `cursors.toml` |
| layers | nenhuma camada depende de outra acima |
| wasm | `cargo check --target wasm32-unknown-unknown` continua passando |
| cleanroom | nenhum aviso de copyright da Adobe nem fixture feita com apps da Adobe |

O `xtask` é um binário Rust no próprio workspace (`xtask/src/*.rs`), então cada regra tem testes próprios. O `layers.rs`, por exemplo, testa que uma dependência para cima ou para o lado é sinalizada.

### Robustez

- Panics são proibidos no código de produção pelos lints. Arquivos, dados colados, mensagens MCP e parâmetros de comando são tratados como entrada hostil.
- `vectorcraft_engine::guard` captura qualquer panic em cada ponto de entrada (comandos, eventos de ferramenta, requisições MCP, frame da UI) e reverte o documento.
- Entradas não confiáveis têm fuzzing: `import_fuzz.rs`, `command_sweep.rs` (todos os comandos com parâmetros lixo) e `mcp/tests/protocol_props.rs`.

## MCP em detalhe

O servidor MCP é o crate `crates/mcp` (cerca de 3.700 linhas de código e 3.200 de testes em \`src/\`). É JSON-RPC 2.0 escrito à mão, por stdio, sem SDK e sem runtime assíncrono. Ele não tem lógica de desenho: só traduz tools MCP em chamadas a um `Backend`, que no fim chama o mesmo `Session::execute` usado pela interface.

&#91;embedded content: caminho de uma chamada MCP · 2 backends, 1 motor\]

### Dois backends, uma interface

```rust
pub trait Backend {
  /// Chama um método do canal de controle ("engine.execute", "document.inspect", "ui.render"...).
  fn call(&mut self, method: &str, params: Value) -> Result<Value, String>;
  /// true quando há UI real (ui.key, ui.inspect funcionam)
  fn has_ui(&self) -> bool;
  fn describe(&self) -> String; // "headless", "remote 127.0.0.1:7979"
}
```

| Modo | Como iniciar | Quando usar |
| --- | --- | --- |
| Remote | app com `vectorcraft --control 7979`, depois `vectorcraft-cli mcp --connect 127.0.0.1:7979` | Ver o agente desenhar ao vivo; tudo funciona, inclusive cliques e screenshots da janela |
| Headless | `vectorcraft-cli mcp --headless` | Automação, CI, servidores; tudo menos as tools só de UI |
| Sem flag | `vectorcraft-cli mcp` | Tenta a porta 7979 e cai para headless |

O truque: o `Headless` implementa **os mesmos nomes de método** do canal de controle do app. Por isso as tools são escritas uma vez só. O canal de controle é uma porta TCP só em loopback com uma requisição JSON por linha (`{"id","method","params"}` → `{"id","ok","result"|"error"}`). Ele também serve para testes de UI e para os agentes que desenvolvem o app.

### As 32 tools, em três grupos

| Grupo | Tools | Ideia |
| --- | --- | --- |
| Acesso genérico ao registro | `command_list` / `list_commands`, `command_run` / `run_command`, `command_batch`, `invoke_menu` | 3 tools dão acesso aos 700+ comandos; o agente descobre e executa |
| Atalhos de alto nível | `draw_shape`, `draw_path`, `set_paint`, `add_text`, `apply_effect`, `pathfinder`, `transform`, `create_graph`, `text_wrap`, `open_file`, `save_file`, `export`, `undo`, `redo` | As tarefas mais comuns em uma chamada, com schema rico |
| Olhos e mãos | `doc_inspect` / `inspect_document`, `render_preview`, `screenshot`, `ui_screenshot`, `inspect_ui`, `select_tool`, `pointer_gesture`, `press_key`, `type_text`, `open_panel` | O agente vê (PNG inline, árvore de camadas) e usa o app como um humano |

Alguns nomes têm duas grafias (`command_run` e `run_command`). Isso aumenta a chance de o modelo acertar o nome de primeira.

### Outras partes do protocolo que eles usam

- **`instructions` no `initialize`.** Um parágrafo que ensina o sistema de coordenadas, o fluxo típico ("desenhe com draw\_shape, olhe com render\_preview, ache comandos com command\_list") e diz qual backend está ativo.
- **Resources.** Três fixos (`vectorcraft://document`, `vectorcraft://document/json`, `vectorcraft://commands`) e quatro templates (`object/{id}`, `command/{id}`, `effect/{id}`, `swatch/{name}`). Os templates leem uma coisa por vez, para o agente não pagar milhares de linhas do documento inteiro a cada passo.
- **Prompts.** Cinco fluxos prontos (`poster`, `icon-set`, `recolor`, `trace-and-style`, `export-set`), com argumentos, valores sugeridos e uma instrução para conferir com screenshots antes de exportar.
- **Completions.** `completion/complete` completa ids de comando, formatos, efeitos e nomes de swatch.
- **Logging, progresso e cancelamento.** `notifications/progress` em exportações longas ("Writing page 2 of 5"), `notifications/cancelled` para no próximo checkpoint sem gravar nada. Pedidos que chegam com o motor ocupado há mais de 2 s recebem o erro `-32003` com o nome da chamada em andamento.
- **Annotations.** Cada tool declara `readOnlyHint`, `destructiveHint` e `idempotentHint`, e as que gravam arquivo nunca são marcadas como somente leitura.
- **`command_batch` com referências.** Até 256 passos; um parâmetro `"$1.id"` pega o id criado no passo 1. Com `atomic: true` o lote vira um único passo de undo.

### Segurança e limites

- `--automation-read-root` e `--automation-write-root` confinam leituras e escritas a pastas. Links simbólicos são resolvidos, `..` e nomes de dispositivo do Windows são recusados. O erro volta como texto que o agente pode ler e corrigir.
- Limites explícitos: linha de até 16 MiB, lote de até 64 mensagens, resposta do app de até 256 MiB, até 64 linhas na fila. A porta de controle aceita só loopback, no máximo 16 conexões, e fecha a conexão com qualquer linha que não seja JSON (isso bloqueia um `fetch` de página web).
- Parâmetro desconhecido é erro antes de rodar, com sugestão: `unknown parameter 'widht'; did you mean 'width'?`.
- Testes de propriedade (`proptest`) no protocolo e testes de concorrência, limites e cancelamento.

O que eles deixaram de fora de propósito, e documentaram: assinatura de recursos, sampling e elicitation, e transporte HTTP/SSE.

### Exemplo de uso

```sh
cargo install --path apps/vectorcraft-cli --locked
claude mcp add vectorcraft -- vectorcraft-cli mcp
# confinado a uma pasta de projeto:
vectorcraft-cli mcp --automation-read-root /work/proj --automation-write-root /work/proj/out
```

```json
{"name":"draw_shape","arguments":{"shape":"rectangle","x":72,"y":72,"width":200,"height":120,"radius":12,"fill":"#1e88e5"}}
{"name":"run_command","arguments":{"command":"object.align","params":{"horizontal":"left"}}}
{"name":"screenshot","arguments":{"scale":0.5}}
{"name":"export","arguments":{"path":"/tmp/art.svg"}}
```

## Como usam agentes para desenvolver

O VectorCraft foi feito quase todo por agentes de código. O repositório tem 4.764 commits desde 30/09/2026, ou seja, em cerca de três semanas. No histórico, 1.249 commits têm `Co-Authored-By: Claude Opus 5.5`, além de Sonnet 5.5, Haiku 5.5 e Fable 5.1. Contribuidores externos também usam Cursor (88) e Codex (25). O ROADMAP mede o trabalho que falta em horas de agente: cerca de 170 a 270 h até a beta.

O segredo não é um framework de agentes. São quatro coisas versionadas no repositório: instruções, um ciclo de trabalho fixo, verificações automáticas e uma lista de trabalho ranqueada.

### 1. Instruções: `AGENTS.md` e `CLAUDE.md`

Os dois arquivos têm o mesmo conteúdo (88 linhas); `AGENTS.md` serve Codex, Cursor e outros, e `CLAUDE.md` o Claude Code. A estrutura:

| Seção | O que diz |
| --- | --- |
| Start every session here | Ler `ROADMAP.md` e `docs/gaps.md`; depois `plan/STATUS.md` e a tarefa em `plan/execution-plan.md`; seguir o protocolo autônomo |
| Non-negotiables | Clean-room, assets licenciados, nunca dar panic, tudo é comando, camadas, UI fina, só Rust, nunca quebrar WASM |
| Running and looking | Como rodar o app com `--control 7979`, mandar comandos JSON e tirar screenshot para olhar o resultado |
| Parallel agents | `CARGO_TARGET_DIR` separado por agente, editar só os crates que são seus, apagar o target no fim (\~30 GB) |
| Roadmap and progress docs | Quais documentos atualizar no mesmo PR quando uma tarefa termina |

Cada regra vem com o motivo e com a verificação que a impõe. Exemplo: "nunca dar panic" explica que um crash perde o trabalho do usuário, lista os substitutos (`?`, `.get(i)`, `let … else`) e diz que `cargo xtask ci` falha se a regra for quebrada. Regras compartilhadas entre todos os apps ficam num repositório separado, `storytold/craftrules` (privado), referenciado pelos `AGENTS.md`.

### 2. O ciclo de trabalho

&#91;embedded content: protocolo autônomo · 6 etapas por tarefa\]

O plano detalhado fica em `plan/`, uma pasta fora do git. Ela guarda o status da sessão, o plano de execução e notas de comportamento tiradas só de documentação pública.

### 3. Verificações que o agente consegue rodar sozinho

- `cargo xtask ci` antes de cada commit, com o resumo ok/FAIL/skip (seção de estrutura).
- Olhar o resultado: `ui.screenshot` pelo canal de controle e leitura do PNG. Se a tela estiver bloqueada, `ui.render` ou `vectorcraft-cli run … --export x.png`, e testes de painéis com egui headless.
- Orçamento de performance: `vectorcraft-cli perf` em um documento sintético de 50 mil paths, antes e depois de mexer em renderização ou formatos.
- Fuzzing e varredura de comandos para qualquer parser ou método de protocolo novo.

### 4. Progresso medido, não declarado

- `docs/gaps.md` é a lista ranqueada de tudo que falta: é de onde o agente tira a próxima tarefa quando ninguém passa uma.
- `docs/target-app-parity.md` dá nota e horas restantes por área, e checklists separados cobrem UI, formatos, efeitos, tipografia, hardware e idiomas.
- Regras de honestidade: notas autoavaliadas devem errar para baixo, cada número é marcado como medido ou estimado, e cada documento tocado ganha linha de status e histórico de revisão.

### Paralelismo

Os nomes de branch (`stream/vc-featD-3451-…`) mostram várias "streams" de agentes trabalhando ao mesmo tempo, cada uma num issue. Isso funciona porque cada agente tem seu próprio diretório de build, só edita os crates que lhe cabem e passa pelo mesmo `cargo xtask ci`. PRs passam por CodeRabbit e SonarCloud antes do merge.

## Receita para os seus projetos

Comece pelo registro de comandos e pelo `AGENTS.md`; o MCP vem depois e fica pequeno. A ordem abaixo segue a do VectorCraft.

1. **Monte o workspace em camadas.** `crates/model` (dados + serde), `crates/core` (algoritmos), `crates/engine` (sessão + comandos), `crates/ui` e `crates/mcp` em cima, `apps/*` e `xtask` no topo. Nada abaixo de `ui` importa a biblioteca de interface.
2. **Crie o registro de comandos** com id, label, `params` descritivo, `enabled` que explica o motivo e `run`. Um único `Session::execute(id, params)` como porta de entrada.
3. **Ligue a UI ao registro.** Menus e atalhos chamam `execute`; nada de lógica de negócio na UI.
4. **Exponha o registro por MCP** com três tools genéricas (`list_commands`, `run_command`, `batch`) e uma tool que devolve imagem ou estado para o agente conferir o resultado.
5. **Adicione um canal de controle** (TCP loopback, JSON por linha) se o app tem janela, e um backend headless com os mesmos métodos.
6. **Escreva o `xtask ci`** e o `AGENTS.md`, e crie `docs/gaps.md` com a lista ranqueada do que falta.
7. **Só então** acrescente atalhos de alto nível no MCP para as tarefas que o agente mais repete.

### Esqueleto: registro de comandos

```rust
// crates/engine/src/cmd/mod.rs
use serde_json::{json, Value};

pub type Run = fn(&mut Session, &Value) -> Result<Value, EngineError>;
pub type Enabled = fn(&Session) -> Result<(), String>;

pub struct CommandSpec {
  pub id: &'static str,
  pub label: &'static str,
  pub menu: &'static [&'static str],
  pub shortcut: Option<&'static str>,
  pub params: &'static str, // "{x, y, width, height} → {id}"
  pub enabled: Enabled,
  pub run: Run,
}

pub fn has_doc(s: &Session) -> Result<(), String> {
  s.doc.as_ref().map(|_| ()).ok_or_else(|| "no document open".into())
}

pub static COMMANDS: &[CommandSpec] = &[
  CommandSpec { id: "shape.rectangle", label: "Rectangle", menu: &[], shortcut: None,
    params: "{x, y, width, height} → {id}", enabled: has_doc, run: shape_rectangle },
  // ...
];

impl Session {
  /// A única porta de entrada: UI, CLI, canal de controle e MCP chamam aqui.
  pub fn execute(&mut self, id: &str, params: &Value) -> Result<Value, EngineError> {
    let spec = COMMANDS.iter().find(|c| c.id == id)
      .ok_or_else(|| EngineError::UnknownCommand(id.into()))?;
    (spec.enabled)(self).map_err(|why| EngineError::Disabled(id.into(), why))?;
    let snapshot = self.doc.clone(); // modelo com Arc: cópia barata
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (spec.run)(self, params))) {
      Ok(r) => r,
      Err(_) => { self.doc = snapshot; Err(EngineError::Internal(id.into())) }
    }
  }

  pub fn list(&self) -> Value {
    json!(COMMANDS.iter().map(|c| json!({
      "id": c.id, "label": c.label, "params": c.params,
      "enabled": (c.enabled)(self).is_ok(),
      "disabledReason": (c.enabled)(self).err(),
    })).collect::<Vec<_>>())
  }
}
```

### Esqueleto: servidor MCP por stdio, sem SDK

```rust
// crates/mcp/src/lib.rs
use std::io::{BufRead, Write};
use serde_json::{json, Value};

const INSTRUCTIONS: &str = "Every action is a command: find ids with list_commands, \
  run them with run_command (or batch). Look at the result with render before saving.";

pub fn serve(session: &mut Session) -> std::io::Result<()> {
  let stdin = std::io::stdin();
  let mut out = std::io::stdout();
  for line in stdin.lock().lines() {
    let line = line?;
    if line.trim().is_empty() { continue; }
    let Ok(msg) = serde_json::from_str::<Value>(&line) else {
      writeln!(out, "{}", json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}))?;
      continue;
    };
    let Some(id) = msg.get("id").cloned() else { continue }; // notificação: sem resposta
    let method = msg["method"].as_str().unwrap_or_default();
    let reply = match method {
      "initialize" => json!({"result": {
        "protocolVersion": "2025-06-18",
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "meuapp", "version": env!("CARGO_PKG_VERSION")},
        "instructions": INSTRUCTIONS }}),
      "tools/list" => json!({"result": {"tools": tool_definitions()}}),
      "tools/call" => json!({"result": call_tool(session, &msg["params"])}),
      "ping" => json!({"result": {}}),
      _ => json!({"error": {"code": -32601, "message": format!("unknown method {method}")}}),
    };
    let mut reply = reply;
    reply["jsonrpc"] = json!("2.0");
    reply["id"] = id;
    writeln!(out, "{reply}")?;
    out.flush()?; // stdout é só protocolo; logs vão para stderr
  }
  Ok(())
}

fn call_tool(s: &mut Session, p: &Value) -> Value {
  let args = &p["arguments"];
  let r = match p["name"].as_str().unwrap_or_default() {
    "list_commands" => Ok(s.list()),
    "run_command" => s.execute(args["command"].as_str().unwrap_or_default(), &args["params"])
      .map_err(|e| e.to_string()),
    "render" => return image_result(s.render_png()), // {"type":"image","data":base64,"mimeType":"image/png"}
    other => Err(format!("unknown tool {other}")),
  };
  match r { // erro de tool vira texto que o agente lê e corrige, não erro de protocolo
    Ok(v) => json!({"content": [{"type": "text", "text": v.to_string()}], "isError": false}),
    Err(e) => json!({"content": [{"type": "text", "text": e}], "isError": true}),
  }
}
```

Registre no Claude Code com `claude mcp add meuapp -- meuapp-cli mcp`.

### Template de `AGENTS.md` (copie também como `CLAUDE.md`)

```markdown
# MeuApp — instruções para agentes

Uma frase sobre o que é o app e o alvo de qualidade.

## Comece toda sessão aqui
1. Leia ROADMAP.md e docs/gaps.md (lista ranqueada). Sem tarefa do usuário, pegue a primeira de gaps.md.
2. Leia plan/STATUS.md (local, fora do git) e a tarefa no plano.
3. Ciclo: orientar → planejar → implementar + testar → verificar → registrar → commit.
   Pare e pergunte só para: licença, publicação, segredos, remotos novos.

## Inegociáveis
- Tudo é comando: comportamento novo = CommandSpec em crates/engine/src/cmd/ + teste.
- Nunca dar panic em código de produção (sem unwrap/expect/panic!); entradas são hostis.
- Camadas: nada abaixo de crates/ui depende da biblioteca de UI (cargo xtask layers).
- UI fina: painéis só leem estado e chamam execute.

## Verificação
- Antes de cada commit: cargo xtask ci (fmt, clippy -D warnings, testes, layers).
- Mudou UI? Rode com --control 7979, tire ui.screenshot e leia o PNG.
- Um id de tarefa por commit: "M2.1: ferramenta pen".

## Agentes em paralelo
- CARGO_TARGET_DIR próprio; edite só seus crates; apague o target no fim.

## Progresso
- Ao terminar: atualize docs/gaps.md, o checklist da área e o log do ROADMAP.md.
- Notas autoavaliadas erram para baixo; marque cada número como medido ou estimado.
```

### `Cargo.toml` do workspace: os lints que fazem o agente obedecer

```toml
[workspace.lints.rust]
unsafe_code = "deny"

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
unimplemented = "deny"
unreachable = "deny"
```

Com `clippy.toml` contendo `allow-unwrap-in-tests`, `allow-expect-in-tests` e `allow-panic-in-tests` iguais a `true` (como no VectorCraft), os testes continuam livres para usar `unwrap`.

## Fontes

- [Página do VectorCraft](https://getartcraft.com/apps/vectorcraft) (versão 0.13.1, plataformas, recursos)
- [storytold/vectorcraft](https://github.com/storytold/vectorcraft), commit atual da branch principal, lido localmente:
  - `AGENTS.md`, `CLAUDE.md`, `Cargo.toml`, `clippy.toml`, `ROADMAP.md`
  - `docs/architecture.md`, `docs/mcp.md`, `docs/control-protocol.md`, `docs/gaps.md`, `docs/target-app-parity.md`
  - `crates/engine/src/cmd/mod.rs`, `crates/engine/src/lib.rs` (`Session::execute`)
  - `crates/mcp/src/` (`lib.rs`, `server.rs`, `tools.rs`, `backend.rs`, `intake.rs`, `prompts.rs`)
  - `xtask/src/main.rs`, `xtask/src/layers.rs`
  - histórico git: 4.764 commits, trailers de coautoria
- [storytold/wordcraft](https://github.com/storytold/wordcraft) e [storytold/artcraft](https://github.com/storytold/artcraft), para confirmar que a estrutura é a mesma em toda a suíte
- [Especificação do Model Context Protocol](https://modelcontextprotocol.io)

O repositório `storytold/craftrules` (regras compartilhadas) e a pasta `plan/` (plano de execução) são privados; o que está aqui sobre eles vem das referências nos `AGENTS.md`.
