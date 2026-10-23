# Estilo da GUI

Padrões visuais que valem para toda a GUI (`crates/ui`). Quem cria ou muda uma janela segue estes
padrões em vez de inventar um novo. Revisão: AGENTS.md, "UI fina".

## Selos (chips)

Um **selo** é uma pílula pequena e arredondada ao lado de um valor, para uma informação curta sobre
ele: `privada`, `CGNAT`, `MPLS 85260`. Código: `crates/ui/src/chip.rs` (primeiro uso: MTR, G6.3d).

- **Nunca** texto entre colchetes (`10.0.0.1 [private]`) nem cores escolhidas na hora: use `chip()`.
- Fica **na mesma linha** do valor, a ~8 px dele, e nunca mais alto que a linha da tabela (todas as
  linhas da tabela com a mesma altura).
- Texto curto, minúsculo quando é uma palavra comum (`privada`), sigla em maiúsculas (`CGNAT`).
- Detalhes vão no tooltip, não no selo.

Tons (`chip(ui, texto, tom)`):

| Tom | Quando | Exemplo |
|---|---|---|
| `neutral_tone(visuals)` | um fato que vale um olhar, sem alarme | `privada` |
| `AMBER.tone(visuals)` | algo que o operador deve notar | `CGNAT` |
| `BLUE.tone(visuals)` | um detalhe extra, informativo | `MPLS 85260` |
| `GREEN.tone(visuals)` | um estado que está como deve | `running` |
| `RED.tone(visuals)` | um estado quebrado, que pede o operador | `failed` |

## Selos coloridos por chave (hash de cor)

Quando o selo identifica **uma coisa que se repete** numa lista (um AS, uma VLAN, uma VRF, uma
interface list), a cor vem de um **hash da chave**: a mesma chave tem sempre a mesma cor, em todas as
linhas, janelas e execuções, e a troca de uma para outra salta aos olhos (no MTR, onde termina uma
operadora e começa a outra).

- `hashed(chave)` dá a entrada da paleta (`PALETTE`, 8 tons escolhidos para contraste no tema
  claro e no escuro); `palette_tone(visuals, entrada)` dá as cores.
- Numa lista em sequência (os hops de um caminho), use `hues_along(chaves)`: se duas chaves
  **diferentes e vizinhas** caírem na mesma cor, a segunda pega a próxima — a mudança sempre aparece.
- Chave numérica (AS, VLAN id) vai direto; chave de texto (nome de lista, de VRF): faça um hash
  estável do nome para `u64` (FNV-1a) e passe ao `hashed`. Nunca `std::hash` aleatório.
- O texto do selo é curto (`AS7162 UOL`); o nome completo vai no tooltip.
- Nunca use a cor como a única informação: o texto do selo diz o que é.

## Selo de identidade do assinante (G0.25)

Ao lado de um endereço IP que pode ser de um assinante, o nome dele num selo azul com o ícone de
crachá (`IDENTIFICATION_BADGE` do Phosphor, o equivalente ao `ti-user`): `100.64.0.1 [crachá João
Pereira] +2`. Código: `crates/ui/src/identity.rs`; dados: `ip.identity.lookup`.

- **O selo é a primeira fonte com nome**, na ordem de Settings › Subscriber identity; os outros
  nomes diferentes viram um selo neutro `+N`. O nome chega limpo e cortado pelo engine (64
  caracteres, sem controle nem bidi).
- **Tooltip** lista todos os nomes, cada um com a fonte e o detalhe (MAC, lista, zona), e o passo do
  CGNAT quando houve (`203.0.113.0:1100 → 100.64.0.0`).
- **Clique** abre o item de origem com ele selecionado: a concessão (DHCP Server › Leases), o
  endereço (IP › Addresses), a entrada (Firewall › Address Lists) ou o registro PTR (DNS › Zones ›
  Records).
- Sem nome conhecido: nada (o endereço sozinho). O nome é pedido em lote no refresh seguinte e
  guardado 30 s; uma janela nunca pede endereço a endereço.
- **Onde aparece** é preferência do cliente (Settings › Subscriber identity › Show in), como os
  idiomas: cada tela passa a sua chave (`torch`, `connections`, `traffic-flow`, `cgnat`, `leases`,
  `mtr`).

Como usar numa janela:

- **Numa tabela:** `identity::add_chips(app, ui, "<tela>", &mut row, coluna, &ip)` depois de montar
  a linha, e `identity::table_chip(app, ui, "<tela>", &out, &rows, |chave| ip_da_linha)` depois do
  `table::show` (tooltip e clique; o `TableOutput.chip` diz qual selo está sob o ponteiro).
- **Fora de tabela** (formulário, linha de resultado): `identity::badge(app, ui, "<tela>", &ip)`;
  num instante passado (CGNAT › Quem era?), `identity::badge_at(app, ui, "cgnat", &ip,
  Some(instante))`: o nome de quem tinha o IP naquela hora (histórico de concessões).
- IP público com porta (`203.0.113.5:40001`) vai como está: o engine passa pelo CGNAT.

Um selo de célula com ícone: um rótulo que começa por um code point de uso privado (os do
`icons.rs`) é desenhado com esse ícone na fonte de ícones (`chip::label_galley`).

## Tabelas

- Uma linha por item, todas com a mesma altura; o valor longo termina em `…` com o completo no
  tooltip.
- Item sem dado: texto apagado (`sem resposta`), números como `–`.
- Clique numa linha seleciona (destaque com a cor de seleção do tema, pintado atrás do texto);
  clique de novo desmarca; clique direito abre o menu com as cópias úteis (endereço, nome).
- Confira no tema claro **e** no escuro (screenshot), como manda o AGENTS.md.

## Explicação ⓘ em todo lugar que couber (regra)

Sempre que der, todo rótulo de campo, parâmetro, coluna, aba, item de menu e título de janela leva
o ícone **ⓘ**, que abre o **modal de explicações**: o que é, quando mudar, cuidado, o padrão ou
recomendado e a RFC quando houver. O texto vem do catálogo de explicações (abaixo), **em
português por padrão** (configurável em Settings). Janela ou campo novo sem explicação é
incompleto: o teste do catálogo confere que toda chave usada tem texto. Só fica sem ⓘ o que é
óbvio por si (um botão OK, um campo Comment).

## Idioma: rótulos e explicações (G0.15)

A GUI tem **dois idiomas independentes**, escolhidos em Settings › Settings e guardados com o tema
(preferência deste computador ou navegador, nunca do roteador):

- **rótulos** — menus, títulos de janela, colunas, botões. Padrão: inglês (os nomes do RouterOS);
- **explicações** — o texto de ajuda e o modal do botão ⓘ. Padrão: português.

Código: `crates/ui/src/i18n/` (catálogos `en.rs` e `pt.rs`, ordenados pela chave), `help.rs` (botão
ⓘ e modal) e `markdown.rs` (o Markdown simples das explicações). Uma janela **nova** faz assim:

- **Rótulo:** `tr(app.lang.labels, "Ring size")`. O texto em inglês é a chave e o fallback: sem
  tradução aparece em inglês, nunca uma chave. A tradução entra em `i18n/pt.rs` (`LABELS`, na
  ordem); uma feature com muitos textos ganha o seu par de arquivos (`i18n/tuning_en.rs`,
  `tuning_pt.rs`) e uma linha em `Lang::labels`/`help`, para PRs paralelos não editarem a mesma
  lista. O título da janela (`WinDef::title`) e o nome do grupo do menu já passam pelo `tr`.
- **Explicação:** uma chave estável por parâmetro ou tópico (`tuning.net.core.netdev_max_backlog`),
  com o texto em `HELP` de `en.rs` **e** de `pt.rs` (o teste
  `every_explanation_exists_in_both_languages` confere). Markdown simples: `## Título`,
  parágrafos separados por linha em branco, `- item`, `` `código` `` e `**negrito**`.
- **Botão ⓘ:** `help::info_button(ui, id, dica)` ao lado do valor; clicado, guarde
  `Some(HelpView::new(chave, título))` no estado do painel e desenhe `help::modal(ctx, app.lang,
  &mut self.help)` em `PanelState::dialogs`. Faltou a explicação no idioma escolhido? Ela aparece
  no idioma dos rótulos e depois em inglês, sem panic.
- Texto calculado (valor recomendado, comando equivalente) entra como seção extra do `HelpView`
  (`.with(título, markdown)`), com o título em inglês passado ao `tr` no idioma das explicações.
- Texto que o **engine** manda em inglês com argumentos (o motivo de um valor recomendado) vem com
  um id: `i18n::template(lang, "why.<id>", args, inglês)` usa o modelo do catálogo (`TEMPLATES`) e
  cai para o texto do engine; um teste confere que todo id do engine tem modelo em PT com os mesmos
  argumentos.
- Os rótulos das janelas antigas ainda não passam pelo `tr` (G0.15b).

**Janela nova: traduções em `crates/ui/src/i18n/auto/`.** Um par de arquivos por janela,
`<escopo>_en.rs` e `<escopo>_pt.rs` (constantes `LABELS`, `HELP`, `TEMPLATES`), que o `build.rs`
registra sozinho: não edite as listas do `i18n/mod.rs` (era o arquivo onde todo PR com tela
conflitava). Os rótulos da janela usam `i18n::tr_in("<escopo>", lang, "Texto")`: o catálogo do
escopo vem primeiro, então a mesma palavra em inglês pode ter traduções diferentes em janelas
diferentes ("Last" = "Última" numa, "Últimos" noutra) sem quebrar o teste. Explicações usam chaves
com o escopo na frente (`traffic_flow.active_timeout`). Veja `i18n/auto/README.md`.

## Menu lateral e ícones (G0.23)

- Toda janela tem **entrada em `crates/ui/src/menu.rs`** (`CATALOG`): subgrupo (`DHCP`, `DNS`)
  quando o grupo passaria de ~8 itens soltos, rótulo curto dentro do subgrupo ("Static" em
  IP › DNS; o título da janela continua "DNS Static"), ícone, caminho no RouterOS, prefixos dos
  comandos e sinônimos de busca. Janela nova sem entrada reprova o teste do menu.
- **Ícones só do Phosphor** (`crates/ui/src/icons.rs`), nunca emoji nem glifo solto: a fonte da
  GUI não tem a maioria. Ícone novo: constante em `icons.rs` + `scripts/icons-subset.sh`.
  Escolha pelo que a janela **é**: servidor (`HARD_DRIVES`), cliente (`LAPTOP`), escudo
  (firewall), placa de rua (rotas), globo (DNS), coração (Services), medidor (Tuning).
- Grupos principais em negrito com ícone; subgrupo recolhido mostra a contagem num selo neutro;
  área ainda sem comandos aparece apagada, com cadeado e o selo `soon`.
- A explicação de uma janela (ⓘ do item selecionado) é `menu.<chave>` nos catálogos
  `i18n/menu_en.rs` e `i18n/menu_pt.rs`; caminho do RouterOS e comandos o modal acrescenta sozinho.

- **Busca** (campo do menu e Ctrl+K, `crates/ui/src/menu_search.rs`): acha pelo título, rótulo,
  lugar no menu, caminho do RouterOS e sinônimos da entrada. Janela nova: ponha nos sinônimos as
  palavras que o operador usaria (inclusive em português e o nome em outros roteadores). Atalhos:
  `/` foca a busca, Ctrl+K abre a paleta; nenhuma janela deve usar esses dois.
- **Selos de estado no menu** (`crates/ui/src/menu_badges.rs`): só de consultas que já existem,
  sem regra de negócio na UI; vermelho para o que está quebrado (`1 failed` em Services), âmbar
  para o que pede um olhar (`2 conflict` no DHCP Server, `drift 1` em History). Grupo ou subgrupo
  fechado mostra o selo dos seus itens (ou quantos são, na cor do pior); detalhes no tooltip.
- **Partes de uma janela são abas dela, não itens do menu** (DNS Zones: Zones, Records, Zone File;
  DHCP Server: …, History, Statistics). Item novo no menu só para uma janela que o operador abre
  por si.

## Janela de lista e modal de adicionar (padrão aprovado, G0.24)

Toda janela que lista itens configuráveis (endereços, regras, pools, estáticas, concessões…)
segue este padrão; a referência é IP › Addresses (G1.28). Os componentes são reutilizáveis (não
copie o código de uma janela para outra).

**Barra de ações**, nesta ordem, com ícone e dica:

| Botão | Ação | Cinza quando |
|---|---|---|
| **+** | abre o modal de adicionar | o roteador não tem o comando `…add` |
| **−** | remove a seleção (com confirmação se for mais de um) | nada selecionado; item dinâmico (DHCP, RA) que não se remove |
| **✓** | ativa a seleção | nada desativado selecionado |
| **✗** | desativa a seleção (fica na config, sai do kernel) | nada ativo selecionado; item sem `disabled` |
| **💬** | comenta a seleção | nada selecionado |

Depois dos botões: os filtros em selos (família, origem, estado…) e o Find à direita. Botão
cinza diz por quê na dica (a regra vem do engine: `enabled`/`disabledReason`).

**Tabela:** selo de **estado** (`active`, `disabled`, `invalid`, `tentative`…) e de **origem**
(`static`, `dhcp`, `ra`, …) no lugar das flags de letra do RouterOS (que continuam no terminal);
interface e VRF em selo colorido por chave; item desativado em cinza; rodapé com contagens
(total, por estado, por família). Duplo clique abre o mesmo modal preenchido (editar); clique
direito: copiar, copiar como comando (CoreRouter e RouterOS), ativar/desativar, remover.

**Modal de adicionar e editar:**

- **ⓘ em cada rótulo** e no título da janela, abrindo a explicação no idioma configurado (o que
  é, quando mudar, cuidado, padrão recomendado, RFC). Rótulos em inglês, explicações em português.
- **Campos calculados** ao digitar (rede, broadcast e hosts de um endereço; quantos itens uma
  faixa gera), sem regra na UI: o engine calcula (comando de consulta ou de pré-visualização).
- **Cadastro em série** quando faz sentido (faixa, lista colada, contador): gera vários itens
  numa **transação só**, com teto e aviso acima dele.
- **Checagens antes de aplicar**, com selo `ok`/`aviso`/`erro` e o motivo: conflito e
  sobreposição com o que existe, uso na rede quando dá para conferir (ARP, RFC 5227), e o
  **risco de perder o acesso** (mexer na interface por onde a sessão chega pede confirmação e
  sugere o Safe Mode).
- **Prévia dos comandos** que serão aplicados.
- Botões **Cancel**, **Apply** (aplica e mantém aberto) e **OK** (aplica e fecha); Enter = OK,
  Esc = Cancel. Erro do engine aparece no modal, junto do campo, sem fechar.

### Como adotar (API dos componentes)

Código: `crates/ui/src/list.rs` (barra, filtros, rodapé, menu de clique direito, cópias, transação)
e `crates/ui/src/list_modal.rs` (o modal). Nada ali decide o que um item pode: a linha que o engine
manda diz (`disabled`, `dynamic`, motivo), e o `engine.list` diz se o comando existe e está liberado.

- **Barra:** `Tools::new(&app.can(), &Cmds{add, remove, set, what}, &picked)` calcula cada botão
  (`Ok` ou o motivo do cinza: primeiro o do roteador, depois o da seleção); `list::toolbar(ui, salt,
  &tools, &sel, lang)` desenha **+ − ✓ ✗ 💬** e devolve um `Act`. `Item::of(linha, "id", motivo)`
  monta o que cada linha diz de si (item dinâmico fica preso, com o motivo).
- **Filtros:** `Filters` guarda os selos ligados por campo da linha; `filters.chips(ui, "family",
  &[("ipv4", "IPv4"), …], lang)` desenha, `filters.shows(&linha)` filtra (E entre campos, OU dentro
  de um). O Find (`table::find_field`) vem por último, à direita.
- **Rodapé:** `list::footer(ui, &[(n, "addresses", tom), …], lang)`; contagem zero depois da
  primeira some. `list::count(linhas, campo, valor)` conta.
- **Clique direito e teclado:** dentro do `Menu::Rows` do `table::show`, `list::row_menu(ui, &tools,
  sel, comandos_conhecidos, lang)` (abrir, copiar, copiar como comando CoreRouter e RouterOS,
  ativar, desativar, comentar, remover); `list::from_shortcut(out.shortcut, &tools, &sel)` faz o
  mesmo pelas teclas, só quando o botão agiria.
- **Cópias:** `list::copy_rows` (texto das células, separado por tab) e
  `list::copy_commands(app, "ip.address.add", &linhas, Syntax::RouterOs)` — o `add` que recria cada
  linha, com os parâmetros que o próprio `add` do roteador declara (`corerouter_shell::recreate`,
  `command_line`): `/ip address add address=10.0.0.1/24 interface=ether1` ou
  `ip.address.add {"address":…}`.
- **Transação:** `app.run_steps(passos, then)` manda vários comandos como um `engine.batch`
  atômico (tudo ou nada); um passo só vai como ele mesmo, para a proteção de perda de acesso
  (G2.1b) poder perguntar.
- **Modal:** a janela descreve os campos uma vez (`Spec { panel, parent, new_title, edit_title,
  help, fields, preview }`, cada `Field { param, label, help, input, edit }`), abre com
  `Modal::open(app, item, valores)` e, no `dialogs` do painel, chama `modal.show(app, ctx, area,
  &SPEC, &opções)` até ele devolver `false`. O painel repassa ao modal a resposta da pré-visualização
  (`arrived` com a chave `list_modal::PREVIEW`) e a do Apply/OK (`reply` com `list_modal::Applied`).

**O comando de pré-visualização** (consulta do engine, um por janela) recebe os mesmos parâmetros do
`add`, todos opcionais, mais `id` ao editar, e nunca falha por entrada ruim (vira checagem `error`):

```text
{ computed: [{label, value}],                 campos calculados
  checks:   [{level, check, message, param?}], ok | warning | error | pending | info
  commands: [{command, params}],              o que OK/Apply mandam, numa transação
  risk?:    "por que pode cortar esta sessão" }
```

`pending` é checagem em andamento (ARP): o modal pergunta de novo em ~0,4 s. Erro com `param`
aparece embaixo do campo; o erro do roteador ao aplicar também. `risk` pede o "Entendi" (os comandos
vão com `force: true`) ou o botão Safe Mode.

Exemplo (um painel com lista; o IP › Addresses, G1.28, é a referência completa):

```rust
const FIELDS: &[Field] = &[
    Field { param: "address", label: "Address", help: "ip.address.address",
            input: Input::Text("10.0.0.1/24"), edit: true },
    Field { param: "interface", label: "Interface", help: "ip.address.interface",
            input: Input::Choice, edit: true },
];
const SPEC: Spec = Spec { panel: NAME, parent: Win::Panel(WIN), new_title: "New Address",
    edit_title: "Address", help: "ip.address", fields: FIELDS, preview: "ip.address.preview" };

// window(): a barra e a tabela
let picked: Vec<Item> = linhas_selecionadas.map(|r| Item::of(r, "id", "dynamic")).collect();
let tools = Tools::new(&app.can(), &CMDS, &picked);
let mut act = None;
ui.horizontal(|ui| {
    act = list::toolbar(ui, TABLE, &tools, &sel, app.lang.labels);
    self.filters.chips(ui, "family", &[("ipv4", "IPv4"), ("ipv6", "IPv6")], app.lang.labels);
    table::find_field(ui, TABLE, &mut self.table);
});
// … table::show(…, |ui, menu| if let Menu::Rows(sel) = menu {
//         act = list::row_menu(ui, &tools, sel, true, l) });
// act: Add → self.modal = Some(Modal::open(app, None, padrões)); Edit(k) → Modal::open(app, Some((k, nome)), valores)

// dialogs(): o modal
if let Some(m) = self.modal.as_mut() && !m.show(app, ctx, area, &SPEC, &|p| opções(p)) {
    self.modal = None;
}
```
