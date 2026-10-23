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
