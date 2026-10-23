id: audit-gui

Auditoria da GUI (`crates/ui`, `apps/corerouter-gui`): 11 dos 12 achados corrigidos aqui, 1 vira
gap (G1.24) e o resto de custo por quadro com listas enormes vira a G1.25. Os testes novos
falharam com o código da `main` (rodados com a correção desligada, **medido**); os de desempenho
têm bench antes/depois na seção `## perf` (bench novo `crates/ui/benches/frames.rs`, que desenha a
UI de verdade sobre listas grandes postas no cache, pelos ganchos `corerouter_ui::perf`).

Corrigido:

- **Médio — seleção de tabela O(n²) por quadro** (#1). `table::show` recalculava a seleção
  inteira (`state.selection(rows)`) uma vez **por linha**, e `retain` fazia `order.contains`
  (um `Vec`) para cada chave selecionada; cada janela ainda filtrava as linhas com
  `selection.contains` num `Vec<String>`. Com 10 000 endereços e Ctrl+A, **15 s por quadro**. Agora
  a seleção é um `table::Selection` (ordem de exibição + `HashSet`, `contains` O(1)), calculada uma
  vez por quadro; `retain` usa um `HashSet`; e a tabela só desenha e registra as linhas que estão
  na tela (as outras só ocupam o lugar; a linha arrastada continua viva fora da tela). Testes
  `table::tests::only_the_rows_in_view_are_drawn` e o bench `ui_frame/addresses_10k_all_selected`:
  15,15 s → 28 ms.
- **Médio — aba Filter Rules copiava todas as regras a cada quadro e o "NUNCA CASA" era O(n²)**
  (#2). As listas do firewall ficam num `Arc<Vec<Value>>` (o quadro pega emprestado, não copia), e
  a posição de cada regra por id é um `HashMap` montado uma vez por quadro (`firewall::positions`).
  Bench `ui_frame/firewall_5k_shadowed`: 155 ms → 21 ms.
- **Médio — célula de tabela nunca era cortada** (#3, docs/ui-style.md › Tabelas). Um valor longo
  esticava a coluna sem limite e era medido inteiro em toda linha e todo quadro. Agora a célula
  mostra até 120 caracteres (`table::CELL_CHARS`) numa linha só, termina em `…` e o texto inteiro
  (até 4096 caracteres) vai no tooltip da célula; os selos (chips) depois do texto ficam. Teste
  `table::tests::a_long_cell_is_cut_with_an_ellipsis`; bench `addresses_1k_4kB_comments`: 94 ms →
  1,8 ms. (O engine já limita `comment` a 256 caracteres; a correção vale para toda célula.)
- **Médio — consulta ou poll sem resposta travava a atualização para sempre** (#4). O `refresh` não
  manda nada enquanto houver consulta pendente, e o Ping/MTR só pede de novo quando a resposta
  chega. Agora cada pedido pendente tem prazo: consulta, poll de ferramenta e aba de interface
  30 s, ação e terminal 120 s (o mesmo do cliente nativo). Consulta vencida: a UI pede de novo,
  registra no log e mostra o selo âmbar `stale` na barra de status até a próxima resposta; poll
  vencido: pergunta de novo sem dar a tarefa por perdida; ação vencida: sai do "waiting for the
  router" com erro ("pode ter sido aplicada: confira"). Na web, o `WsBackend` também dá prazo de
  120 s a cada id em voo (e um login sem resposta reabre a conexão). Testes
  `a_lost_query_reply_does_not_freeze_the_refresh`,
  `a_lost_poll_polls_again_and_a_lost_action_is_released`.
- **Médio — terminal re-quebrava e re-diagramava as 5000 linhas a cada quadro** (#5). As linhas
  quebradas ficam em cache por largura (só as novas são quebradas), só as linhas visíveis viram
  `Label`, e uma linha de saída guarda no máximo 64 Ki caracteres (`…` no fim). Teste
  `a_full_terminal_lays_out_only_what_is_in_view`; bench `terminal_5000_lines`: 8,5 ms → 0,09 ms.
- **Baixo — firewall mostrava listas de interface entre colchetes** (`[LAN]`, `![LAN]`, #6). Agora
  é um selo colorido pelo nome da lista (`chip::name_hue`, FNV-1a; a mesma função passou a servir
  o DHCP Server). Teste `firewall::interface_lists_are_chips_not_brackets`.
- **Baixo — cores escolhidas na hora** (#7): o `ALERT …` branco sobre vermelho fixo do Ping virou o
  selo vermelho `alerta` com os detalhes no tooltip; o status do NTP (`synchronized`/`waiting`) e
  o `link-ok`/`no-link` da aba Status da interface viraram selos GREEN/AMBER/RED; o âmbar da aba
  Ethernet vem do `chip::AMBER`. Ficou o vermelho do botão Safe Mode (`SAFE_MODE_FILL`): é o
  botão no estilo do WinBox, não um selo de estado.
- **Baixo — `TaskView::absorb` somava o contador `lost` do router sem saturar** (#8): dois
  `u64::MAX` davam panic em debug. Agora `saturating_add`. Teste `a_hostile_lost_counter_saturates`.
- **Baixo — `target as usize` no wasm32** (#9): `usize::try_from`, o evento fora de faixa é
  ignorado (só reproduz com ponteiro de 32 bits; sem teste que falhe em x86_64).
- **Baixo — CSV do Ping** (#10): campo que começa com `=`, `+`, `-`, `@`, tab ou CR (e não é
  número) ganha `'` na frente (injeção de fórmula em planilha); o app nativo nunca sobrescreve um
  arquivo (`create_new`, depois `ping-1-2.csv`, …). Testes `csv_quotes_what_needs_it` e
  `export::tests::a_second_export_never_replaces_the_first`.
- **Baixo — cobertura headless** (#12): `every_window_renders_with_data_and_long_values` abre
  todas as janelas (IPv6, rotas, VRF, DHCP Server/Relay com `relay_info_trusted`, firewall…) sobre
  um lab com dados e comentários longos e confere que nada sai inteiro nem entre colchetes;
  `every_interface_tab_renders_with_data` passa por todas as abas de "Interface <ether2>" com
  amostras de tráfego.

Conferido: os dois checkboxes `relay_info_trusted` (DHCP Server "Trust Option 82 Without Relay",
DHCP Relay "Trust Client Option 82") alinham no formulário (screenshots no PR). Como testar:
`cargo test -p corerouter-ui`, `cargo bench -p corerouter-ui --bench frames`; na GUI, IP ›
Addresses com comentários longos (passe o mouse no `…`) e IP › Firewall com
`in_interface_list=!LAN`.

| G1.24 | Regras de negócio que a GUI ainda decide sozinha | engine, ui | O engine expõe nas respostas de listagem o que hoje a UI deduz (`removable`/`editable` por linha, como já faz o `shadowed_by`; quais parâmetros cada `action` do firewall aceita) ou um `dry_run`; a UI só mostra: some `can_remove` (portas físicas), endereço dinâmico, `action_field_owner`, `not_zone`/`can_toggle`, `can_enable` do DHCP client/IPv6. Teste de contrato entre UI e engine | 6 h | aberto |
| G1.25 | Tabela de 10 000 linhas abaixo de 16 ms por quadro | ui | Com seleção O(1) e só as linhas visíveis desenhadas, o quadro de 10 000 endereços ainda custa 16 ms (28 ms com tudo selecionado, **medido**): as janelas remontam as `Row` do JSON e medem a largura de toda célula a cada quadro. Montar as linhas e as larguras uma vez por resposta (cache no `TableState`), `ui_frame/addresses_10k` < 5 ms | 4 h | aberto |

## perf

### audit-gui: um quadro da GUI com listas grandes (2026-10-22, **medido**)

AMD Ryzen AI MAX+ 395 (32 CPUs), build release (`cargo bench`), criterion. Bench novo
`crates/ui/benches/frames.rs`: um quadro 1400×900 da UI real, com a janela aberta e a lista posta
no cache (sem refresh entre quadros). "antes" = código da `main` (237ea9b) com os mesmos ganchos.

| Bench | antes | depois |
|---|---|---|
| `ui_frame/addresses_10k` | 208 ms | 16,1 ms |
| `ui_frame/addresses_10k_all_selected` (Ctrl+A) | 15,15 s | 28,0 ms |
| `ui_frame/addresses_1k_4kB_comments` | 94,4 ms | 1,78 ms |
| `ui_frame/firewall_5k_shadowed` | 155 ms | 21,0 ms |
| `ui_frame/terminal_5000_lines` (200 caracteres) | 8,47 ms | 0,090 ms |
