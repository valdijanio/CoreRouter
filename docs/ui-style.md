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
