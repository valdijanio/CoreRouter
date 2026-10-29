# Políticas BGP — `/routing filter` (G3.2b)

A política de rotas do CoreRouter segue o `/routing filter` do RouterOS v7: regras escritas na
linguagem dele (`if (dst in bogons) { reject }`), agrupadas em chains, com listas de prefixos e de
communities ao lado. Uma conexão BGP aponta a chain das rotas recebidas (`input_filter`, o
`input.filter` do RouterOS) e a das enviadas (`output_filter`, o `output.filter-chain`).

O engine guarda o texto das regras, valida, avalia (prévia e impacto no commit) e rende para o FRR
como route-maps, prefix-lists, community-lists e AS-path access-lists; o `hal-frr` aplica só a
diferença.

## Como usar

```sh
corerouter-cli run routing.filter.prefix-list.add '{"name":"bogons","entries":"0.0.0.0/8 le 32, 10.0.0.0/8 le 32, 100.64.0.0/10 le 32, 127.0.0.0/8 le 32, 169.254.0.0/16 le 32, 172.16.0.0/12 le 32, 192.168.0.0/16 le 32, 0.0.0.0/0"}'
corerouter-cli run routing.filter.community-list.add '{"name":"blackhole","communities":"blackhole, 65100:666"}'
corerouter-cli run routing.filter.rule.add '{"chain":"upstream-in","rule":"if (dst in bogons) { reject }"}'
corerouter-cli run routing.filter.rule.add '{"chain":"upstream-in","rule":"if (afi ipv4 && dst-len > 24 || afi ipv6 && dst-len > 48) { reject }"}'
corerouter-cli run routing.filter.rule.add '{"chain":"upstream-in","rule":"if (bgp-communities any-list blackhole) { reject } set bgp-local-pref 150; accept"}'
corerouter-cli run routing.filter.rule.add '{"chain":"upstream-out","rule":"if (dst in 203.0.113.0/24) { set bgp-path-prepend 2; append bgp-communities 65000:10; accept }"}'
corerouter-cli run routing.bgp.connection.set '{"id":"upstream1","input_filter":"upstream-in","output_filter":"upstream-out"}'
corerouter-cli run routing.filter.preview '{"connection":"upstream1","direction":"in"}'
corerouter-cli run routing.filter.impact
```

| Comando | RouterOS v7 |
|---|---|
| `routing.filter.rule.{add,set,remove,move,list,check}` | `/routing filter rule` |
| `routing.filter.prefix-list.{add,set,remove,list,check}` | (o RouterOS usa address-lists do firewall; aqui é uma lista própria, no formato do FRR/Cisco) |
| `routing.filter.community-list.{add,set,remove,list,check}` | `/routing filter community-list` e `community-large-list` (juntas) |
| `routing.filter.preview` | — (o RouterOS não tem prévia) |
| `routing.filter.impact` | — |
| `routing.filter.status` | — (chains, quem usa, e as conexões eBGP sem chain) |
| `routing.filter.prepend.set` | — (G3.9fg: a contagem do `bgp-path-prepend` de um filtro antigo) |

Na GUI: **Routing › Filters** (abas Rules, Prefix Lists, Community Lists, Preview; aviso RFC 8212 e
impacto do commit em cima) e, em Routing › BGP, a página **Filters** do modal da conexão e do
template (Input Filter, Output Filter, Keep Received).

## `set bgp-path-prepend N` (G3.9fg)

Como no RouterOS v7: para um vizinho eBGP a rota sai com o nosso AS **N vezes no total**, a cópia
que o eBGP sempre põe incluída. `set bgp-path-prepend 3` sai `65000 65000 65000`; N = 1 não muda
nada. Na entrada e na saída iBGP o RouterOS não põe cópia nenhuma, e o CoreRouter também não (o
`rule.check` avisa `prepend-count`). Tudo **medido** no RouterOS 7.25 CHR,
`scripts/routeros-interop-bgp.sh prepend`: N = 1, 2, 3 no eBGP → 1, 2, 3 cópias; no iBGP e na
entrada → 0.

No FRR, `set as-path prepend` põe as cópias antes da do eBGP. O render faz a conta: o mapa de
saída de uma conexão eBGP põe N − 1, e o de entrada ou de saída iBGP não põe nada. Uma chain usada
nos dois lugares ganha um segundo mapa só para as saídas eBGP, `CR-<chain>+ebgp-out` (o `+` não
cabe num nome de chain).
A prévia (`routing.filter.preview`, `impact`) mostra a mesma conta: o caminho que a chain entrega,
antes da cópia do eBGP.

**Configs antigas não mudam sozinhas.** Até a G3.9fg o CoreRouter punha N além da cópia do eBGP
(N + 1). Um filtro gravado por uma versão anterior não tem o campo `prepend` e é lido como
`legacy`, com a contagem antiga: depois da atualização o roteador manda os mesmos caminhos de
antes. `routing.filter.status` traz `prepend` e `prepend_warning`, o `routing.filter.rule.check`
avisa (`prepend-count`) e a janela Routing › Filters mostra o selo **Prepend count** com o botão
**Use RouterOS count**, que roda:

```sh
corerouter-cli run routing.filter.prepend.set '{"count":"routeros"}'
```

Com `keep_paths` (padrão), ele reescreve N para N + 1 nas chains que só saem por eBGP, para o
vizinho continuar recebendo o mesmo caminho, e lista em `left` o que não dá para manter: chain
usada na entrada ou numa saída iBGP, onde o prepend deixa de fazer efeito (com a contagem antiga
punha N), e N já em 16. Em
modo transacional, `routing.filter.impact` mostra o efeito antes do commit. Filtros novos já
nascem com a contagem do RouterOS.

## A linguagem

```text
rule    := stmt*
stmt    := if (expr) { stmt* } [else { stmt* } | else if …] | action [;]
action  := accept | reject | return | jump CHAIN
         | set bgp-local-pref N | set bgp-med N | set bgp-path-prepend 1..16
         | set|append|delete bgp-communities VALORES|LISTA   (set … none apaga todas)
         | set|append|delete bgp-large-communities VALORES|LISTA
expr    := expr || expr | expr && expr | not expr | ! expr | (expr) | matcher
matcher := dst in PREFIXO|LISTA | dst == PREFIXO | dst != PREFIXO
         | dst-len (==|!=|<|<=|>|>=) N | dst-len in N-M
         | afi ipv4|ipv6 | protocol bgp,connected,static,ospf,rip
         | bgp-as-path "REGEX"
         | bgp-communities|bgp-large-communities includes|any|equal[-list] VALORES|LISTA
```

- As regras de uma chain rodam na ordem da lista; `accept`/`reject` encerram; `jump` roda outra
  chain e volta no fim dela ou num `return`; a rota que **nenhuma regra aceita é rejeitada** (a
  ação padrão do RouterOS v7). Laço de `jump` é recusado no commit.
- `dst in PREFIXO` é o prefixo e os mais específicos; `dst in LISTA` casa as entradas da lista no
  formato prefix-list (`10.0.0.0/8` exato, `10.0.0.0/8 le 24`, `0.0.0.0/0 ge 25`).
- `bgp-as-path` usa a expressão regular do FRR/Cisco (`_` é separador ou ponta do caminho). A do
  RouterOS v7 é outra (o próprio manual avisa que não é compatível com a do v6 nem com a da
  Cisco); escolhemos a que o FRR roda, para a prévia e o roteador concordarem. Barra invertida não
  é aceita (POSIX e Rust discordam dos escapes).
- Entrada hostil: texto até 4 096 caracteres, 2 048 palavras, 32 níveis; erro com a coluna e "did
  you mean". Proptest de texto aleatório e de texto com cara de regra (nunca entra em pânico).

### O que ficou de fora (e por quê)

- `bgp-med`/`bgp-local-pref` como **condição**: o FRR só compara igualdade, e numa rota recebida o
  LOCAL_PREF ainda não existe na entrada; prometer `>` seria mentir. Marque a rota com community.
- Valores relativos (`set bgp-med +10`): o FRR soma sobre um valor que a rota pode não ter (0 ou
  100, depende do caminho). Fica só o valor absoluto.
- `bgp-ext-communities`, `rpki` (G3.2c), `distance`, `bgp-path-len`: a mensagem de erro diz
  qual usar no lugar.

## Como vira FRR

Cada chain vira um route-map `CR-<chain>`; cada condição, uma prefix-list, AS-path access-list ou
community-list com nome tirado do conteúdo (`CR-P-<hash>`, `CR-C-<hash>`; listas nomeadas viram
`CR-L-<nome>`). Tudo com prefixo `CR-`: o que o operador digitou à mão no FRR fica intacto.

O programa (if/else, `&&`, `||`, `not`, `jump`) vira entradas com saltos só para a frente:

- teste = `permit` + um `match` + `on-match goto <então>`; se o match falha, o FRR tenta a
  próxima entrada, que é o "senão";
- `a && b`, `a || b`, `not a` = testes que saltam uns por cima dos outros (curto-circuito);
- ação = `permit` + `set …` + `on-match next`; `accept` = `permit` que encerra; `reject` = `deny`;
- `jump` é **expandido** no lugar: o `call` do FRR não distingue "a chain chamada aceitou" de
  "caiu no fim dela", e o RouterOS distingue;
- as entradas começam na sequência 10 (1–9 ficam para o prelúdio do RPKI da G3.2c, `frr::render_with`);
- fim da chain = `deny 65535` (sequência fixa: acrescentar uma regra não renumera o fim).

Depois, reescritas encolhem o mapa: um teste cujo destino sempre termina igual vira essa entrada
(`if (dst in X) { reject }` é um `deny` só), ações se fundem com a entrada seguinte, salto para a
próxima entrada vira `next`, entradas inalcançáveis saem. **Prova:** o proptest
`frr_render_runs_like_the_policy` gera regras e rotas aleatórias e roda as duas coisas — o
avaliador (`eval`) e um modelo da semântica de route-map do FRR (`lib/routemap.c`) sobre o
render — e exige o mesmo veredito e os mesmos atributos (20 000 casos verdes, **medido**).

A forma é a canônica do FRR 10.7.1 (conferida na VM: `ge 25` volta `ge 25`, community-list volta
ordenada por valor, nomes bem conhecidos como `blackhole`): um segundo sync não digita nada.

## RFC 8212

O FRR (`frr defaults traditional`) liga `bgp ebgp-requires-policy` e o render não desliga. Uma
conexão eBGP sem `input_filter` não aceita rota; sem `output_filter`, não envia. A janela avisa em
cima, o modal da conexão diz o que falta, e `routing.filter.status` lista as conexões. Para aceitar
tudo de propósito: uma chain com a regra `accept`.

## Prévia e impacto no commit

- `routing.filter.preview {chain?, connection?, direction}` roda a chain **pendente** e a **em
  vigor** sobre as mesmas rotas: quantas passam, quantas caem, quais mudam de destino e quais
  mudam de atributo, com as primeiras de cada tipo listadas.
- `routing.filter.impact {}` faz isso para cada conexão e direção que o commit mexe: "this change
  withdraws N prefixes announced to AS X".
- **Rotas:** no laboratório virtual, uma amostra reproduzível por conexão (5 000 rotas com forma
  de tabela completa, bogons, rota padrão e ~2 % de prefixos longos demais); com o FRR, as rotas
  de verdade, lidas pela thread do FRR do daemon fora do lock (a primeira pergunta volta
  `pending`, a seguinte tem a tabela; guardada 30 s).
- **Recebidas:** o FRR só guarda o que chegou antes da política com `soft-reconfiguration
  inbound` — o parâmetro `keep_received` da conexão, ligado por padrão (o RouterOS também guarda as
  rejeitadas). O JSON `received-routes` do FRR 10.7.1 não traz communities, e o `detail` só as
  traz das rotas que a política aceitou (**medido** na VM); as outras chegam sem communities e a
  prévia diz quantas (`partial`).

## Pesquisa

- **MikroTik RouterOS v7** — [Route Selection and Filters](https://help.mikrotik.com/docs/spaces/ROS/pages/74678285/Route+Selection+and+Filters):
  linguagem `if (…) { … } else { … }`, `&&`/`||`/`not`, matchers `dst`, `dst-len`, `protocol`,
  `bgp-as-path`, `bgp-communities` (`includes`, `any`, `equal`, `-list`), ações `accept`,
  `reject`, `return`, `jump`, `set`, `append`, `delete`; **ação padrão reject**; rejeitadas ficam
  guardadas como "filtered"; `community-list`, `community-large-list`, `num-list`. Não tem prévia.
- **Juniper Junos** — `policy-statement` com `term … from … then`, `route-filter` com
  `orlonger`/`upto`/`prefix-length-range`, `community` com regex, `as-path`; várias políticas em
  cadeia; **`test policy`** mostra quais rotas da tabela uma política aceita — a inspiração da
  nossa prévia (que vai além: compara com a política em vigor antes do commit).
- **Cisco** — IOS-XE `route-map` (sequências, `continue`, `match`/`set`), `ip prefix-list` com
  `ge`/`le`, `ip community-list standard|expanded`, `ip as-path access-list`. IOS-XR **RPL**
  (`route-policy` com `if … then … else … endif`, parecida com a do RouterOS) e eBGP sem política
  descarta tudo por padrão (RFC 8212).
- **Nokia** — SR Linux `routing-policy` com `prefix-set`, `community-set`, `as-path-set`,
  `statement` e `default-action`; SR OS `policy-options`.
- **FRR** — `route-map` com `on-match goto|next`, `call`, `continue`; `bgp ebgp-requires-policy`
  (RFC 8212) ligado por padrão; `soft-reconfiguration inbound`; `show bgp … received-routes`.
- **RFCs:**
  - RFC 4271 §9.1 (Phase 1/3: política de entrada e de saída; a rota rejeitada não entra na
    decisão) e §9.1.2 (laço de AS: o bgpd descarta antes de qualquer política). Atualizada por RFC
    4724, 6286, 6608, 6793, 7606, 7607, 7705, **8212**, 8654, 9072, 9687, 9774; sem errata que
    mude o que usamos.
  - **RFC 8212** (atualiza a 4271): eBGP sem política não aceita nem anuncia. Sem errata.
  - **RFC 1997** (communities; well-known `NO_EXPORT`, `NO_ADVERTISE`, `NO_EXPORT_SUBCONFED`).
    Atualizada por RFC 7606 e **RFC 8642** (as well-known se manipulam na política como qualquer
    outra: é o que fazemos). Errata 3889 e 3890 (editoriais, held), 4576 (rejeitada).
  - **RFC 8092** (large communities, 3 × 32 bits). Errata 4962 (editorial, held).
  - RFC 7454 (BCP 194, operação e segurança do BGP): filtros de bogons e de tamanho de prefixo
    (/24 IPv4, /48 IPv6) são os exemplos da documentação e da amostra.
- **Adotado:** a sintaxe e a ação padrão do RouterOS; a regex do FRR/Cisco; prefix-list no
  formato do FRR/Cisco; a prévia "o que passa" do Junos, estendida para comparar com a política em
  vigor e para medir o impacto no commit; guardar as rotas recebidas (RouterOS, FRR
  `soft-reconfiguration`).
- **Melhorias propostas que entraram:** prévia antes do commit com a tabela real; impacto por
  conexão ("retira N prefixos anunciados ao AS X"); RFC 8212 com aviso que diz o que fazer;
  erro com coluna e "did you mean"; listas em uso não somem; prova automática de que o render do
  FRR roda igual à prévia.
- **Ficou para depois:** ver a seção "Gaps" no `docs/changes/G3.2b.md`.
