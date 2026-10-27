//! Portuguese labels and explanations of the Routing › Filters window
//! (G3.2b), each sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"#"##, r##"#"##),
    (r##"(chain only)"##, r##"(só a chain)"##),
    (r##"(the connection's)"##, r##"(a da conexão)"##),
    (r##"AS Path"##, r##"Caminho AS"##),
    (r##"Actions"##, r##"Ações"##),
    (r##"Before"##, r##"Antes"##),
    (r##"Chain"##, r##"Chain"##),
    (r##"Change"##, r##"Mudança"##),
    (r##"Commit impact"##, r##"Impacto do commit"##),
    (r##"Communities"##, r##"Communities"##),
    (r##"Community List"##, r##"Lista de communities"##),
    (r##"Community Lists"##, r##"Listas de communities"##),
    (r##"Connection"##, r##"Conexão"##),
    (r##"Direction"##, r##"Direção"##),
    (r##"Entries"##, r##"Entradas"##),
    (r##"Filter Rule"##, r##"Regra de filtro"##),
    (r##"Filters"##, r##"Filtros"##),
    (r##"IPv4"##, r##"IPv4"##),
    (r##"IPv6"##, r##"IPv6"##),
    (r##"Input Filter"##, r##"Filtro de entrada"##),
    (r##"Keep Received"##, r##"Manter recebidas"##),
    (r##"Large"##, r##"Large"##),
    (r##"Matches"##, r##"Condições"##),
    (r##"Move Down"##, r##"Descer"##),
    (r##"Move Up"##, r##"Subir"##),
    (r##"New Community List"##, r##"Nova lista de communities"##),
    (r##"New Community List…"##, r##"Nova lista de communities…"##),
    (r##"New Filter Rule"##, r##"Nova regra de filtro"##),
    (r##"New Prefix List"##, r##"Nova lista de prefixos"##),
    (r##"New Prefix List…"##, r##"Nova lista de prefixos…"##),
    (r##"New Rule…"##, r##"Nova regra…"##),
    (r##"No rules yet. An eBGP connection without a chain accepts and sends nothing (RFC 8212): add rules, then set the connection's Input Filter and Output Filter."##, r##"Nenhuma regra ainda. Uma conexão eBGP sem chain não aceita nem envia nada (RFC 8212): crie as regras e depois escolha o Filtro de entrada e o Filtro de saída da conexão."##),
    (r##"Normal"##, r##"Normais"##),
    (r##"Output Filter"##, r##"Filtro de saída"##),
    (r##"Pick a connection or a chain and run the preview: it shows which routes pass, which are rejected and what changes against the policy in force."##, r##"Escolha uma conexão ou uma chain e rode a prévia: ela mostra quais rotas passam, quais são rejeitadas e o que muda em relação à política em vigor."##),
    (r##"Prefix"##, r##"Prefixo"##),
    (r##"Prefix List"##, r##"Lista de prefixos"##),
    (r##"Prefix Lists"##, r##"Listas de prefixos"##),
    (r##"Preview"##, r##"Prévia"##),
    (r##"Reading the routes from FRR…"##, r##"Lendo as rotas do FRR…"##),
    (r##"Rule"##, r##"Regra"##),
    (r##"Rules"##, r##"Regras"##),
    (r##"Run Preview"##, r##"Rodar prévia"##),
    (r##"Used By"##, r##"Usada por"##),
    (r##"Verdict"##, r##"Resultado"##),
    (r##"Which routes the chain lets through"##, r##"Quais rotas a chain deixa passar"##),
    (r##"accepted"##, r##"aceitas"##),
    (r##"attributes change"##, r##"mudam atributos"##),
    (r##"chains"##, r##"chains"##),
    (r##"changed"##, r##"alteradas"##),
    (r##"in"##, r##"entrada"##),
    (r##"lists"##, r##"listas"##),
    (r##"newly accepted"##, r##"passam a ser aceitas"##),
    (r##"newly rejected"##, r##"passam a ser rejeitadas"##),
    (r##"out"##, r##"saída"##),
    (r##"rejected"##, r##"rejeitadas"##),
    (r##"routes"##, r##"rotas"##),
    (r##"routes came without their communities (FRR shows them only for accepted routes)"##, r##"rotas vieram sem as communities (o FRR só as mostra para rotas aceitas)"##),
    (r##"rules"##, r##"regras"##),
    (r##"source"##, r##"fonte"##),
    (r##"threads"##, r##"threads"##),
    (r##"with errors"##, r##"com erro"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"bgp.param.input_filter"##, r##"## O que é
`input.filter` do RouterOS: a chain do `/routing filter` por onde passam as rotas recebidas deste vizinho. eBGP sem ela não aceita nada (RFC 8212)."##),
    (r##"bgp.param.keep_received"##, r##"## O que é
Guarda as rotas que o vizinho manda antes da chain de entrada (`soft-reconfiguration inbound` do FRR; o RouterOS também guarda as rejeitadas): a prévia dos filtros roda nelas, e uma chain nova vale sem pedir as rotas de novo ao vizinho.

## Custo
Mais uma cópia de cada rota recebida na memória. Vazio: sim."##),
    (r##"bgp.param.output_filter"##, r##"## O que é
`output.filter-chain` do RouterOS: a chain por onde passam as rotas enviadas a este vizinho. eBGP sem ela não envia nada (RFC 8212)."##),
    (r##"filter.community_list"##, r##"## O que é
Uma lista de communities com nome, normais e large."##),
    (r##"filter.community_list.communities"##, r##"## O que é
Communities normais (RFC 1997: `65000:100`, ou `no-export`, `no-advertise`, `blackhole`, `graceful-shutdown`…) e large (RFC 8092: `65000:1:2`)."##),
    (r##"filter.impact"##, r##"## O que é
O que o commit das mudanças pendentes faz com as rotas de cada conexão, medido nas mesmas rotas da Prévia: prefixos que deixam de ser anunciados a (ou aceitos de) um vizinho, novos, e atributos alterados."##),
    (r##"filter.list.name"##, r##"## O que é
O nome da lista, como as regras o escrevem (`dst in NOME`, `any-list NOME`)."##),
    (r##"filter.list.used_by"##, r##"## O que é
As chains cujas regras usam esta lista. Uma lista em uso não pode ser removida nem renomeada."##),
    (r##"filter.prefix_list"##, r##"## O que é
Uma lista de prefixos com nome. Separe as entradas com vírgula ou quebra de linha."##),
    (r##"filter.prefix_list.entries"##, r##"## O que é
Prefixos com uma faixa de tamanho opcional (forma do FRR/Cisco): `10.0.0.0/8` casa só esse prefixo; `10.0.0.0/8 le 24`, ele e os mais específicos até /24; `0.0.0.0/0 ge 25`, qualquer prefixo IPv4 /25 ou maior."##),
    (r##"filter.preview.as_path"##, r##"## O que é
O caminho de AS da rota, o vizinho primeiro."##),
    (r##"filter.preview.before"##, r##"## O que é
O que a política em vigor (a do último commit) faz com a mesma rota. Um resultado diferente é uma mudança que o seu commit causa."##),
    (r##"filter.preview.change"##, r##"## O que é
O que a chain muda na rota: LOCAL_PREF, MED, prepends, communities acrescentadas (+) ou removidas (-)."##),
    (r##"filter.preview.connection"##, r##"## O que é
A conexão BGP cujas rotas entram na prévia, com a chain dela para a direção. Vazio: só a chain, na amostra."##),
    (r##"filter.preview.direction"##, r##"## O que é
`entrada`: as rotas que o vizinho manda, pelo Filtro de entrada. `saída`: as rotas deste roteador, pelo Filtro de saída, antes de serem enviadas."##),
    (r##"filter.preview.prefix"##, r##"## O que é
O prefixo da rota."##),
    (r##"filter.preview.verdict"##, r##"## O que é
O que a chain faz com a rota: aceita ou rejeita."##),
    (r##"filter.rfc8212"##, r##"## O que é
RFC 8212: uma sessão eBGP sem política não aceita nem envia rota nenhuma, para o roteador não vazar nem aceitar uma tabela completa por engano. O FRR impõe isso (`bgp ebgp-requires-policy`).

## O que fazer
Escreva as chains (Regras) e escolha o Filtro de entrada e o Filtro de saída da conexão (Routing › BGP › Conexões, página Filtros). Para aceitar tudo de propósito, uma chain com uma regra `accept`."##),
    (r##"filter.rule"##, r##"## O que é
Uma regra na linguagem do RouterOS v7: `if (dst in bogons || dst-len > 24) { reject }`, `if (bgp-as-path "^64500_") { set bgp-local-pref 200; accept }`. A prévia abaixo conta quantas rotas a chain deixa passar com esta mudança.

## Linguagem
Condições: `dst in|==|!=`, `dst-len`, `afi`, `protocol`, `bgp-as-path` (regex do FRR/Cisco, `_` é separador), `bgp-communities` e `bgp-large-communities` com `includes`, `any`, `equal` (e `-list`). Combinadas com `&&`, `||`, `not` e parênteses. Ações: `accept`, `reject`, `return`, `jump CHAIN`, `set bgp-local-pref|bgp-med|bgp-path-prepend|bgp-communities|bgp-large-communities`, `append …`, `delete …`."##),
    (r##"filter.rule.actions"##, r##"## O que é
O que a regra faz: verde aceita, vermelho rejeita, azul muda um atributo."##),
    (r##"filter.rule.chain"##, r##"## O que é
A chain da regra. As conexões apontam chains no Filtro de entrada e no Filtro de saída; `jump` roda outra chain e volta. Letras, dígitos, `-`, `_`, `.`."##),
    (r##"filter.rule.disabled"##, r##"## O que é
Uma regra desativada fica na lista e é pulada."##),
    (r##"filter.rule.matches"##, r##"## O que é
O que a regra testa (`dst`, `dst-len`, `bgp-as-path`, `bgp-communities`…)."##),
    (r##"filter.rule.position"##, r##"## O que é
A posição da regra: as chains rodam as regras nessa ordem. Mova com as setas."##),
    (r##"filter.rule.rule"##, r##"## O que é
A regra em si. Um erro diz a coluna e sugere a palavra que você quis escrever."##),
    (r##"filter.tab.community_lists"##, r##"## O que é
Listas de communities com nome, para `bgp-communities any-list NOME` (e `includes-list`, `equal-list`) e para `delete bgp-communities NOME`. Communities normais (RFC 1997, `65000:100`, `no-export`) e large (RFC 8092, `65000:1:2`) podem ficar na mesma lista."##),
    (r##"filter.tab.prefix_lists"##, r##"## O que é
Listas de prefixos com nome, para `dst in NOME`. Cada entrada é um prefixo com uma faixa de tamanho opcional: `10.0.0.0/8` (só ele), `10.0.0.0/8 le 24`, `0.0.0.0/0 ge 25`."##),
    (r##"filter.tab.preview"##, r##"## O que é
Quais rotas uma chain deixa passar, nas rotas de uma conexão: no laboratório virtual, uma amostra reproduzível (formato de tabela completa, mais bogons, rota padrão e prefixos longos demais); com o FRR, as rotas que o vizinho mandou de verdade (entrada) ou as melhores rotas deste roteador (saída). As mudanças pendentes são comparadas com a política em vigor."##),
    (r##"filter.tab.rules"##, r##"## O que é
As regras do `/routing filter` (RouterOS v7), em ordem. Cada regra pertence a uma chain; uma conexão BGP passa as rotas recebidas pela chain do Filtro de entrada e as enviadas pela do Filtro de saída. As regras rodam de cima para baixo; `accept` e `reject` encerram a chain, e a rota que nenhuma regra aceita é rejeitada."##),
];
