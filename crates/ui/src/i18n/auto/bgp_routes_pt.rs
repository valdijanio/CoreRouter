//! Portuguese labels and explanations of Routing › BGP Routes and "Why
//! this route?" (G3.2c), each sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"Accepted routes only: this neighbor keeps no Adj-RIB-In (no RPKI drop on it), so refused routes are not known."##, r##"Só as rotas aceitas: este vizinho não guarda a Adj-RIB-In (sem descarte RPKI nele), então as recusadas não são conhecidas."##),
    (r##"Advertised"##, r##"Anunciadas"##),
    (r##"Ask Again"##, r##"Perguntar de novo"##),
    (r##"BGP has no path to this prefix."##, r##"O BGP não tem caminho para este prefixo."##),
    (r##"Choose a BGP connection to see its routes."##, r##"Escolha uma conexão BGP para ver as rotas dela."##),
    (r##"Chosen"##, r##"Escolhido"##),
    (r##"Connection"##, r##"Conexão"##),
    (r##"History"##, r##"Histórico"##),
    (r##"Lost At"##, r##"Perdeu em"##),
    (r##"No route matches."##, r##"Nenhuma rota corresponde."##),
    (r##"No session went down since the daemon started."##, r##"Nenhuma sessão caiu desde que o daemon subiu."##),
    (r##"Order:"##, r##"Ordem:"##),
    (r##"RPKI"##, r##"RPKI"##),
    (r##"Read Again"##, r##"Ler de novo"##),
    (r##"Reading the routes from the routing daemon… a full table takes a few seconds."##, r##"Lendo as rotas do daemon de roteamento… uma tabela completa leva alguns segundos."##),
    (r##"Received"##, r##"Recebidas"##),
    (r##"Search"##, r##"Buscar"##),
    (r##"The daemon chose differently from this step-by-step comparison (an option such as deterministic-med or multipath decided)."##, r##"O daemon escolheu diferente desta comparação passo a passo (decidiu uma opção como deterministic-med ou multipath)."##),
    (r##"Why this route?"##, r##"Por que essa rota?"##),
    (r##"against"##, r##"contra"##),
    (r##"as-path-length"##, r##"tamanho do AS path"##),
    (r##"choose…"##, r##"escolha…"##),
    (r##"cluster-length"##, r##"cluster list"##),
    (r##"confed-peer-type"##, r##"confederação"##),
    (r##"down"##, r##"caiu"##),
    (r##"equal"##, r##"empate"##),
    (r##"filtered"##, r##"filtrada"##),
    (r##"filtered only"##, r##"só filtradas"##),
    (r##"flap"##, r##"oscilou"##),
    (r##"igp-metric"##, r##"métrica IGP"##),
    (r##"invalid"##, r##"inválida"##),
    (r##"local-pref"##, r##"local-pref"##),
    (r##"local-route"##, r##"rota local"##),
    (r##"med"##, r##"MED"##),
    (r##"neighbor-address"##, r##"endereço do vizinho"##),
    (r##"not-usable"##, r##"inutilizável"##),
    (r##"of"##, r##"de"##),
    (r##"older-path"##, r##"caminho mais antigo"##),
    (r##"origin"##, r##"origin"##),
    (r##"peer-type"##, r##"eBGP × iBGP"##),
    (r##"prefix or address"##, r##"prefixo ou endereço"##),
    (r##"read"##, r##"lida há"##),
    (r##"router-id"##, r##"router-id"##),
    (r##"routes"##, r##"rotas"##),
    (r##"stale"##, r##"obsoleto"##),
    (r##"unknown"##, r##"desconhecida"##),
    (r##"unverified"##, r##"não verificada"##),
    (r##"up"##, r##"subiu"##),
    (r##"valid"##, r##"válida"##),
    (r##"weight"##, r##"weight"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"bgp_routes.as_path"##, r##"## O que é
Os ASes que a rota atravessou, o vizinho primeiro e a origem por último. `{…}` é um AS_SET (agregação), `(…)` segmentos de confederação."##),
    (r##"bgp_routes.communities"##, r##"## O que é
As communities da rota (RFC 1997, `asn:valor`) e as large communities (RFC 8092, `a:b:c`): etiquetas que guiam as políticas."##),
    (r##"bgp_routes.explain"##, r##"## O que é
Todos os caminhos que o roteador tem para este prefixo, o escolhido e, para cada outro, o passo da decisão BGP que o deixou para trás (RFC 4271 §9.1, na ordem em que o bgpd do FRR compara). Clique num passo para ler o que ele compara.

Quando a escolha do daemon não se reproduz passo a passo (deterministic-med, multipath), a janela avisa."##),
    (r##"bgp_routes.explain.lost_at"##, r##"## O que é
O passo em que este caminho perdeu para o melhor, com os dois valores comparados (o vencedor primeiro). Vermelho: pela nossa comparação este caminho deveria ter vencido (veja o aviso no topo)."##),
    (r##"bgp_routes.explain.path"##, r##"## O que é
O vizinho (a conexão dele) de onde o caminho veio; `best` marca o escolhido."##),
    (r##"bgp_routes.history.connection"##, r##"## O que é
A conexão BGP (ou o endereço do vizinho, numa sessão do FRR que nenhuma conexão nomeia)."##),
    (r##"bgp_routes.history.event"##, r##"## O que é
`down`: a sessão saiu de Established. `up`: voltou. `flap`: caiu e voltou entre duas amostras (o contador de quedas andou)."##),
    (r##"bgp_routes.history.reason"##, r##"## O que é
A última NOTIFICATION enviada ou recebida (RFC 4271 §6, subcódigos de Cease da RFC 4486) ou o motivo do daemon (hold timer expirou, limite de prefixos, reset administrativo)."##),
    (r##"bgp_routes.history.time"##, r##"## O que é
Quando a mudança foi vista (a amostra do estado do daemon de roteamento, a cada 2 s)."##),
    (r##"bgp_routes.history.uptime"##, r##"## O que é
Quanto tempo a sessão estava de pé antes de cair."##),
    (r##"bgp_routes.local_pref"##, r##"## O que é
LOCAL_PREF: a preferência do AS entre as saídas; o maior vence. Vazio: não veio (eBGP), conta 100."##),
    (r##"bgp_routes.med"##, r##"## O que é
MULTI_EXIT_DISC: a dica do vizinho sobre qual dos links dele usar; o menor vence entre rotas do mesmo AS vizinho."##),
    (r##"bgp_routes.next_hop"##, r##"## O que é
Para onde vai o tráfego do prefixo (o NEXT_HOP do BGP)."##),
    (r##"bgp_routes.origin"##, r##"## O que é
O atributo ORIGIN: `igp`, `egp` ou `incomplete` (redistribuída)."##),
    (r##"bgp_routes.origin_as"##, r##"## O que é
O AS que originou a rota: o último AS do AS path (RFC 6811 §2). O nosso AS nas nossas rotas; nenhum quando o caminho termina num AS_SET."##),
    (r##"bgp_routes.prefix"##, r##"## O que é
O prefixo de destino da rota."##),
    (r##"bgp_routes.rpki"##, r##"## O que é
O estado da validação de origem RPKI (RFC 6811):

- `valid`: uma ROA cobre o prefixo, aceita o tamanho dele e nomeia o AS de origem;
- `invalid`: ROAs o cobrem mas nenhuma aceita esta origem ou este tamanho (sequestro ou erro de configuração); é descartada, salvo se a conexão disser `accept`;
- `unknown`: nenhuma ROA o cobre (boa parte da tabela hoje);
- `unverified`: nenhum validador está em sincronia, então nada se pode dizer."##),
    (r##"bgp_routes.rpki_share"##, r##"## O que é
A porcentagem de cada estado RPKI entre as rotas desta conexão. Uma tabela completa hoje tem por volta de metade válida e metade desconhecida, com inválidas bem abaixo de 1 %; muita inválida aponta vazamento ou sequestro."##),
    (r##"bgp_routes.search"##, r##"## Como buscar
- **Prefixo**: um prefixo traz ele e toda rota dentro dele (`orlonger`); um endereço traz as rotas que o contêm (`covering`).
- **AS path**: números de AS em sequência; `^` prende no vizinho, `$` na origem: `^64500`, `13335$`, `64500 3356`.
- **Community**: `65000:100`, `65000:1:2` ou um nome conhecido (`no-export`).
- **RPKI** e **só filtradas** estreitam a lista.

A busca roda no roteador, na tabela inteira, e a resposta vem uma página por vez."##),
    (r##"bgp_routes.status"##, r##"## O que é
`best`: o daemon escolheu este caminho para o prefixo. `filtered`: recebida mas recusada pela política de entrada (rota RPKI inválida, um filtro)."##),
    (r##"bgp_routes.step.as-path-length"##, r##"## O passo
**Tamanho do AS_PATH** (RFC 4271 §9.1.2.2 a): menos ASes vence. Um AS_SET conta como um; segmentos de confederação não contam.

Prepend (repetir o próprio AS) é o jeito de um vizinho fazer um caminho perder aqui."##),
    (r##"bgp_routes.step.cluster-length"##, r##"## O passo
**Tamanho da CLUSTER_LIST** (RFC 4456 §9): vence a rota refletida por menos refletores."##),
    (r##"bgp_routes.step.confed-peer-type"##, r##"## O passo
Numa confederação, uma rota de outro AS membro vence uma do nosso próprio AS membro."##),
    (r##"bgp_routes.step.igp-metric"##, r##"## O passo
**Custo IGP até o próximo salto** (RFC 4271 §9.1.2.2 e): vence a saída mais próxima (hot-potato)."##),
    (r##"bgp_routes.step.local-pref"##, r##"## O passo
**LOCAL_PREF** (RFC 4271 §9.1.1): o maior vence. É o jeito iBGP de dizer qual saída o AS prefere; sem valor conta 100.

Use para escolher o trânsito preferido: suba o local-pref das rotas dele na política de entrada."##),
    (r##"bgp_routes.step.local-route"##, r##"## O passo
Uma rota originada aqui (network, redistribute, aggregate) vence uma recebida."##),
    (r##"bgp_routes.step.med"##, r##"## O passo
**MED** (RFC 4271 §9.1.2.2 c): o menor vence, comparado só entre rotas do mesmo AS vizinho (salvo always-compare-med). Sem MED conta 0.

É o pedido do vizinho sobre por qual dos links dele entrar."##),
    (r##"bgp_routes.step.neighbor-address"##, r##"## O passo
**Endereço do vizinho** (RFC 4271 §9.1.2.2 g): o último desempate, vence o menor endereço."##),
    (r##"bgp_routes.step.not-usable"##, r##"## O passo
Um caminho que o daemon não pode usar (próximo salto inalcançável, laço de AS, recusado) não concorre (RFC 4271 §9.1.2)."##),
    (r##"bgp_routes.step.older-path"##, r##"## O passo
Entre duas rotas eBGP ainda empatadas, fica a já escolhida: a mais nova não a desloca, o que evita oscilação (FRR, Cisco)."##),
    (r##"bgp_routes.step.origin"##, r##"## O passo
**ORIGIN** (RFC 4271 §9.1.2.2 b): IGP vence EGP, que vence incomplete (rota redistribuída)."##),
    (r##"bgp_routes.step.peer-type"##, r##"## O passo
**eBGP antes de iBGP** (RFC 4271 §9.1.2.2 d): uma rota aprendida de outro AS vence a aprendida dentro do nosso."##),
    (r##"bgp_routes.step.router-id"##, r##"## O passo
**BGP Identifier** (RFC 4271 §9.1.2.2 f): o menor router-id vence; numa rota refletida conta o ORIGINATOR_ID (RFC 4456 §9)."##),
    (r##"bgp_routes.step.stale"##, r##"## O passo
Uma rota guardada de uma sessão que está reiniciando (graceful restart, RFC 4724) perde para uma fresca."##),
    (r##"bgp_routes.step.weight"##, r##"## O passo
O **weight** é local deste roteador (FRR, Cisco): o maior vence. Nunca vai aos vizinhos. O CoreRouter só o define por política."##),
    (r##"bgp_routes.tab.advertised"##, r##"## O que é
As rotas que mandamos a este vizinho, depois da política de saída (o `advertised` do RouterOS, o `advertising-protocol` do Junos)."##),
    (r##"bgp_routes.tab.history"##, r##"## O que é
Quando cada sessão caiu e voltou, por quê (a última NOTIFICATION) e quanto tempo estava de pé. Fica na memória (64 por sessão) até o daemon reiniciar; uma queda e volta entre duas amostras de 2 s aparece como `flap`."##),
    (r##"bgp_routes.tab.received"##, r##"## O que é
As rotas que este vizinho mandou. Quando o CoreRouter guarda a Adj-RIB-In dele (guarda em toda conexão que descarta inválidas pelo RPKI), a lista é a de **antes** da política de entrada, e as recusadas aparecem com o selo `filtered`; senão, só as aceitas.

## Cuidado
Guardar a Adj-RIB-In custa memória (uma cópia dos atributos por rota recebida); é o que permite ao FRR revalidar quando as ROAs mudam."##),
];
