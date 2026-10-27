//! Portuguese labels and explanations of IP › Firewall's tabs (G2.1c),
//! sorted by key.

/// Labels: (English, Portuguese). The tab names are RouterOS'.
pub(super) const LABELS: &[(&str, &str)] = &[
    ("Address Lists", "Address Lists"),
    ("Connections", "Connections"),
    ("Filter Rules", "Filter Rules"),
    ("Mangle", "Mangle"),
    ("NAT", "NAT"),
    ("Raw", "Raw"),
    ("Zones", "Zones"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "firewall.tab.address-list",
        "## Address Lists\n\nConjuntos nomeados de endereços que as regras usam (`src-address-list=blocked`). Entradas com prazo (timeout) são dinâmicas: não vão para a config e expiram sozinhas.",
    ),
    (
        "firewall.tab.connections",
        "## Connections\n\nA tabela de conexões do kernel (conntrack): o que o firewall sabe de cada fluxo, o NAT dele e quanto tempo falta.",
    ),
    (
        "firewall.tab.filter",
        "## Filter Rules\n\nO que pode passar: chain `input` (para o roteador), `forward` (atravessando) e `output` (saindo dele). A primeira regra que decide vale; nenhuma decide = aceita.",
    ),
    (
        "firewall.tab.mangle",
        "## Mangle\n\nMarca conexões, pacotes e roteamento (roteamento por política, filas). Não decide nada sozinha, a não ser com `passthrough=no`.",
    ),
    (
        "firewall.tab.nat",
        "## NAT\n\n`srcnat` troca a origem (masquerade para a internet); `dstnat` troca o destino (redirecionamento de porta).",
    ),
    (
        "firewall.tab.raw",
        "## Raw\n\nRegras que rodam **antes do rastreamento de conexões** (conntrack), nas chains `prerouting` (tudo que chega) e `output` (o que o roteador envia). Ações: `accept`, `drop`, `notrack`, `jump`, `return`, `log`, `passthrough` e as de address-list.\n\n- **drop** aqui custa menos que no filter: o pacote nunca vira conexão, então uma inundação com origem falsa não enche a tabela do conntrack.\n- **notrack**: o pacote pula o conntrack; o filter passa a vê-lo como `connection-state=untracked` (aceite `untracked` lá, senão ele cai nas suas regras de drop). Útil para tráfego sem estado em alta taxa (DNS de um resolvedor, BGP de um route server).\n\n**Cuidado:** não há `connection-state`, `connection-mark`, `connection-nat-state` nem `routing-mark` (a conexão ainda não existe). Um `notrack` em `output` quebra as conexões do próprio roteador (as respostas chegam sem rastreio). O NAT não vale para pacotes sem rastreio.\n\nModelo pronto: **Drop Bogons Before Conntrack**. É o `/ip firewall raw` do RouterOS; no nftables, prioridade `raw` (-300).",
    ),
    (
        "firewall.tab.zones",
        "## Zones\n\nO modo simples: uma matriz dizendo que zona (lista de interfaces ou o roteador) pode abrir conexões para qual. Ela gera um bloco de regras no filter.",
    ),
];
