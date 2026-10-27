//! Portuguese labels and explanations of IP › Firewall's tabs (G2.1c),
//! sorted by key.

/// Labels: (English, Portuguese). The tab names are RouterOS'.
pub(super) const LABELS: &[(&str, &str)] = &[
    ("Address Lists", "Address Lists"),
    ("Chain", "Chain"),
    ("Connections", "Connections"),
    ("Decided by", "Decidido por"),
    ("Diff", "Diff"),
    ("Dst. Address", "Dst. Address"),
    ("Dst. Port", "Dst. Port"),
    ("Duration", "Duração"),
    ("Filter Rules", "Filter Rules"),
    ("In. Interface", "In. Interface"),
    ("Leaves as", "Sai como"),
    ("Mangle", "Mangle"),
    ("Marks real packets that match the filter (at most 20 a second, for a limited time) and shows their way through the kernel.", "Marca os pacotes reais que casam com o filtro (no máximo 20 por segundo, por tempo limitado) e mostra o caminho deles no kernel."),
    ("Max Events", "Máx. eventos"),
    ("NAT", "NAT"),
    ("No rule decided: the chain policies (accept) let it through.", "Nenhuma regra decidiu: as políticas das chains (accept) deixaram passar."),
    ("Pending config changes", "Mudanças de config pendentes"),
    ("Protocol", "Protocol"),
    ("Raw", "Raw"),
    ("Result", "Resultado"),
    ("Routing decision", "Decisão de rota"),
    ("Rule", "Regra"),
    ("Show whole table", "Mostrar a tabela inteira"),
    ("Src. Address", "Src. Address"),
    ("Src. Port", "Src. Port"),
    ("Start", "Iniciar"),
    ("State", "State"),
    ("Stop", "Parar"),
    ("Test", "Test"),
    ("The kernel already holds what the candidate config renders.", "O kernel já tem o que a config candidata gera."),
    ("Trace real packets", "Rastrear pacotes reais"),
    ("Which way would this packet take? Nothing is sent: the rules are evaluated as the kernel would.", "Que caminho este pacote faria? Nada é enviado: as regras são avaliadas como o kernel faria."),
    ("Zones", "Zones"),
    ("lines of nftables change at the next commit", "linhas do nftables mudam no próximo commit"),
    ("no change", "sem mudança"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "firewall.col.bytes",
        "## Bytes\n\nBytes que a regra casou, lidos do `counter` do kernel enquanto esta janela está aberta (a cada 2 s). Não ficam salvos: recomeçam quando o roteador reinicia; um commit não os zera.",
    ),
    (
        "firewall.col.last-used",
        "## Last Used\n\nHá quanto tempo a regra casou um pacote pela última vez. `— (3 d)`: nenhuma vez desde que os contadores começaram a ser lidos. Selo âmbar **stale**: sem uso há 30 dias — talvez uma regra que ninguém precisa mais (confira antes de remover: algumas regras esperam eventos raros).",
    ),
    (
        "firewall.col.packets",
        "## Packets\n\nPacotes que a regra casou (o `packets` do RouterOS), ao vivo do kernel: uma leitura netlink da tabela inteira a cada 2 s enquanto a janela está aberta. **Reset Counters** zera o que aparece (as regras selecionadas, ou todas).",
    ),
    (
        "firewall.col.rate",
        "## Rate\n\nPacotes por segundo no último intervalo de leitura (2 s).",
    ),
    (
        "firewall.tab.address-list",
        "## Address Lists\n\nConjuntos nomeados de endereços que as regras usam (`src-address-list=blocked`). Entradas com prazo (timeout) são dinâmicas: não vão para a config e expiram sozinhas.",
    ),
    (
        "firewall.tab.connections",
        "## Connections\n\nA tabela de conexões do kernel (conntrack): o que o firewall sabe de cada fluxo, o NAT dele e quanto tempo falta.",
    ),
    (
        "firewall.tab.diff",
        "## Diff\n\nA tabela `inet corerouter` do nftables como o próximo **commit** vai carregá-la, contra o que o kernel tem agora: linhas `+` entram, linhas `-` saem. Ao lado, as mudanças de config pendentes (`config.diff`). No modo imediato não há nada pendente: o diff fica vazio.",
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
        "firewall.tab.test",
        "## Test\n\n**Testador de pacotes**: descreva um pacote e veja o caminho dele pela raw, mangle, NAT, decisão de rota e filter, chain por chain, e a regra que decide. Nada é enviado. Suposições: sem marcas, limites não estourados, address lists só com as entradas do roteador.\n\n**Rastrear pacotes reais**: marca os pacotes reais que casam com um filtro (`meta nftrace`, no máximo 20/s) por um tempo limitado e mostra o caminho que cada um fez no kernel. Como o `packet-trace` do Junos; o RouterOS não tem.",
    ),
    (
        "firewall.tab.zones",
        "## Zones\n\nO modo simples: uma matriz dizendo que zona (lista de interfaces ou o roteador) pode abrir conexões para qual. Ela gera um bloco de regras no filter.",
    ),
    (
        "firewall.test.dst",
        "## Dst. Address\n\nEndereço de destino (um endereço do roteador: chain input).",
    ),
    (
        "firewall.test.dst_port",
        "## Dst. Port\n\nPorta de destino (padrão 80).",
    ),
    (
        "firewall.test.in_interface",
        "## In. Interface\n\nPor onde entra. Vazio: o próprio roteador envia (chain output).",
    ),
    (
        "firewall.test.protocol",
        "## Protocol\n\ntcp, udp, icmp, icmpv6 ou um número (padrão tcp).",
    ),
    (
        "firewall.test.src",
        "## Src. Address\n\nEndereço de origem do pacote.",
    ),
    (
        "firewall.test.src_port",
        "## Src. Port\n\nPorta de origem (padrão 40000).",
    ),
    (
        "firewall.test.state",
        "## State\n\nEstado da conexão para o conntrack (padrão new). As chains de NAT só veem `new`.",
    ),
    (
        "firewall.trace.dst",
        "## Dst. Address\n\nRastreia pacotes para este endereço ou prefixo.",
    ),
    (
        "firewall.trace.duration",
        "## Duration\n\nSegundos, de 1 a 300 (padrão 60). O rastreio termina sozinho.",
    ),
    (
        "firewall.trace.in_interface",
        "## In. Interface\n\nSó pacotes que chegam por aqui (aí os pacotes que o roteador envia não são rastreados).",
    ),
    (
        "firewall.trace.max_events",
        "## Max Events\n\nPara depois de tantos eventos do kernel (padrão 1000, no máximo 10000). Cada pacote gera um evento por regra que encontra.",
    ),
    (
        "firewall.trace.port",
        "## Dst. Port\n\nSó esta porta de destino (precisa de tcp, udp, sctp ou udp-lite).",
    ),
    (
        "firewall.trace.protocol",
        "## Protocol\n\nSó este protocolo.",
    ),
    (
        "firewall.trace.src",
        "## Src. Address\n\nRastreia pacotes vindos deste endereço ou prefixo.",
    ),
];
