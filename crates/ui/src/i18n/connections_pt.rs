//! Portuguese labels of IP › Firewall › Connections (G2.2), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("Bytes", "Bytes"),
    ("Cancel", "Cancelar"),
    ("Clear", "Limpar"),
    ("Connection Tracking", "Rastreamento de conexões"),
    ("Connection table", "Tabela de conexões"),
    ("Conns", "Conexões"),
    ("Dst.", "Destino"),
    ("Dst. Address", "End. destino"),
    ("Filter by this source", "Filtrar por esta origem"),
    ("Flags", "Flags"),
    ("Generic Timeout", "Timeout genérico"),
    ("ICMP Timeout", "Timeout ICMP"),
    ("Kill", "Derrubar"),
    ("Kill matching", "Derrubar as filtradas"),
    ("Max Entries", "Máximo de entradas"),
    ("NAT", "NAT"),
    ("Pause", "Pausar"),
    ("Ports", "Portas"),
    ("Protocol", "Protocolo"),
    ("Remove the selected connections from the table", "Tira as conexões selecionadas da tabela"),
    ("Seconds or 1d, 5m. Kept as System › Tuning parameters.", "Segundos ou 1d, 5m. Guardados como parâmetros de System › Tuning."),
    ("Select connections first", "Selecione conexões primeiro"),
    ("Set a filter first", "Defina um filtro primeiro"),
    ("Since boot: connections the kernel could not create or kept out", "Desde o boot: conexões que o kernel não conseguiu criar ou deixou de fora"),
    ("Src.", "Origem"),
    ("Src. Address", "End. origem"),
    ("State", "Estado"),
    ("Subscriber", "Assinante"),
    ("TCP Close Wait Timeout", "Timeout TCP close wait"),
    ("TCP Established Timeout", "Timeout TCP estabelecida"),
    ("TCP FIN Wait Timeout", "Timeout TCP FIN wait"),
    ("TCP SYN Received Timeout", "Timeout TCP SYN recebido"),
    ("TCP SYN Sent Timeout", "Timeout TCP SYN enviado"),
    ("TCP Time Wait Timeout", "Timeout TCP time wait"),
    ("Table", "Tabela"),
    ("Their traffic stops until the hosts open new connections.", "O tráfego delas para até os hosts abrirem conexões novas."),
    ("Timeout", "Timeout"),
    ("Top subscribers", "Assinantes com mais conexões"),
    ("Tracking…", "Rastreamento…"),
    ("UDP Stream Timeout", "Timeout UDP stream"),
    ("UDP Timeout", "Timeout UDP"),
    ("Via", "Via"),
    ("any", "todos"),
    ("connections matching the filter?", "conexões que casam com o filtro?"),
    ("nf_conntrack_max: change it in System › Tuning", "nf_conntrack_max: mude em System › Tuning"),
    ("of", "de"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "connections.generic_timeout",
        "## Generic Timeout

Timeout dos protocolos que o conntrack não entende em detalhe (GRE sem helper, ESP, protocolos raros).

**Padrão:** 600 s.",
    ),
    (
        "connections.icmp_timeout",
        "## ICMP Timeout

Quanto uma consulta ICMP (ping) fica na tabela esperando a resposta.

**Padrão:** 30 s no Linux, 10 s no RouterOS. **RFC 5508 REQ-2:** num NAT, ≥ 60 s é o recomendado.",
    ),
    (
        "connections.max_entries",
        "## Max Entries

O tamanho máximo da tabela de conexões (`nf_conntrack_max`). Cheia, o roteador descarta conexões novas.

**Quando mudar:** num CGNAT, conte uns 300–500 por assinante ativo.

**Cuidado:** cada entrada usa cerca de 300 bytes de RAM; acompanhe também `nf_conntrack_buckets` (System › Tuning).

**Padrão:** o kernel escolhe pela RAM.",
    ),
    (
        "connections.table",
        "## Tabela de conexões

O kernel guarda cada conexão que passa pelo roteador (o *conntrack*): é com ela que o firewall sabe o que é resposta e que o NAT/CGNAT lembra a tradução de cada fluxo.

**Quando cheia**, conexões novas são descartadas (`dropped`) ou expulsam as mais velhas sem resposta (`early drop`): para o assinante, \"a internet parou\". `insert failed` conta conexões que não acharam porta livre no NAT (no CGNAT: o assinante esgotou a faixa dele) ou perderam uma corrida.

**O que fazer:** acima de 70 % aumente `nf_conntrack_max` em System › Tuning (cada entrada custa cerca de 300 bytes de RAM) ou encurte os timeouts (botão Rastreamento…).

**Padrão:** o kernel escolhe pelo tamanho da RAM. Num CGNAT, reserve uns 300–500 por assinante.",
    ),
    (
        "connections.tcp_close_wait_timeout",
        "## TCP Close Wait Timeout

Quanto uma conexão fica depois do FIN do outro lado, esperando a aplicação local fechar.

**Padrão:** 60 s.",
    ),
    (
        "connections.tcp_established_timeout",
        "## TCP Established Timeout

Quanto tempo uma conexão TCP estabelecida e **parada** (sem nenhum pacote) fica na tabela.

**Quando mudar:** num CGNAT com a tabela enchendo, reduza (por exemplo para 2h4m). Cada conexão ociosa segura uma porta pública do assinante.

**Cuidado:** abaixo do keepalive das aplicações (SSH, VPN, bancos de dados costumam mandar a cada 2 h), a conexão some e a aplicação trava sem aviso.

**Padrão:** 5 dias no Linux, 1 dia no RouterOS. **RFC 5382 REQ-5:** no mínimo 2 h 4 min num NAT.",
    ),
    (
        "connections.tcp_fin_wait_timeout",
        "## TCP FIN Wait Timeout

Quanto uma conexão fica depois que um lado mandou FIN, esperando o outro.

**Padrão:** 120 s. **RFC 7857 §2.1:** no NAT, o tempo de transição deveria ser ≥ 4 min; curto demais pode cortar o fim de downloads.",
    ),
    (
        "connections.tcp_syn_received_timeout",
        "## TCP SYN Received Timeout

Quanto espera o último passo do aperto de mão TCP depois do SYN-ACK.

**Padrão:** 60 s no Linux, 5 s no RouterOS. Raramente precisa mudar.",
    ),
    (
        "connections.tcp_syn_sent_timeout",
        "## TCP SYN Sent Timeout

Quanto espera a resposta de uma conexão TCP que só mandou o SYN.

**Quando mudar:** reduza se varreduras e ataques de SYN enchem a tabela.

**Cuidado:** em links lentos (satélite), muito curto derruba conexões legítimas.

**Padrão:** 120 s no Linux, 5 s no RouterOS.",
    ),
    (
        "connections.tcp_time_wait_timeout",
        "## TCP Time Wait Timeout

Quanto a conexão fica depois de fechada dos dois lados (para pacotes atrasados não caírem numa conexão nova com a mesma porta).

**Quando mudar:** num CGNAT com muitas conexões curtas, reduzir libera portas mais cedo.

**Cuidado:** muito curto pode misturar pacotes atrasados com uma conexão nova. **Padrão:** 120 s (2 × MSL).",
    ),
    (
        "connections.top",
        "## Assinantes com mais conexões

Quem tem mais conexões abertas agora, com quantas portas públicas do seu bloco do CGNAT estão em uso (TCP e UDP contam à parte; vale o protocolo mais cheio).

**Por que olhar:** um assinante perto de 100 % não consegue abrir conexões novas (o kernel descarta em silêncio, `insert failed`); é o sintoma clássico de \"só um site não abre\". Também acha máquina infectada ou P2P abrindo milhares de conexões.

**O que fazer:** clique no assinante para filtrar a tabela por ele. Se for uso legítimo, aumente as portas por assinante do pool (IP › Firewall › CGNAT) ou dê a ele uma exceção 1:1.",
    ),
    (
        "connections.udp_stream_timeout",
        "## UDP Stream Timeout

Quanto um fluxo UDP **com resposta** (DNS feito, jogo, VoIP, QUIC) fica parado na tabela.

**Quando mudar:** aumente se chamadas VoIP ou jogos caem depois de silêncio.

**Padrão:** 120 s no Linux, 3 min no RouterOS. **RFC 4787 REQ-5:** ≥ 2 min, 5 min recomendado.",
    ),
    (
        "connections.udp_timeout",
        "## UDP Timeout

Quanto um fluxo UDP **sem resposta** (só ida) fica na tabela.

**Padrão:** 30 s (Linux e RouterOS). **RFC 4787 REQ-5:** um NAT deve manter o mapeamento UDP por ≥ 2 min; o CGNAT do CoreRouter guarda o mapeamento EIM por 5 min à parte, então este timeout pode ficar curto.",
    ),
    (
        "connections.via",
        "## Via

Por onde passam os pacotes da conexão:

- **rules** — cada pacote atravessa as regras do firewall (o caminho normal);
- **software** — a conexão entrou no *flowtable* (o fasttrack do RouterOS): os pacotes seguintes pulam as regras, bem mais rápido;
- **hardware** — a placa de rede encaminha a conexão sozinha (offload, por exemplo NVIDIA ConnectX em modo switchdev).

Conexões em software ou hardware não passam por filas nem contadores de regra. Veja IP › Fast path (G2.4).",
    ),
];
