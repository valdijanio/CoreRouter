//! Portuguese explanations and labels of IP › Firewall XDP (G2.5a), each
//! sorted by key.

/// Explanations by key (`xdp`, `xdp.<label>`).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "xdp",
        r##"## O que é
Um filtro que roda **dentro do driver da placa de rede** (XDP, eXpress Data Path), antes de o kernel gastar qualquer coisa com o pacote: antes do `raw`, do connection tracking e do roteamento. Descarta o que um ataque manda em volume: origens em listas de bloqueio, origens acima de uma taxa, cabeçalhos quebrados e combinações de flags TCP que nenhuma conexão usa.
## Por que
Uma placa em modo nativo descarta dezenas de milhões de pacotes por segundo com poucas CPUs (artigo do XDP, CoNEXT 2018: 24 Mpps por núcleo numa ConnectX-5; **estimado** para o seu hardware até medir). No mesmo artigo, a tabela raw do iptables descartava 4,8 Mpps por núcleo. O ganho vem de não alocar o pacote no kernel, e só aparece no modo native de uma placa real: num par veth, sem placa, o XDP não ganhou do nftables (**medido**, docs/xdp.md).
## Equivalente no RouterOS
Não existe XDP no RouterOS. O mais próximo é `/ip firewall raw add chain=prerouting src-address-list=… action=drop` com `dst-limit=…,src-address` para a taxa.
## Cuidado
Um pacote descartado aqui não aparece em nenhum outro contador do firewall. O filtro vale igual em todas as interfaces onde está."##,
    ),
    (
        "xdp.active",
        r##"## O que mostra
Como o filtro está preso à interface agora: **native** (no driver: o rápido), **generic** (depois do driver, sobre o buffer do kernel: funciona em qualquer interface, mais lento) ou **off** (não preso; a coluna Nota diz por quê).
## Se o modo for auto
Auto tenta native e cai para generic quando o driver não tem XDP; a Nota diz o motivo da recusa."##,
    ),
    (
        "xdp.allow_lists",
        r##"## O que faz
Listas de endereços do firewall (IP › Firewall › Address Lists) cujas **origens o filtro nunca descarta** por lista de bloqueio nem por taxa. Pacotes malformados continuam descartados.
## Para quê
Ponha aqui o que não pode cair: os vizinhos BGP, a rede de gerência (NOC), os resolvedores DNS, os servidores de monitoramento. Evita que uma lista de bloqueio importada ou uma taxa baixa demais corte o seu próprio acesso.
## Proteção
Se uma mudança fosse descartar o endereço da sua própria sessão de gerência, o commit é recusado (como no firewall), a menos que você confirme (force) ou esteja em Safe Mode."##,
    ),
    (
        "xdp.block_lists",
        r##"## O que faz
Listas de endereços do firewall cujas **origens são descartadas** no driver. Prefixos IPv4 e IPv6, faixas (viram blocos CIDR exatos) e as entradas dinâmicas (com timeout) entram; entradas desabilitadas não.
## Como funciona
Os prefixos vão para uma árvore de maior prefixo (LPM trie) no kernel: uma busca por pacote, qualquer que seja o número de entradas (o custo por tamanho da árvore está medido em docs/xdp.md).
## Exemplos
Bogons, listas de reputação (Spamhaus DROP, FireHOL), a lista `ddos-attackers` que uma regra do firewall alimenta.
## Fica para depois
Entradas que uma regra `add-src-to-address-list` põe na lista vivem só no nftables e ainda não chegam ao XDP (G2.5c)."##,
    ),
    (
        "xdp.blocked",
        r##"## O que conta
Pacotes descartados porque a origem está numa lista de bloqueio (e em nenhuma lista de exceção). A aba Top Sources mostra quais origens e de que lista."##,
    ),
    (
        "xdp.drop",
        r##"## O que conta
Pacotes descartados por segundo nesta interface, somando todos os motivos (bloqueio, taxa, malformado, flags TCP). Calculado da diferença dos contadores entre duas leituras com pelo menos um segundo de intervalo."##,
    ),
    (
        "xdp.fast_nat",
        r##"## O que faz
Caminho rápido do CGNAT: as conexões que o CGNAT do kernel (nftables) já traduziu passam a ser traduzidas e encaminhadas aqui, no driver, sem passar pelo conntrack, pelas regras nem pelo roteamento do kernel.
## Como funciona
O kernel continua decidindo tudo: os primeiros pacotes de cada conexão passam pelo nftables, que escolhe a porta na faixa determinística do assinante. Quando o conntrack diz que a conexão está estabelecida (os dois sentidos vistos), o serviço `xdp-nat` copia os dois sentidos para o mapa do XDP; dali em diante o XDP troca endereço e porta, corrige os checksums (RFC 1624), desconta o TTL e manda o pacote pela interface que a tabela de rotas indica (`bpf_fib_lookup`). O serviço renova o timeout do conntrack das conexões que o XDP carregou e tira do mapa as que o conntrack encerrou.
## Fica no kernel
IPv6, ICMP, fragmentos, quadros com VLAN, pacotes com opções IP, SYN/FIN/RST (o conntrack acompanha a abertura e o fechamento), TTL 1, e o que a tabela de rotas não resolve na hora (vizinho ainda sem MAC, MTU). "Enviado ao kernel" mostra quantos de cada motivo.
## Precisa
XDP nas interfaces dos assinantes e nas de saída para a internet. Até 262 144 conexões ao mesmo tempo; as que passarem disso seguem pelo kernel. O "Quem era?" continua exato: a porta foi o kernel que escolheu."##,
    ),
    (
        "xdp.malformed",
        r##"## O que descarta
Quadros com cabeçalho impossível: cortado no meio do cabeçalho Ethernet, VLAN, IP ou de transporte; versão do IP diferente do EtherType; IHL abaixo de 20 bytes; comprimento total menor que o cabeçalho ou maior que o quadro; comprimento UDP impossível; offset TCP abaixo de 20 bytes.
## Fragmentos
Primeiro fragmento curto demais para o cabeçalho TCP/UDP e fragmento TCP no offset 8 bytes (ataques de fragmento minúsculo e de sobreposição, RFC 1858 §3) contam como malformados. Os demais fragmentos passam: não têm cabeçalho de transporte para conferir.
## Por que é seguro
O kernel descartaria esses pacotes mais adiante; aqui eles saem antes de custar CPU."##,
    ),
    (
        "xdp.mode",
        r##"## Opções
- **auto**: native onde o driver tem XDP, generic onde não tem. O padrão.
- **native**: no driver, antes de o kernel alocar o pacote. mlx5 (ConnectX-4 em diante), i40e, ice, ixgbe, bnxt, ena, igb, igc, virtio_net e veth têm. Recusado (e o commit desfeito) onde o driver não tem.
- **generic**: depois do driver, em qualquer interface (VLAN, bridge). Uma fração da velocidade do native (8,4 contra 19,8 Mpps num núcleo numa mlx5, **medido** por terceiros).
## Dica
VLAN e bridge não têm driver próprio: ponha o filtro na porta física, que vê os quadros com a tag."##,
    ),
    (
        "xdp.pass",
        r##"## O que conta
Pacotes por segundo que o filtro deixou seguir para o kernel nesta interface (inclui ARP, LLDP e o que não é IP)."##,
    ),
    (
        "xdp.rate-limit",
        r##"## O que conta
Pacotes descartados porque a origem passou da taxa por origem (aba Filter). A aba Top Sources mostra quais."##,
    ),
    (
        "xdp.rate_burst",
        r##"## O que faz
Quantos pacotes uma origem pode mandar de uma vez acima da taxa (o tamanho do balde). 0 usa um segundo de taxa.
## Exemplo
Taxa 1000 e burst 5000: uma origem pode mandar 5000 pacotes de uma vez e depois 1000 por segundo."##,
    ),
    (
        "xdp.rate_limit",
        r##"## O que faz
Limite de pacotes por segundo **por origem**, num balde de fichas (token bucket) por endereço. 0 desliga.
## Equivalente no RouterOS
`dst-limit=<taxa>,<burst>,src-address` numa regra `raw`.
## Cuidado
Um endereço pode ser muita gente: um CGNAT de outro provedor, um resolvedor, um CDN, um vizinho BGP. Ponha esses numa lista de exceção. Abaixo de 100 pps o comando avisa.
## Limites
Até 262 144 origens têm balde ao mesmo tempo; passando disso, a menos vista recentemente perde o seu e começa de novo cheia. Duas CPUs atualizando a mesma origem ao mesmo tempo podem ganhar ou perder uma ficha: a taxa é aproximada nesse caso."##,
    ),
    (
        "xdp.tcp-flags",
        r##"## O que descarta
Segmentos TCP com combinação de flags que nenhuma conexão usa: SYN+FIN, SYN+RST, FIN+RST, FIN sem ACK, nenhuma flag (null scan), FIN+PSH+URG (Xmas). A tabela é a do `nf_conntrack` do kernel, que marcaria esses pacotes como inválidos.
## Por que é seguro
Uma pilha TCP correta nunca manda essas combinações; elas vêm de varreduras de portas e de ataques que tentam passar por firewalls sem estado."##,
    ),
    (
        "xdp.top",
        r##"## O que mostra
As origens com mais pacotes descartados, de qualquer motivo: endereço, pacotes, bytes, o motivo e a lista do último descarte, e há quantos segundos.
## Limites
O filtro lembra até 16 384 origens descartadas; passando disso, a menos vista recentemente sai da tabela. Reset Counters zera os contadores e esta tabela."##,
    ),
    (
        "xdp.unavailable",
        r##"## Por quê
Carregar um programa XDP exige as capacidades CAP_BPF e CAP_NET_ADMIN no namespace inicial: rode o `corerouter-daemon` como root ou dê as capacidades ao binário (`setcap cap_bpf,cap_net_admin,cap_perfmon+ep`). Também pode faltar suporte a BPF no kernel.
## No laboratório virtual
O filtro é simulado: os contadores crescem conforme o que está ligado, sem pacotes de verdade."##,
    ),
];

/// Label translations: (English, Portuguese), sorted by English.
pub(super) const LABELS: &[(&str, &str)] = &[
    ("Active", "Ativo"),
    ("Add XDP Interface…", "Adicionar interface XDP…"),
    ("Allow Lists", "Listas de exceção"),
    ("Allowed prefixes", "Prefixos permitidos"),
    ("Block Lists", "Listas de bloqueio"),
    ("Blocked", "Bloqueados"),
    ("Blocked prefixes", "Prefixos bloqueados"),
    ("Burst (packets)", "Rajada (pacotes)"),
    ("CGNAT Fast Path", "Caminho rápido do CGNAT"),
    ("Drop Invalid TCP Flags", "Descartar flags TCP inválidas"),
    ("Drop Malformed", "Descartar malformados"),
    ("Drop pps", "Descartados pps"),
    ("Fast NAT pps", "Caminho rápido pps"),
    ("Filter", "Filtro"),
    ("Malformed", "Malformados"),
    ("Most dropped sources", "Origens mais descartadas"),
    ("New XDP Interface", "Nova interface XDP"),
    ("Pass pps", "Passando pps"),
    ("Rate Limit", "Limite de taxa"),
    ("Rate Limit (pps per source)", "Limite de taxa (pps por origem)"),
    ("Reset Counters", "Zerar contadores"),
    ("Select an interface first", "Selecione uma interface primeiro"),
    ("Sent to the kernel:", "Enviado ao kernel:"),
    ("TCP Flags", "Flags TCP"),
    ("This router has no XDP filter yet: update corerouter-daemon.", "Este roteador ainda não tem o filtro XDP: atualize o corerouter-daemon."),
    ("Top Sources", "Top origens"),
    ("connections", "conexões"),
    ("flow directions", "sentidos de fluxo"),
    ("timeouts renewed", "timeouts renovados"),
    ("unavailable", "indisponível"),
];
