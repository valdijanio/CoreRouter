//! Portuguese labels and explanations of IP › ARP (G1.27d), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("ARP (IPv4)", "ARP (IPv4)"),
    ("ARP Ping", "ARP Ping"),
    ("ARP Timeout", "Timeout ARP"),
    ("Add to Address List", "Adicionar à Address List"),
    ("Add to Address List…", "Adicionar à Address List…"),
    ("Addresses", "Endereços"),
    ("Apply", "Aplicar"),
    ("Confirm", "Confirmar"),
    ("Download the IEEE listing now (standards-oui.ieee.org); the downloaded table wins over the built-in one", "Baixar a lista do IEEE agora (standards-oui.ieee.org); a tabela baixada vale mais que a embutida"),
    ("Entries", "Entradas"),
    ("Entries the kernel holds and its ceiling", "Entradas que o kernel guarda e o teto"),
    ("Flush", "Flush"),
    ("Forget the learned entries (never the gateway in use nor your management neighbor)", "Esquecer as entradas aprendidas (nunca o gateway em uso nem o vizinho da sua gerência)"),
    ("Forget the learned neighbors", "Esquecer os vizinhos aprendidos"),
    ("History", "Histórico"),
    ("Hosts without a static entry stop being reachable.", "Hosts sem entrada estática deixam de ser alcançáveis."),
    ("IP, CIDR, MAC prefix or text", "IP, CIDR, prefixo de MAC ou texto"),
    ("Kernel table", "Tabela do kernel"),
    ("Last Seen", "Visto"),
    ("MAC Address", "Endereço MAC"),
    ("Make Static", "Tornar estática"),
    ("ND (IPv6)", "ND (IPv6)"),
    ("Nearly full: new hosts will be refused. Suggested:", "Quase cheia: hosts novos serão recusados. Sugestão:"),
    ("Neighbor", "Vizinho"),
    ("New ARP Entry…", "Nova entrada ARP…"),
    ("Only static entries (and DHCP add-arp) reach hosts: the others stop being reachable.", "Só entradas estáticas (e o add-arp do DHCP) alcançam hosts: os outros deixam de ser alcançáveis."),
    ("Open Tuning", "Abrir Tuning"),
    ("Pick an interface to change its ARP mode", "Escolha uma interface para mudar o modo ARP"),
    ("Ping", "Ping"),
    ("Reading…", "Lendo…"),
    ("Router address", "Endereço do roteador"),
    ("Routes through it", "Rotas por ele"),
    ("Select learned neighbors first", "Selecione vizinhos aprendidos antes"),
    ("Select one IPv4 neighbor", "Selecione um vizinho IPv4"),
    ("Settings", "Configurações"),
    ("Source", "Origem"),
    ("State", "Estado"),
    ("Static", "Estáticas"),
    ("The limits are kernel parameters of System › Tuning.", "Os limites são parâmetros do kernel em System › Tuning."),
    ("The router answers ARP for addresses it routes elsewhere (RFC 1027), which can pull traffic of the whole segment.", "O roteador responde ARP por endereços que roteia para outro lado (RFC 1027), o que pode puxar tráfego do segmento inteiro."),
    ("Torch", "Torch"),
    ("Unresolved", "Sem resposta"),
    ("Update vendors", "Atualizar fabricantes"),
    ("Vendor", "Fabricante"),
    ("Vendors", "Fabricantes"),
    ("ago", "atrás"),
    ("downloading…", "baixando…"),
    ("dynamic", "dinâmicas"),
    ("events lost: read again", "eventos perdidos: lido de novo"),
    ("kernel table", "tabela do kernel"),
    ("match", "batem"),
    ("nearly full", "quase cheia"),
    ("neighbors", "vizinhos"),
    ("none", "nenhuma"),
    ("same MAC since the router started watching", "mesmo MAC desde que o roteador começou a observar"),
    ("static", "estáticas"),
    ("table of", "tabela de"),
    ("update failed", "falha ao atualizar"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "arp.address",
        "## Address

O endereço IP do vizinho. Na busca, aceita um IP exato, uma rede em CIDR (`10.0.0.0/24`), um prefixo de MAC (`00:50:56`) ou texto (interface, estado, comentário).",
    ),
    (
        "arp.detail",
        "## Vizinho selecionado

O histórico de MACs do endereço (desde quando cada um respondeu; um MAC que volta e vai é sinal de IP duplicado ou ARP spoofing), as rotas que usam este vizinho como gateway e o endereço do roteador na mesma rede.

Ações: **Make Static** (o MAC aprendido vira entrada estática), **Add to Address List** (firewall), **ARP Ping**, **Ping** e **Torch** na interface.",
    ),
    (
        "arp.disabled",
        "## Disabled

A entrada fica na configuração mas sai do kernel. Útil para testar sem perder o que estava digitado.",
    ),
    (
        "arp.entries",
        "## Entries

Quantos vizinhos IPv4 a interface tem agora na tabela do kernel, de todos os estados.",
    ),
    (
        "arp.flush",
        "## Flush

Apaga as entradas **aprendidas** (não as estáticas): o kernel volta a perguntar na próxima vez que precisar. Útil depois de trocar um equipamento de lugar.

**Nunca apaga** o gateway de uma rota ativa nem o vizinho por onde vem a sua sessão de gerência: numa porta `reply-only` essas entradas não voltariam sozinhas. A resposta diz quais ficaram e por quê.",
    ),
    (
        "arp.gc_thresh",
        "## gc_thresh1/2/3

O tamanho da tabela de vizinhos do kernel (RouterOS: `max-neighbor-entries`).

- **gc_thresh1**: abaixo disso nada é apagado;
- **gc_thresh2**: acima disso por 5 s, o coletor apaga as entradas velhas;
- **gc_thresh3**: o teto. Passou dele, hosts novos são recusados (\"neighbour table overflow\").

**Padrão do Linux:** 128 / 512 / 1024, pouco para um BNG. O roteador avisa no log ao passar de 80 % do teto e sugere valores (RFC 6583: uma varredura de fora pode encher a tabela). Muda-se em System › Tuning, com transação e Safe Mode.",
    ),
    (
        "arp.interface",
        "## Interface

A porta onde o vizinho está. A cor do selo vem do nome da interface: a mesma em todas as janelas.",
    ),
    (
        "arp.last_seen",
        "## Last Seen

Há quanto tempo o vizinho foi confirmado alcançável pela última vez (o kernel confirma por resposta ARP/NA ou por tráfego TCP que avança).",
    ),
    (
        "arp.mac_address",
        "## MAC Address

O endereço de camada 2 que respondeu por este IP. Vazio enquanto a resolução não terminou (`incomplete`) ou falhou (`failed`).

Uma troca de MAC de um IP conhecido gera um aviso no log (tópico `arp`), como o arpwatch.",
    ),
    (
        "arp.mode",
        "## ARP (modo da interface)

Como no RouterOS:

- **enabled** (padrão): aprende e responde (RFC 826);
- **disabled**: não usa ARP; só entradas estáticas alcançam hosts;
- **reply-only**: responde pelos endereços do roteador mas não aprende: só entradas estáticas (ou `add-arp` do DHCP) alcançam hosts. É o modo antispoofing;
- **proxy-arp**: responde por endereços que o roteador alcança por outra porta (RFC 1027);
- **local-proxy-arp**: responde por hosts da mesma porta, para clientes isolados se falarem pelo roteador.

**Cuidado:** disabled, reply-only e proxy-arp pedem confirmação, e mudar a porta por onde vem a sua sessão sem entrada estática para o seu gateway é recusado (use Make Static antes ou o Safe Mode).",
    ),
    (
        "arp.published",
        "## Published

O roteador responde ARP por este endereço com o próprio MAC, quando tem rota para ele por outra porta: um proxy-ARP para um host só, sem ligar o proxy-arp da interface inteira.

**Padrão:** não.",
    ),
    (
        "arp.source",
        "## Source

De onde a entrada vem: **dynamic** (o kernel aprendeu da rede) ou **static** (você cadastrou; fica `permanent`, nunca expira), ou **dhcp** (o servidor DHCP com `add_arp` pôs: some com a concessão). **published** marca uma entrada estática que o roteador anuncia como proxy.",
    ),
    (
        "arp.state",
        "## State

O estado da resolução, nos termos da RFC 4861 §7.3.2 (o Linux usa os mesmos para ARP):

- **reachable**: confirmado há pouco;
- **stale**: não confirmado há um tempo, ainda usado; é conferido no próximo pacote;
- **delay** / **probe**: sendo conferido;
- **incomplete**: o roteador perguntou e ninguém respondeu ainda;
- **failed**: ninguém respondeu (o host sumiu ou o endereço não existe);
- **permanent**: entrada estática;
- **noarp**: não precisa de resolução.

Os selos acima da tabela contam a tabela inteira; um clique filtra.",
    ),
    (
        "arp.static",
        "## Entrada ARP estática

Um par IP → MAC fixo numa interface (RouterOS `/ip arp add`). Fica `permanent` no kernel e nunca expira. Use para equipamentos críticos, para portas `reply-only` (onde só o estático alcança o host) ou para corrigir um vizinho que responde errado.

**Cuidado:** um MAC diferente do que o host usa corta o host. O modal avisa quando o host responde agora com outro MAC.",
    ),
    (
        "arp.static_count",
        "## Static

Quantas entradas estáticas a interface tem.",
    ),
    (
        "arp.tab.arp",
        "## ARP (IPv4)

A tabela ARP: o MAC de cada vizinho IPv4 (RFC 826), com as entradas estáticas.",
    ),
    (
        "arp.tab.nd",
        "## ND (IPv6)

A tabela de vizinhos IPv6 (Neighbor Discovery, RFC 4861). O selo **router** marca quem anunciou ser roteador (flag R).",
    ),
    (
        "arp.tab.settings",
        "## Settings

O modo ARP e o timeout de cada interface, e o tamanho da tabela do kernel.",
    ),
    (
        "arp.timeout",
        "## ARP Timeout

Por quanto tempo uma entrada aprendida fica `reachable` sem nova confirmação (Linux `base_reachable_time`); o kernel sorteia entre a metade e 1,5 vez esse valor (RFC 4861 §6.3.2).

**Padrão:** auto (30 s, RFC 4861 §10 REACHABLE_TIME). Depois disso a entrada fica `stale`, não some.",
    ),
    (
        "arp.unresolved",
        "## Unresolved

Quantos vizinhos da interface estão `incomplete` ou `failed`: o roteador perguntou e ninguém respondeu. Muitos aqui costumam ser uma varredura ou um gateway fora do ar.",
    ),
    (
        "arp.vendor",
        "## Vendor

O fabricante da placa, pelos três primeiros bytes do MAC (OUI do IEEE). A tabela vem embutida e pode ser atualizada em Settings › Update vendors. MACs aleatórios (privacidade em Wi-Fi, VMs) não têm fabricante.",
    ),
    (
        "arp.vendors",
        "## Vendors (fabricantes)\n\nA tabela que dá o fabricante pelos três primeiros bytes do MAC: a lista pública MA-L do IEEE (`oui.csv`). Vem uma embutida no programa, com a data em que foi lida; **Update vendors** pede ao roteador que baixe a lista atual de standards-oui.ieee.org (TLS conferido, tamanho limitado), confira e troque a tabela de uma vez. A baixada vale mais que a embutida e sobrevive a um reinício.\n\nMACs aleatórios (privacidade em Wi-Fi, VMs) e blocos que o dono pagou para esconder não têm fabricante. Fonte e termos: `docs/third-party.md`.",
    ),
];
