//! Portuguese labels and explanations of IP › Fast Path (G2.4), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("Card", "Placa"),
    ("Counters", "Contadores"),
    ("Fast Path", "Fast Path"),
    ("Fix", "Como resolver"),
    ("HW Offload", "Offload em hardware"),
    ("Offload", "Offload"),
    ("Ports", "Portas"),
    ("Why", "Motivo"),
    ("eSwitch", "eSwitch"),
    ("every Ethernet and bond port", "todas as portas Ethernet e bonds"),
    ("hardware asked", "hardware pedido"),
    ("in hardware", "em hardware"),
    ("in software", "em software"),
    ("installed", "instalado"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "fastpath.counters",
        "## Counters

Contadores do flowtable (kernel 5.7+): os bytes e pacotes que passam pelo fast path continuam aparecendo nos contadores da conexão (IP › Firewall › Connections, Traffic Flow, gráficos).

**Padrão:** ligado. **Quando desligar:** só se cada ciclo de CPU contar; sem eles, uma conexão no fast path parece parada nos contadores.",
    ),
    (
        "fastpath.enabled",
        "## Enabled

Liga o fast path: depois que o firewall **aceitou** uma conexão TCP ou UDP e ela ficou estabelecida, os pacotes seguintes pulam as regras de forward e vão direto da porta de entrada à de saída, já com o NAT. É o FastTrack do RouterOS, sem a regra `fasttrack-connection` nem o `accept` gêmeo: a cadeia que alimenta o flowtable roda **depois** do firewall, então uma regra de drop sempre vale.

**O que pula o fast path:** o primeiro pacote, fragmentos, pacotes maiores que o MTU e o FIN/RST do TCP (vão pelas regras). **Cuidado:** filas, contabilidade por regra e qualquer coisa que dependa de ver todo pacote no forward não veem os pacotes acelerados. Ao mudar o firewall, o flowtable é recriado e as conexões voltam às regras.

**Padrão:** desligado.",
    ),
    (
        "fastpath.fix",
        "## Fix

O que rodar para uma porta ir para hardware, quando a placa permite e falta um passo:

- eSwitch em **legacy**: `devlink dev eswitch set pci/… mode switchdev`, como root no sistema (fora do CoreRouter). **Cuidado:** a placa reinicia, os links dela caem alguns segundos e as VFs são recriadas: faça numa janela de manutenção, de preferência com Safe Mode, e não pela porta que você usa para gerenciar.
- **hw-tc-offload** desligado: o comando `interface.ethernet.set` mostrado, que o CoreRouter aplica e desfaz como qualquer mudança.

**Copy** copia o comando.",
    ),
    (
        "fastpath.hw_offload",
        "## HW Offload

Pede à placa que encaminhe as conexões do flowtable (`flags offload`).

- **auto** (padrão): pede; se o kernel recusar (placa sem suporte, veth, ConnectX em modo legacy), roda em software e a janela diz o motivo.
- **yes**: exige; a mudança é recusada se a placa recusar.
- **no**: só software.

**Placas:** NVIDIA/Mellanox ConnectX-5/6/7 (driver mlx5) com o eSwitch em **switchdev** e `hw-tc-offload` ligado; o NAT vai junto. Em campo o offload às vezes é aceito e não usado: a prova é a coluna Via = hardware em Connections. Os primeiros pacotes de cada conexão sempre passam em software.",
    ),
    (
        "fastpath.interfaces",
        "## Interfaces

As portas do flowtable. **Vazio** (padrão): todas as portas Ethernet e bonds (as portas de um bond ficam de fora; o bond entra).

**VLAN e PPPoE:** nomeie a porta, não a VLAN: desde o kernel 5.13 o flowtable acha sozinho o dispositivo real. Uma conexão só é acelerada se entra e sai por portas da lista.",
    ),
    (
        "fastpath.ports",
        "## Ports

Uma linha por porta:

- **Offload:** `hardware` (a placa encaminha), `software` (o kernel, sem as regras) ou `off` (fora do flowtable, linha apagada);
- **Card:** driver e firmware, e os selos `representor` (porta switchdev) e `hw-tc-offload`;
- **eSwitch:** `legacy` ou `switchdev` (só placas com devlink);
- **Why:** por que não está em hardware; o que rodar aparece abaixo da tabela, em **Fix**.",
    ),
    (
        "fastpath.window",
        "## Fast Path

O flowtable do Linux (`nf_flowtable`): o caminho rápido das conexões já aceitas, em software ou na placa. Equivale ao FastTrack do RouterOS (que é só IPv4 e pede duas regras); aqui vale para IPv4 e IPv6 e é uma opção só.

A tabela mostra cada porta e o que ela consegue; acima, quantas conexões estão no fast path agora.",
    ),
];
