//! Portuguese labels and explanation of the Interfaces' network card problems
//! (G1.6ja), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("Click for the card, the missing file and what to do", "Clique para ver a placa, o arquivo que faltou e o que fazer"),
    ("Close", "Fechar"),
    ("Every network card has its driver and firmware.", "Toda placa de rede tem driver e firmware."),
    ("Network card problems", "Problemas nas placas de rede"),
    ("Normal on the ISO, which has no firmware files: the installed image has them", "Normal na ISO, que não traz firmware: a imagem instalada traz"),
    ("The kernel's log cannot be read here: a missing firmware file would not show.", "O log do kernel não pode ser lido aqui: um firmware faltando não apareceria."),
    ("What this means", "O que isto quer dizer"),
    ("What to do:", "O que fazer:"),
    ("Without a driver, not a problem:", "Sem driver, e não é problema:"),
    ("firmware", "firmware"),
    ("no driver", "sem driver"),
    ("safe mode", "safe mode"),
    ("until installed", "até instalar"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[(
    "nic_problems.overview",
    "## Problemas nas placas de rede

O roteador olha as placas de rede PCI e USB da máquina a cada 10 segundos e o que o kernel disse sobre elas.

- **sem driver**: a placa está no barramento e nada a assumiu, então ela não tem porta. Se a imagem tem um módulo para ela, ele não subiu; senão, esta imagem não conhece a placa (a tabela está em `docs/os-image.md`).
- **firmware**: o driver pediu um arquivo e não conseguiu carregar. A porta pode não subir, ou subir com menos recursos. O nome do arquivo está na lista.
- **safe mode**: o driver `ice` da Intel E810 não conseguiu usar o pacote DDP: uma fila só, sem RSS, sem XDP, sem offloads. O tráfego passa, num núcleo só.
- **até instalar**: na ISO, que não traz firmware, é o normal. Nada a fazer.

**Não contam:** placa Wi-Fi para a qual esta imagem não tem driver (a que tem driver é uma interface de tipo wifi: Interfaces › Wi-Fi), funções virtuais sem driver (entregues a uma VM de propósito) e o `regulatory.db`, que uma imagem anterior ao Wi-Fi não trazia.

A mesma lista está na saúde do roteador (`interface.hardware`), no log do roteador e no aviso da CLI e do MCP; `interface.hardware-problem.print` devolve a lista.",
)];
