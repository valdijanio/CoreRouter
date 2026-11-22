//! Portuguese labels and explanations of the station-bridge and peers of
//! Interfaces › Wi-Fi (G1.30m), each sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"Add Peer"##, r##"Adicionar par"##),
    (r##"Add Peer…"##, r##"Adicionar par…"##),
    (r##"Airtime"##, r##"Tempo de ar"##),
    (r##"Bridge Protocol"##, r##"Protocolo de bridge"##),
    (r##"General"##, r##"Geral"##),
    (r##"Link"##, r##"Ligação"##),
    (r##"No radio is an access point: set Mode to ap first"##, r##"Nenhum rádio é ponto de acesso: ponha Modo ap primeiro"##),
    (r##"Peers"##, r##"Pares"##),
    (r##"Select one or more peers first"##, r##"Selecione um ou mais pares primeiro"##),
    (r##"Station Bridge"##, r##"Station bridge"##),
    (r##"The other router's station-bridge radio: its MAC is in its Wi-Fi window. Only registered peers get four addresses."##, r##"O rádio station-bridge do outro roteador: o MAC está na janela Wi-Fi dele. Só pares cadastrados ganham quatro endereços."##),
    (r##"away"##, r##"ausente"##),
    (r##"bridge"##, r##"bridge"##),
    (r##"peers"##, r##"pares"##),
    (r##"up"##, r##"ativo"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "interface.wifi.bridge_protocol",
        r##"## Protocolo de bridge (station-bridge)
Como o station-bridge combina os quadros de quatro endereços com o ponto de acesso.

- **multi-ap** (o padrão): backhaul do Wi-Fi EasyMesh. A associação diz isso, e o ponto de acesso dá os quatro endereços. Entre CoreRouters e com pontos de acesso EasyMesh.
- **wds**: quatro endereços desde o início, sem negociação. Para o OpenWrt (`option wds 1`) e outros que falam WDS.

Nenhum dos dois fala com o `station-bridge` do MikroTik, que é próprio e só funciona entre RouterOS."##,
    ),
    (
        "interface.wifi.peer.airtime",
        r##"## Tempo de ar
A parte do ar que o enlace do par ocupou entre as duas últimas leituras (2 s de intervalo): quadros enviados e recebidos, pelos contadores de tempo de ar do driver. Âmbar a partir de 60 %, vermelho a partir de 85 %: o canal está quase cheio e o enlace não passa disso ali (outro canal, ou outro enlace no bonding)."##,
    ),
    (
        "interface.wifi.peer.link",
        r##"## Ligação
Para onde vai o enlace do par: uma bridge (a LAN chega ao outro roteador) ou um bonding (vários enlaces entre os mesmos dois roteadores, G1.30m parte 2)."##,
    ),
    (
        "interface.wifi.peer.mac",
        r##"## Endereço MAC
O rádio station-bridge do outro roteador. Só um MAC cadastrado ganha quatro endereços; qualquer outra estação que pedir é desligada."##,
    ),
    (
        "interface.wifi.peer.name",
        r##"## Nome
O enlace do par é uma interface com este nome (tipo `wifi-peer`), presente enquanto o par está associado: ponha numa bridge ou num bonding como qualquer porta. Com o par ausente, a configuração espera, como a de uma porta desconectada."##,
    ),
    (
        "interface.wifi.peer.radio",
        r##"## Rádio
O ponto de acesso em que o par entra. Ele precisa aceitar station-bridges: Station Bridge `yes` ou `only`."##,
    ),
    (
        "interface.wifi.peer.state",
        r##"## Estado
- **ativo**: associado, com o enlace de quatro endereços presente.
- **ausente**: não associado; a configuração espera por ele.
- **desativado**: cadastrado e desligado."##,
    ),
    (
        "interface.wifi.peers",
        r##"## Pares
Os station-bridges de outros roteadores que os pontos de acesso deste aceitam: um enlace Wi-Fi ponto a ponto (ou ponto-multiponto) que leva a LAN, com quadros de quatro endereços.

Cada par é uma interface própria. Dois enlaces entre os mesmos dois roteadores vão num bonding, não os dois numa bridge: as bridges aqui não rodam spanning tree, e dois fariam um laço.

O backhaul é só WPA3 (SAE, quadros de gerência protegidos)."##,
    ),
    (
        "interface.wifi.station_bridge",
        r##"## Station Bridge (ponto de acesso)
Se este ponto de acesso aceita station-bridges, os enlaces dos outros roteadores:

- **no** (o padrão): só clientes; ninguém ganha quatro endereços.
- **yes**: clientes e os pares cadastrados (aba Peers).
- **only**: só os pares cadastrados (um ponto de acesso de backhaul; só estações Multi-AP).

Com yes ou only, o ponto de acesso é WPA3 para os pares, e só os MACs cadastrados ganham quatro endereços."##,
    ),
];
