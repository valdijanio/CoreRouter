//! Portuguese labels and explanations of the subscriber chip (G0.25),
//! sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("Address list comment", "Comentário de address-list"),
    ("CGNAT › Who Was", "CGNAT › Quem era?"),
    ("Click: open where this name comes from", "Clique: abre de onde vem este nome"),
    ("DHCP Leases", "Concessões DHCP"),
    ("IP › Addresses comment", "Comentário de IP › Addresses"),
    ("Lease host name", "Host-name da concessão"),
    ("Name", "Nome"),
    ("PPPoE login", "Login PPPoE"),
    ("PTR of own zones", "PTR das zonas próprias"),
    ("Show in", "Mostrar em"),
    ("Show the subscriber's name next to addresses", "Mostrar o nome do assinante ao lado dos endereços"),
    ("Sources, in order", "Fontes, em ordem"),
    ("Static lease comment", "Comentário da concessão fixa"),
    ("Subscriber identity", "Identidade do assinante"),
    ("Tried first", "Já é a primeira"),
    ("Tried last", "Já é a última"),
    ("soon: G4.3", "em breve: G4.3"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "identity.chip",
        "## Identidade do assinante

Um selo com o nome do assinante ao lado do endereço IP, nas telas que listam endereços (Connections, Torch, Traffic Flow, CGNAT › Quem era?, concessões DHCP, MTR).

- O selo mostra o **primeiro nome encontrado**, na ordem das fontes; os outros nomes diferentes viram **+N**.
- Passe o mouse para ver **todos os nomes**, cada um com a sua fonte (e o MAC, a lista ou a zona).
- **Clique** para abrir o item de onde o nome veio: a concessão, o endereço, a entrada da address-list ou o registro PTR.
- Um IP público **com porta** passa pelo CGNAT: o selo mostra o assinante que tinha aquela porta (a função de mapeamento da RFC 7422).

**Privacidade:** o roteador só mostra o que já está na configuração dele (comentários, host-names das concessões, PTR das zonas próprias). Nada é consultado na rede.

Comando: `ip.identity.lookup`. Preferência deste computador, não do roteador.",
    ),
    (
        "identity.enabled",
        "## Mostrar o nome do assinante

Liga ou desliga o selo em todas as telas. Desligado, nenhuma consulta de nome é feita.

Os nomes são pedidos em lote (até 1024 endereços por vez) e guardados por 30 s; o roteador responde da memória, sem acesso a disco nem à rede.",
    ),
    (
        "identity.places",
        "## Mostrar em

As telas onde o selo aparece. Útil para tirar o nome de uma tela que vai para um print ou uma apresentação.",
    ),
    (
        "identity.sources",
        "## Fontes, em ordem

De onde vem o nome, na ordem em que o roteador procura. A primeira fonte com nome vira o selo; as outras aparecem no tooltip.

- **Login PPPoE** — o usuário da sessão PPPoE que tem o IP (chega com o servidor PPPoE, G4.3).
- **Comentário da concessão fixa** — o *comment* de `/ip dhcp-server lease` sem a flag D. Com um instante (Quem era?), só vale se o MAC da concessão fixa é o de quem tinha o IP naquela hora.
- **Host-name da concessão** — o nome que o cliente mandou no DHCP (opção 12/81). Com um instante, vem do histórico de concessões.
- **Comentário de IP › Addresses** — o endereço do roteador e os hosts de uma rede pequena (/29 ou menor: o /30 ou /31 de um cliente dedicado). A rede de uma LAN /24 não dá nome a cada host.
- **Comentário de address-list** — entradas de até 256 endereços.
- **PTR das zonas próprias** — o registro PTR de uma zona `in-addr.arpa`/`ip6.arpa` do roteador.

Desmarque uma fonte para não usá-la.",
    ),
];
