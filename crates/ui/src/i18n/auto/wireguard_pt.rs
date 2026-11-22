//! Portuguese labels and explanations of Interfaces › WireGuard (G1.31a),
//! each sorted by key (registered by `build.rs`).

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"Accept in Firewall"##, r##"Aceitar no firewall"##),
    (r##"Add Peer…"##, r##"Adicionar par…"##),
    (r##"Allowed Address"##, r##"Endereço permitido"##),
    (r##"Asking the router…"##, r##"Perguntando ao roteador…"##),
    (r##"Client Allowed Address"##, r##"Endereço permitido do cliente"##),
    (r##"Client Config"##, r##"Config do cliente"##),
    (r##"Client Config…"##, r##"Config do cliente…"##),
    (r##"Client DNS"##, r##"DNS do cliente"##),
    (r##"Client Endpoint"##, r##"Endpoint do cliente"##),
    (r##"Comment"##, r##"Comentário"##),
    (r##"Copy"##, r##"Copiar"##),
    (r##"Copy Public Key"##, r##"Copiar chave pública"##),
    (r##"Create Routes"##, r##"Criar rotas"##),
    (r##"Disabled"##, r##"Desativado"##),
    (r##"Endpoint"##, r##"Endpoint"##),
    (r##"Endpoint Port"##, r##"Porta do endpoint"##),
    (r##"Export"##, r##"Exportar"##),
    (r##"Export…"##, r##"Exportar…"##),
    (r##"Import WireGuard"##, r##"Importar WireGuard"##),
    (r##"Import…"##, r##"Importar…"##),
    (r##"Interface"##, r##"Interface"##),
    (r##"Interfaces"##, r##"Interfaces"##),
    (r##"Last Handshake"##, r##"Último handshake"##),
    (r##"Listen Port"##, r##"Porta"##),
    (r##"MTU"##, r##"MTU"##),
    (r##"Name"##, r##"Nome"##),
    (r##"New WireGuard Interface"##, r##"Nova interface WireGuard"##),
    (r##"New WireGuard Interface…"##, r##"Nova interface WireGuard…"##),
    (r##"New WireGuard Peer"##, r##"Novo par WireGuard"##),
    (r##"New WireGuard Peer…"##, r##"Novo par WireGuard…"##),
    (r##"No WireGuard interface yet: add one in the Interfaces tab first."##, r##"Nenhuma interface WireGuard ainda: crie uma na aba Interfaces primeiro."##),
    (r##"No WireGuard interface. + adds one: the router makes its key pair; then give it an address (IP › Addresses) and add its peers."##, r##"Nenhuma interface WireGuard. + cria uma: o roteador gera o par de chaves; depois dê a ela um endereço (IP › Addresses) e adicione os pares."##),
    (r##"No peers. + adds one: paste the peer's public key, or leave it empty and the router makes the pair (for the client config)."##, r##"Nenhum par. + adiciona um: cole a chave pública do par, ou deixe vazia e o roteador gera o par de chaves (para a config do cliente)."##),
    (r##"Paste a wg-quick file ([Interface] and [Peer] sections): one transaction makes the interface, its addresses and peers."##, r##"Cole um arquivo do wg-quick (seções [Interface] e [Peer]): uma transação só cria a interface, os endereços e os pares."##),
    (r##"Peers"##, r##"Pares"##),
    (r##"Persistent Keepalive"##, r##"Keepalive persistente"##),
    (r##"Preshared Key"##, r##"Chave pré-compartilhada"##),
    (r##"Private Key"##, r##"Chave privada"##),
    (r##"Public Key"##, r##"Chave pública"##),
    (r##"Regenerate Keys"##, r##"Gerar chaves novas"##),
    (r##"Regenerate Keys…"##, r##"Gerar chaves novas…"##),
    (r##"Responder"##, r##"Só responde"##),
    (r##"Rx"##, r##"Rx"##),
    (r##"Show keys"##, r##"Mostrar chaves"##),
    (r##"State"##, r##"Estado"##),
    (r##"The router makes a new key pair for this interface. Every peer must then get the new public key, and every tunnel handshakes again."##, r##"O roteador gera um par de chaves novo para esta interface. Todos os pares precisarão receber a chave pública nova, e todos os túneis refazem o handshake."##),
    (r##"The text and the QR code carry the client's private key: only group full sees them."##, r##"O texto e o QR levam a chave privada do cliente: só o grupo full os vê."##),
    (r##"Tx"##, r##"Tx"##),
    (r##"VRF"##, r##"VRF"##),
    (r##"WireGuard"##, r##"WireGuard"##),
    (r##"WireGuard Interface"##, r##"Interface WireGuard"##),
    (r##"WireGuard Peer"##, r##"Par WireGuard"##),
    (r##"peers"##, r##"pares"##),
    (r##"resolved"##, r##"resolvido"##),
    (r##"roamed"##, r##"mudou de IP"##),
    (r##"warning"##, r##"aviso"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "menu.wireguard",
        r##"## O que faz
O `/interface wireguard` do RouterOS: túneis cifrados para outros roteadores (site a site) e para notebooks e celulares (acesso remoto). Cada interface WireGuard é uma interface (`wg0`) que endereços, rotas e regras de firewall citam como qualquer outra; os pares são as outras pontas.

## Como o CoreRouter faz
- O caminho dos pacotes é o WireGuard do kernel; o roteador manda só o que mudou, então editar um par nunca derruba os outros.
- As chaves nascem no roteador e ficam seladas na configuração.
- Erros que o kernel esconderia são recusados: um prefixo em dois pares, um par com a chave da própria interface.
- Cada par tem um estado calculado pelos tempos do protocolo: `up`, `idle`, `no-handshake`, `never`."##,
    ),
    (
        "wireguard.accept_firewall",
        r##"## O que é
Quando o firewall `input` derruba o UDP da porta da interface (a checagem avisa), marque: a mesma transação cria uma regra `accept` para a porta logo antes da regra que derruba (o assistente de firewall). Sem ela, os pares não alcançam esta interface."##,
    ),
    (
        "wireguard.disabled",
        r##"## O que é
Fica na configuração, fora do kernel: uma interface desativada derruba os túneis dela; um par desativado para só aquele túnel."##,
    ),
    (
        "wireguard.interface",
        r##"## O que é
Uma interface WireGuard: uma porta UDP onde chegam os pacotes cifrados, um par de chaves e os pares com quem ela fala (o `/interface wireguard` do RouterOS).

## Antes de aplicar
A janela confere a porta (de outra interface, de um serviço do roteador), se o firewall `input` deixa entrar UDP nela vindo da WAN, e se o MTU cabe no da WAN menos os 80 bytes do WireGuard. Os comandos que serão executados aparecem embaixo.

## Depois
Dê a ela um endereço (IP › Addresses, `10.9.0.1/24`) e adicione os pares."##,
    ),
    (
        "wireguard.listen_port",
        r##"## O que é
A porta UDP onde chegam os pacotes cifrados. Padrão 13231 (RouterOS); uma segunda interface pega a próxima livre.

## Cuidado
Os pares precisam alcançá-la: aceite UDP nessa porta no firewall `input`. Duas interfaces não dividem uma porta, e a porta de um serviço do roteador (DNS 53, NTP 123, IPsec 500/4500…) falha enquanto o serviço roda."##,
    ),
    (
        "wireguard.mtu",
        r##"## O que é
O maior pacote que o túnel carrega. Padrão 1420: 1500 menos os 80 bytes que o WireGuard acrescenta sobre IPv6 (32 dele, 8 do UDP, 40 do IPv6; whitepaper §5.4.6).

## Quando mudar
Sobre uma WAN com MTU menor, baixe na mesma medida: sobre PPPoE (1492) use **1412**. Grande demais, e os pacotes cheios são fragmentados ou perdidos: páginas que começam a abrir e travam."##,
    ),
    (
        "wireguard.name",
        r##"## O que é
O nome da interface, usado por endereços, rotas e firewall. Vazio: o primeiro `wireguardN` livre, como no RouterOS. Para renomear depois, renomeie a interface."##,
    ),
    (
        "wireguard.peer",
        r##"## O que é
A outra ponta de um túnel: a chave pública dela, os prefixos de onde ela pode enviar e que são enviados para ela (Allowed Address), e onde encontrá-la (Endpoint) quando este roteador chama primeiro.

## Chaves
Cole a chave pública do par, ou deixe vazio: o roteador gera o par de chaves do cliente, sela a privada e depois entrega a configuração ao cliente.

## Antes de aplicar
A janela confere que nenhum outro par da interface tem estes prefixos (o kernel tiraria um deles em silêncio) e se a rota até o endpoint entraria no próprio túnel."##,
    ),
    (
        "wireguard.peer.allowed_address",
        r##"## O que é
Os prefixos de onde este par pode enviar, e que a interface envia para ele (roteamento por chave): `10.9.0.2/32` para um notebook, as redes atrás dele para uma filial (`10.20.0.0/16`). Vários separados por vírgula; IPv4 e IPv6.

## Cuidado
- Dois pares da mesma interface não podem ter o mesmo prefixo: o kernel o daria ao último e o primeiro deixaria de recebê-lo. Um prefixo menor dentro do de outro par pode (vale o mais específico).
- Não cria rota, como no RouterOS: aponte as redes do par para a interface em IP › Routes.
- `0.0.0.0/0` manda a este par tudo o que nenhum outro par casa."##,
    ),
    (
        "wireguard.peer.client_allowed_address",
        r##"## O que é
O que o cliente manda pelo túnel (`AllowedIPs` do arquivo dele). Vazio: tudo (`0.0.0.0/0, ::/0`), todo o tráfego dele passa por este roteador. Só algumas redes (`10.9.0.0/24, 192.168.88.0/24`): túnel dividido."##,
    ),
    (
        "wireguard.peer.client_dns",
        r##"## O que é
Servidores DNS escritos no arquivo do cliente (`DNS =`), por exemplo o endereço deste roteador no túnel. Vazio: nenhum (o cliente fica com o dele)."##,
    ),
    (
        "wireguard.peer.client_endpoint",
        r##"## O que é
Onde o cliente encontra este roteador (`Endpoint =` do arquivo dele): um nome (`vpn.exemplo.com.br`) ou um endereço, com `:porta` ou não (aí vale a porta da interface). Vazio: o endereço do roteador na WAN; atrás de NAT esse endereço é privado, então ponha aqui o nome público."##,
    ),
    (
        "wireguard.peer.create_routes",
        r##"## O que é
Uma rota estática por esta interface para cada prefixo do par que ainda não tem rota para cá (`ip.route.add gateway=<wg>`), na mesma transação. A rede da própria interface e uma rota que já aponta para cá ficam de fora.

## Cuidado
`0.0.0.0/0` mandaria todo o tráfego do roteador sem rota mais específica para o túnel: a janela pede um sim explícito. As rotas são estáticas comuns: remover o par não as remove."##,
    ),
    (
        "wireguard.peer.endpoint_address",
        r##"## O que é
Para onde vai o primeiro handshake: o endereço público do par, ou um nome DNS (`vpn.exemplo.com.br`) que o roteador resolve, e resolve de novo quando o handshake passa de 3 minutos (o par pode ter mudado de endereço). Vazio: este roteador espera o par chamar (um notebook ou celular atrás de NAT). Depois que o par fala, o kernel o segue quando o endereço muda (roaming): a tabela mostra onde ele está agora, com o selo `roamed`.

## Cuidado
Se uma rota manda o endpoint para dentro desta mesma interface (uma rota padrão pelo túnel), o handshake não chega: crie uma rota de host até o endpoint pelo gateway da WAN."##,
    ),
    (
        "wireguard.peer.endpoint_port",
        r##"## O que é
A porta UDP do par (a porta em que ele escuta), junto com o endereço do endpoint: os dois ou nenhum."##,
    ),
    (
        "wireguard.peer.interface",
        r##"## O que é
A interface WireGuard a que este par pertence. Um par não muda de interface: remova-o e crie na outra."##,
    ),
    (
        "wireguard.peer.last_handshake",
        r##"## O que é
Quando as duas pontas combinaram as chaves da sessão pela última vez. Um túnel vivo faz isso a cada 2 minutos (REKEY_AFTER_TIME); passados 3 minutos (REJECT_AFTER_TIME) nenhum pacote passa até o próximo. `never`: nenhum desde que a interface subiu."##,
    ),
    (
        "wireguard.peer.name",
        r##"## O que é
Um nome para o par, único no roteador (RouterOS 7.15+). Vazio: o primeiro `peerN` livre."##,
    ),
    (
        "wireguard.peer.persistent_keepalive",
        r##"## O que é
Segundos entre pacotes vazios enviados ao par mesmo sem nada a dizer. Desligado por padrão.

## Quando usar
Atrás de NAT ou de firewall com estado: **25 s** mantém o mapeamento aberto, e a outra ponta alcança esta a qualquer hora. Sem ele, um par que só responde aparece `idle` quando não há tráfego, o que é normal."##,
    ),
    (
        "wireguard.peer.preshared_key",
        r##"## O que é
Uma chave simétrica a mais, misturada ao handshake (whitepaper §5.2): uma proteção contra uma quebra futura do Curve25519, como por um computador quântico. Gerada no roteador e selada; as duas pontas precisam dela (a configuração do cliente a leva).

## Ao editar
Marcada mantém a chave que o par tem; desmarcada a remove."##,
    ),
    (
        "wireguard.peer.public_key",
        r##"## O que é
A chave pública do par (`wg pubkey`, 44 caracteres de base64 terminando em `=`). Ela identifica o par: o kernel conhece os pares pela chave, não pelo endereço.

## Vazia
Num par novo, o roteador gera o par de chaves do cliente (o `private-key=auto` do RouterOS) e guarda a privada selada, para entregar a configuração ao cliente. Ao editar, a chave sem mudança mantém o par de chaves."##,
    ),
    (
        "wireguard.peer.responder",
        r##"## O que é
O roteador nunca inicia um handshake com este par: só responde (RouterOS 7.15). Para um par que deve chamar mesmo quando tem endpoint."##,
    ),
    (
        "wireguard.peer.rx",
        r##"## O que é
Bytes recebidos deste par desde que a interface subiu (decifrados, com os handshakes)."##,
    ),
    (
        "wireguard.peer.state",
        r##"## O que é
Como o par está pelo último handshake, pelos tempos do protocolo (whitepaper §6.1):
- **up**: um handshake nos últimos 3 minutos; o túnel passa tráfego.
- **idle**: mais antigo, e nada pede um novo (sem keepalive, sem tráfego): normal.
- **no-handshake**: o roteador tenta (endpoint e keepalive, ou tráfego para enviar) e não tem resposta. Em geral, chave pública errada de um dos lados, ou UDP bloqueado no caminho.
- **never**: nenhum handshake ainda, e o roteador espera o par chamar.
- **disabled**: o par ou a interface dele está desativado.

`responder`: o roteador só responde a este par."##,
    ),
    (
        "wireguard.peer.tx",
        r##"## O que é
Bytes enviados a este par desde que a interface subiu (cifrados, com as tentativas de handshake: um par que nunca responde ainda mostra alguns)."##,
    ),
    (
        "wireguard.peers",
        r##"## O que é
Quantos pares a interface tem, e quantos estão `up` (handshake nos últimos 3 minutos)."##,
    ),
    (
        "wireguard.private_key",
        r##"## O que é
A chave privada da interface (`wg genkey`). Vazia: o roteador gera uma e a sela; ela não aparece de novo (só o `export show-sensitive`, grupo full, mostra).

## Quando preencher
Para trazer um túnel de outro roteador mantendo a chave, cole-a aqui. Digitada ao editar, ela troca a chave: todos os pares precisarão da pública nova. Para gerar um par novo, use Gerar chaves novas… no clique direito."##,
    ),
    (
        "wireguard.public_key",
        r##"## O que é
A chave pública da interface, calculada da privada. Os pares precisam dela: copie pelo clique direito (Copiar chave pública)."##,
    ),
    (
        "wireguard.state",
        r##"## O que é
- **running**: no kernel com as chaves e os pares.
- **disabled**: na configuração, fora do kernel.
- **error**: o kernel recusou (o motivo aparece embaixo da tabela com a linha selecionada), como uma porta já em uso.
- **not running**: ainda não confirmada, ou o backend não tem WireGuard."##,
    ),
    (
        "wireguard.tab.interfaces",
        r##"## O que é
As interfaces WireGuard: porta, MTU, chave pública e quantos pares estão ativos. Duplo clique edita; clique direito copia a chave pública, adiciona um par ou gera um par de chaves novo."##,
    ),
    (
        "wireguard.tab.peers",
        r##"## O que é
Todos os pares de todas as interfaces WireGuard, com o estado do handshake, onde estão, os prefixos e o tráfego. Os selos filtram por interface e por estado; a linha embaixo da tabela diz por que o par selecionado está naquele estado."##,
    ),
    (
        "wireguard.vrf",
        r##"## O que é
A VRF por onde saem e chegam os pacotes **cifrados** (o `vrf` do RouterOS 7.21; `main` = a tabela principal): os handshakes e o UDP do túnel. Não é a VRF da própria interface do túnel (essa é a VRF da interface, em IP › VRF).

## Como
O socket do WireGuard no kernel não se prende a uma interface, então o roteador marca os pacotes dele com a marca de roteamento da VRF e uma regra procura essa marca na tabela da VRF; as duas entram e saem no mesmo commit. Para ouvir nas portas da VRF, o roteador liga o `net.ipv4.udp_l3mdev_accept`.

## Cuidado
Com ele ligado, os serviços UDP do roteador que escutam em todos os endereços (DNS, NTP...) também ouvem nas portas da VRF: filtre-os em IP › Firewall (input). A VRF precisa de rota até os endpoints dos pares."##,
    ),
];
