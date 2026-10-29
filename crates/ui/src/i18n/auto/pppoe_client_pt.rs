//! Portuguese labels and explanations of PPP › PPPoE Client (G3.9ga), each
//! sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"AC MAC"##, r##"MAC do AC"##),
    (r##"AC Name"##, r##"Nome do AC"##),
    (r##"Add Default Route"##, r##"Rota padrão"##),
    (r##"Address"##, r##"Endereço"##),
    (r##"Allow"##, r##"Permitir"##),
    (r##"DNS"##, r##"DNS"##),
    (r##"Default Route"##, r##"Rota padrão"##),
    (r##"Default Route Distance"##, r##"Distância da rota padrão"##),
    (r##"Disabled"##, r##"Desativado"##),
    (r##"Dropped"##, r##"Descartados"##),
    (r##"Encoding"##, r##"Autenticação"##),
    (r##"Error"##, r##"Erro"##),
    (r##"Interface"##, r##"Interface"##),
    (r##"Keepalive Timeout"##, r##"Tempo do keepalive"##),
    (r##"Last Down"##, r##"Última queda"##),
    (r##"Local Address"##, r##"Endereço local"##),
    (r##"MTU / MRU"##, r##"MTU / MRU"##),
    (r##"Max MRU"##, r##"MRU máximo"##),
    (r##"Max MTU"##, r##"MTU máximo"##),
    (r##"Name"##, r##"Nome"##),
    (r##"New PPPoE Client"##, r##"Novo cliente PPPoE"##),
    (r##"New PPPoE Client…"##, r##"Novo cliente PPPoE…"##),
    (r##"Packets in / out"##, r##"Pacotes entrada / saída"##),
    (r##"Password"##, r##"Senha"##),
    (r##"Profile"##, r##"Perfil"##),
    (r##"Reconnect"##, r##"Reconectar"##),
    (r##"Remote Address"##, r##"Endereço remoto"##),
    (r##"Select an enabled client first"##, r##"Selecione um cliente ativo primeiro"##),
    (r##"Select one client to see its session."##, r##"Selecione um cliente para ver a sessão dele."##),
    (r##"Service Name"##, r##"Nome do serviço"##),
    (r##"Session ID"##, r##"ID da sessão"##),
    (r##"State"##, r##"Estado"##),
    (r##"Status"##, r##"Estado"##),
    (r##"Uptime"##, r##"Tempo de sessão"##),
    (r##"Use Peer DNS"##, r##"Usar DNS do provedor"##),
    (r##"User"##, r##"Usuário"##),
    (r##"ac-error"##, r##"servidor recusou"##),
    (r##"authenticating"##, r##"autenticando"##),
    (r##"clients"##, r##"clientes"##),
    (r##"closed here"##, r##"fechada aqui"##),
    (r##"connected"##, r##"conectado"##),
    (r##"connecting"##, r##"conectando"##),
    (r##"dialing"##, r##"discando"##),
    (r##"disabled"##, r##"desativado"##),
    (r##"disconnected"##, r##"desconectado"##),
    (r##"disconnecting"##, r##"desconectando"##),
    (r##"distance"##, r##"distância"##),
    (r##"down"##, r##"fora do ar"##),
    (r##"error"##, r##"erro"##),
    (r##"link negotiation failed"##, r##"negociação do enlace falhou"##),
    (r##"login refused"##, r##"login recusado"##),
    (r##"no address from the server"##, r##"servidor não deu endereço"##),
    (r##"no server answered"##, r##"nenhum servidor respondeu"##),
    (r##"peer"##, r##"par"##),
    (r##"redial in"##, r##"redisca em"##),
    (r##"server ended the session"##, r##"servidor encerrou a sessão"##),
    (r##"server refused the session"##, r##"servidor recusou a sessão"##),
    (r##"server stopped answering"##, r##"servidor parou de responder"##),
    (r##"service not offered"##, r##"serviço não oferecido"##),
    (r##"stopped"##, r##"parado"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "interface.pppoe-client",
        r##"## O que é
Um cliente PPPoE: o roteador disca para o servidor PPPoE do provedor (RFC 2516) por uma porta Ethernet ou VLAN, e recebe endereço e DNS pela sessão. É o `/interface pppoe-client` do RouterOS.

## Antes de aplicar
A janela confere por você:
- se outra rota padrão (estática, DHCP client, outro PPPoE) tem a mesma distância e dividiria o tráfego;
- se ficou sem rota padrão nenhuma;
- se o MTU passa de 1492 (só com RFC 4638 no provedor).

Os comandos que ela vai rodar aparecem embaixo.

## Cuidado
Mexer na porta por onde você gerencia o roteador pode derrubar a sua sessão: use o **Safe Mode**."##,
    ),
    (
        "interface.pppoe-client.ac_name",
        r##"## O que é
Aceita só ofertas do concentrador (AC) com este nome. Em branco, fica com a primeira oferta. Útil num segmento com mais de um BNG, para escolher o do provedor."##,
    ),
    (
        "interface.pppoe-client.add_default_route",
        r##"## O que é
Instala a rota padrão (0.0.0.0/0) pela sessão enquanto ela está de pé. O padrão é **não**, como no RouterOS: ligue numa WAN de provedor.

## Cuidado
Se outro uplink (DHCP client, outro PPPoE, rota estática) também põe rota padrão com a **mesma distância**, os dois dividem o tráfego (ECMP). Para ter um link de backup, dê a ele uma distância maior."##,
    ),
    (
        "interface.pppoe-client.address",
        r##"## O que é
O endereço que o provedor deu pela sessão (IPCP) e, depois de `par`, o endereço do servidor do outro lado. Os dois aparecem também em IP › Addresses e IP › Routes como entradas dinâmicas."##,
    ),
    (
        "interface.pppoe-client.allow",
        r##"## O que é
Os métodos de login aceitos: `mschap2`, `mschap1`, `chap`, `pap`. O padrão são todos, como no RouterOS; o servidor escolhe entre eles.

## Cuidado
`pap` manda a senha em claro na rede do provedor: tire-o se o servidor aceitar CHAP."##,
    ),
    (
        "interface.pppoe-client.default_route_distance",
        r##"## O que é
A distância (preferência) da rota padrão: menor ganha. O padrão é 1. Num link de backup, use um número maior que o do principal (ex.: 2)."##,
    ),
    (
        "interface.pppoe-client.disabled",
        r##"## O que é
Desativado, o cliente fica na configuração mas não disca. Ao desativar, o roteador encerra a sessão no provedor (PADT) na hora."##,
    ),
    (
        "interface.pppoe-client.interface",
        r##"## O que é
A porta Ethernet, a VLAN, o bond ou a bridge por onde o roteador procura o servidor PPPoE (o PADI sai por ela em broadcast).

## Quando mudar
Muitos provedores de fibra entregam o PPPoE numa VLAN (ex.: 10, 600): crie a VLAN em Interfaces e escolha-a aqui."##,
    ),
    (
        "interface.pppoe-client.keepalive_timeout",
        r##"## O que é
Quantos segundos sem resposta aos ecos LCP até a sessão ser dada como caída. O padrão é 60 s (RouterOS). O roteador manda um eco a cada um terço desse tempo. `disabled` desliga.

## Cuidado
Muito curto derruba a sessão em congestionamento; muito longo demora a perceber que o provedor caiu."##,
    ),
    (
        "interface.pppoe-client.max_mru",
        r##"## O que é
O maior pacote que o roteador aceita receber pela sessão (o MRU anunciado no LCP). O padrão é 1460, como o max-mtu."##,
    ),
    (
        "interface.pppoe-client.max_mtu",
        r##"## O que é
O maior pacote que o roteador manda pela sessão. O padrão é 1460 (RouterOS). O PPPoE tira 8 bytes do Ethernet, então o máximo normal é 1492 (RFC 2516 §7).

## Quando mudar
Acima de 1492 (até 1500) só se o provedor aceitar o RFC 4638 (PPP-Max-Payload) e a rede até ele levar quadros maiores."##,
    ),
    (
        "interface.pppoe-client.name",
        r##"## O que é
O nome da interface da sessão, que o firewall, as rotas e o DHCPv6 client usam. Em branco, o roteador escolhe o primeiro livre: `pppoe-out1`, `pppoe-out2`… (como o RouterOS)."##,
    ),
    (
        "interface.pppoe-client.password",
        r##"## O que é
A senha do provedor. CHAP e MS-CHAP precisam dela em claro, então o roteador a guarda lacrada (cifrada com uma chave fora da configuração). A lista mostra `***`; só o grupo full vê a senha (show_sensitive).

Ao editar, deixe em branco para manter a senha atual."##,
    ),
    (
        "interface.pppoe-client.profile",
        r##"## O que é
O perfil PPP (`/ppp profile`) da sessão. Do cliente, ele usa:
- `change-tcp-mss`: ajusta o MSS dos SYN TCP ao MTU da sessão (v4 e v6). O perfil `default` liga.
- `use-ipv6`: negocia o IPv6CP (link-local); o prefixo vem do DHCPv6 client sobre a interface."##,
    ),
    (
        "interface.pppoe-client.service_name",
        r##"## O que é
O Service-Name pedido no PADI (RFC 2516 §5.1). Em branco, aceita qualquer servidor. Preencha só se o provedor pedir ou se houver mais de um servidor PPPoE no mesmo segmento."##,
    ),
    (
        "interface.pppoe-client.status",
        r##"## O que é
O estado da sessão:
- **conectado**: de pé, com endereço;
- **discando / conectando / autenticando**: em negociação;
- **desconectado**: caiu ou não subiu. O selo âmbar diz o motivo, e a linha diz quando disca de novo;
- **desativado**.

## A espera entre tentativas
Cresce de 1 s a 60 s, com uma variação para os clientes não discarem juntos. Quando o provedor recusa a senha, espera pelo menos 30 s: assim uma senha errada não martela o BNG dele. **Reconectar** disca na hora."##,
    ),
    (
        "interface.pppoe-client.uptime",
        r##"## O que é
Há quanto tempo a sessão está de pé."##,
    ),
    (
        "interface.pppoe-client.use_peer_dns",
        r##"## O que é
Usa os servidores DNS que o provedor manda na negociação (IPCP, RFC 1877) como servidores dinâmicos do `/ip dns`. O padrão é **não**, como no RouterOS."##,
    ),
    (
        "interface.pppoe-client.user",
        r##"## O que é
O usuário que o provedor deu (muitas vezes `cliente@provedor`). Vai no PAP, CHAP ou MS-CHAP, conforme o servidor pedir."##,
    ),
    (
        "menu.pppoe-client",
        r##"## O que faz
`/interface pppoe-client` do RouterOS: o roteador disca para o servidor PPPoE do provedor e usa a sessão como WAN. Cada cliente é uma interface (`pppoe-out1`), que o firewall, as rotas e o DHCPv6 client nomeiam como qualquer outra.

## Como o CoreRouter faz
- Discagem própria em Rust, com os nomes e padrões do RouterOS v7.
- Se a sessão cai, disca de novo esperando cada vez mais (1 s até 60 s), e pelo menos 30 s quando o provedor recusa a senha, para não martelar o BNG dele.
- Depois de um reboot, encerra no BNG a sessão antiga (PADT) antes de discar de novo."##,
    ),
];
