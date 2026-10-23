//! Portuguese labels and explanations of IP › Addresses (G1.28), each
//! sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (
        "ARP Check",
        r##"Checar ARP"##,
    ),
    (
        "Address",
        r##"Endereço"##,
    ),
    (
        "Disabled",
        r##"Desativado"##,
    ),
    (
        "From Pool",
        r##"Do pool"##,
    ),
    (
        "Interface",
        r##"Interface"##,
    ),
    (
        "New Address",
        r##"Novo endereço"##,
    ),
    (
        "New Address…",
        r##"Novo endereço…"##,
    ),
    (
        "Series to",
        r##"Série até"##,
    ),
    (
        "addresses",
        r##"endereços"##,
    ),
    (
        "disabled",
        r##"desativados"##,
    ),
    (
        "invalid",
        r##"inválidos"##,
    ),
    (
        "tentative",
        r##"em DAD"##,
    ),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "ip.address",
        r##"## O que é
Um endereço IP de uma interface do roteador (no RouterOS, `/ip address` e `/ipv6 address`). Cada endereço também cria a rota conectada da sua rede.

## Antes de aplicar
A janela confere por você:
- se o mesmo endereço já existe em outro lugar;
- se a rede se sobrepõe à de outra interface (na mesma VRF);
- se algum host na rede já responde por ele (ARP, RFC 5227);
- se a mudança corta a sessão pela qual você gerencia o roteador.

Os comandos que ela vai rodar aparecem embaixo.

## Cuidado
Remover ou desativar o endereço pelo qual você está conectado derruba a sua sessão. Entre no **Safe Mode** antes: se o roteador parar de ouvir você, ele desfaz a mudança."##,
    ),
    (
        "ip.address.address",
        r##"## O que é
O endereço e o tamanho do prefixo da rede: `10.20.0.1/24`, `2001:db8::1/64`.

Enquanto você digita, a janela calcula embaixo a rede, o broadcast e quantos hosts cabem.

## Cuidado
Um endereço sem `/len` vira um /32: um host só, sem vizinhos. Escreva o prefixo. Um /31 (RFC 3021) serve para enlace ponto a ponto."##,
    ),
    (
        "ip.address.arp",
        r##"## O que é
Antes de pôr um endereço IPv4, a janela pergunta à rede se alguém já usa esse endereço. Ela manda uma sonda ARP e espera pouco. Pela RFC 5227 a sonda sai com remetente 0.0.0.0, então nenhum vizinho aprende nada com ela. No lab virtual, o roteador do lab responde pelo próprio endereço.

No IPv6 não precisa: o kernel faz sozinho a detecção de endereço duplicado (RFC 4862), e a lista mostra `tentative` enquanto isso.

## Desligado
Desmarque para pular a sonda. Ela é um pacote e leva até 2 s."##,
    ),
    (
        "ip.address.comment",
        r##"## O que é
Texto livre guardado com o endereço: quem usa, para quê, o id do circuito. Aparece na lista."##,
    ),
    (
        "ip.address.disabled",
        r##"## O que é
Um endereço desativado fica na configuração e sai do plano de dados (o kernel): sem tráfego e sem rota conectada. Para voltar, ative com ✓.

Serve para guardar um endereço reserva ou um que vai voltar depois."##,
    ),
    (
        "ip.address.from_pool",
        r##"## O que é
Só IPv6 (no RouterOS, `from-pool`). O endereço é a parte depois do prefixo que um cliente DHCPv6 recebeu delegado neste pool: `::1/64` vira `<prefixo delegado>::1/64`. Quando o provedor troca o prefixo, o endereço acompanha."##,
    ),
    (
        "ip.address.interface",
        r##"## O que é
A interface que recebe o endereço: porta, VLAN, bridge, bond ou loopback. A VRF da interface decide em que tabela a rota conectada entra.

## Cuidado
Duas interfaces na mesma tabela com redes que se sobrepõem disputam os mesmos hosts, e a rota conectada vai para uma só delas. Por isso a janela recusa."##,
    ),
    (
        "ip.address.to",
        r##"## O que é
Opcional: o último endereço de uma **série**. De `10.20.0.1/24` até `10.20.0.5` são cinco endereços numa transação só: entram todos ou nenhum.

## Limites
A série fica na mesma família e na mesma rede, com no máximo 256 endereços de uma vez."##,
    ),
];
