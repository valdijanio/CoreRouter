//! Portuguese labels and explanations of Tools › IP Calculator (G6.9), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("/64 networks in each", "Redes /64 em cada"),
    ("Addresses it adds", "Endereços que ela acrescenta"),
    ("Aggregated", "Agregados"),
    ("CGNAT planner", "Planejar CGNAT"),
    ("Calculate", "Calcular"),
    ("Convert", "Converter"),
    ("Copy CSV", "Copiar CSV"),
    ("Copy as RouterOS script", "Copiar como script RouterOS"),
    ("Copy printable", "Copiar para imprimir"),
    ("Create CGNAT pool", "Criar pool CGNAT"),
    ("DHCPv6-PD pools", "Pools de DHCPv6-PD"),
    ("Delegate", "Delegar"),
    ("Delegations", "Delegações"),
    ("First host", "Primeiro host"),
    ("Generated rules (nftables)", "Regras geradas (nftables)"),
    ("IP Calculator", "Calculadora IP"),
    ("IPv6 PD", "IPv6 PD"),
    ("Last host", "Último host"),
    ("Mapping preview", "Prévia do mapeamento"),
    ("No IPv6 pool yet (IPv6 › DHCP › Pool).", "Nenhum pool IPv6 ainda (IPv6 › DHCP › Pool)."),
    ("Pool name", "Nome do pool"),
    ("Ports if spread evenly", "Portas se distribuídas por igual"),
    ("Ports left on each address", "Portas que sobram em cada IP"),
    ("Public addresses", "IPs públicos"),
    ("Public addresses needed", "IPs públicos necessários"),
    ("Public addresses spare", "IPs públicos sobrando"),
    ("Range to prefixes", "Faixa para prefixos"),
    ("Scope", "Escopo"),
    ("Split", "Dividir"),
    ("Subnet", "Sub-rede"),
    ("Subscribers", "Assinantes"),
    ("Summarize", "Sumarizar"),
    ("Supernet", "Super-rede"),
    ("Type the subscribers and the public addresses.", "Digite os assinantes e os IPs públicos."),
    ("View rules", "Ver regras"),
    ("Wildcard", "Wildcard"),
    ("addresses", "endereços"),
    ("capacity", "de capacidade"),
    ("does not fit", "não cabe"),
    ("fits", "cabe"),
    ("inside this prefix", "dentro deste prefixo"),
    ("no overlap with the configuration", "sem sobreposição com a configuração"),
    ("per public address", "por IP público"),
    ("subscribers", "assinantes"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "ipcalc.address",
        "## Address

Um endereço com prefixo (`192.168.10.77/24`), com máscara (`10.1.2.3 255.255.255.0`) ou IPv6 (`2001:db8::1/64`). Sem prefixo vale /32 (ou /128).

A resposta traz rede, broadcast, primeiro e último host, quantos hosts, máscara, wildcard (a máscara invertida das ACLs) e o escopo (privado RFC 1918, compartilhado RFC 6598, documentação…).

**Hosts:** /31 tem 2 endereços usáveis (enlace ponto a ponto, RFC 3021) e /32 um. **Sobreposição:** a calculadora avisa se a rede encosta num endereço, rota, pool ou pool CGNAT já configurado.",
    ),
    (
        "ipcalc.inside",
        "## Subscribers

Os assinantes: um número (`4096`, contados a partir de 100.64.0.0) ou as faixas internas (`100.64.0.0/22`, várias separadas por vírgula).

**Padrão da operadora:** o espaço compartilhado 100.64.0.0/10 (RFC 6598), que não colide com a LAN do cliente. O planejador usa a mesma fórmula dos pools (RFC 7422): o que ele mostra é o que o pool vai fazer.",
    ),
    (
        "ipcalc.outside",
        "## Public addresses

Os IPs públicos: um número (`32`, contados a partir de 203.0.113.0, só para a conta) ou as faixas de verdade (`203.0.113.0/27`).

**Quantos:** assinantes ÷ (portas da faixa ÷ portas por assinante). Faltando, o planejador diz quantos acrescentar ou quantas portas cabem com os que você tem.",
    ),
    (
        "ipcalc.pd_length",
        "## Delegate

O tamanho do prefixo entregue a cada cliente por DHCPv6-PD.

**Recomendado:** /56 para residencial (256 redes /64 na casa), /48 para empresa (RFC 6177 e BCP 157 pedem prefixos que deixem o cliente criar várias redes). /64 só serve uma LAN; /60 e /62 são o mínimo aceitável.",
    ),
    (
        "ipcalc.pd_prefix",
        "## Prefix

O bloco IPv6 que a operadora tem para delegar (`2001:db8::/40`). A calculadora diz quantas delegações do tamanho escolhido cabem, lista as primeiras e a última e mostra os pools de DHCPv6-PD (IPv6 › DHCP › Pool) dentro dele.",
    ),
    (
        "ipcalc.range",
        "## Range to prefixes

Transforma uma faixa (primeiro – último) no menor conjunto de prefixos que a cobre exatamente: `10.0.0.1 – 10.0.0.6` vira `10.0.0.1/32, 10.0.0.2/31, 10.0.0.4/31, 10.0.0.6/32`. Útil para regras de firewall e listas de endereços.",
    ),
    (
        "ipcalc.split",
        "## Split

Divide a rede do campo Address em sub-redes de um prefixo (`/26`) ou num número delas (`6` vira 8 de /19 numa /16: arredonda para a potência de 2 acima). Mostra até 4096 sub-redes.",
    ),
    (
        "ipcalc.summarize",
        "## Summarize

Agrega prefixos (separados por vírgula) no menor conjunto equivalente e mostra a super-rede que cobre todos, com quantos endereços a mais ela inclui.

**Cuidado:** anunciar a super-rede inclui os endereços a mais; se eles forem de outra pessoa, o tráfego deles vem para você.",
    ),
];
