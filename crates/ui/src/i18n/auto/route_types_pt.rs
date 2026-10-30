//! Portuguese explanation of IP › Routes' route type (G1.5a).

/// Labels: (English, Portuguese). The types are RouterOS words, kept.
pub(super) const LABELS: &[(&str, &str)] = &[];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[(
    "routes.type",
    "## Tipo

O que a rota faz com o pacote, como o `type` do RouterOS v6 (no v7, `blackhole`):

- `unicast`: segue pelo **Gateway** (o normal).
- `blackhole`: descarta calado. Para anular um pool, um agregado de CGNAT ou o prefixo que o BGP anuncia (com distância 254 ela vale só quando o caminho real cai).
- `unreachable`: descarta e responde ICMP \"rede inalcançável\" a quem mandou (o `reject` do Junos).
- `prohibit`: descarta e responde ICMP \"proibido administrativamente\".

Uma rota sem gateway não tem o que verificar (sem Check Gateway) e não divide a distância com uma rota de outro tipo para o mesmo destino: o kernel guarda uma rota por prefixo, distância e tabela. Uma rota mais específica continua ganhando (a de prefixo mais longo). Com `redistribute static` no BGP ou no OSPF ela é anunciada como as outras estáticas.",
)];
