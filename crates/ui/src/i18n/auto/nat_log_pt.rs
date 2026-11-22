//! Portuguese labels and explanations of IP › Firewall › CGNAT › Logging
//! (G4.4j), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("Add Collector", "Adicionar coletor"),
    ("Collectors", "Coletores"),
    ("Enable", "Ligar"),
    ("Exporter", "Exportador"),
    ("Limits", "Limites"),
    ("NAT logs say who used which address: RFC 8158 §7 asks for them encrypted (transport tls).", "Logs de NAT dizem quem usou qual endereço: a RFC 8158 §7 pede que vão cifrados (transporte tls)."),
    ("No collector receives NAT events: they are only kept on the router (Traffic Flow › Retention).", "Nenhum coletor recebe eventos de NAT: eles só ficam no roteador (Traffic Flow › Retenção)."),
    ("Open Traffic Flow", "Abrir Traffic Flow"),
    ("Port Blocks", "Blocos de portas"),
    ("Queue", "Fila"),
    ("Session Destination", "Destino das sessões"),
    ("Sessions", "Sessões"),
    ("This router has no flow exporter (ip.traffic-flow).", "Este roteador não tem exportador de fluxos (ip.traffic-flow)."),
    ("destination in the session records (Marco Civil art. 14)", "destino nos registros de sessão (Marco Civil art. 14)"),
    ("dropped", "descartados"),
    ("events", "eventos"),
    ("natEvent 16/17: one record per block, with pool, VLAN and login", "natEvent 16/17: um registro por bloco, com pool, VLAN e login"),
    ("natEvent 3/13/18: pool exhausted, subscriber out of ports, alert", "natEvent 3/13/18: pool esgotado, assinante sem portas, alerta"),
    ("natEvent 4/5: one record per connection (high volume)", "natEvent 4/5: um registro por conexão (muito volume)"),
    ("records/min", "registros/min"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    ("nat-log.collectors", "## Collectors\n\nOs coletores de Traffic Flow que recebem eventos de NAT (conteúdo `all` ou `nat`), com o estado de cada um. **Add Collector** abre o destino já preenchido para IPFIX sobre TLS, só NAT, porta 4740.\n\n- **Transport** verde: cifrado (tls). A RFC 8158 §7 pede logs de NAT cifrados.\n- **natEvent:** `RFC 8158` (4/5) ou `1/2 legacy` para coletores antigos.\n- **Lost:** mensagens perdidas (coletor fora do ar por UDP, fila cheia).\n\nO ClickHouse (System › Analytics) é outro destino possível, opcional."),
    ("nat-log.exporter", "## Exporter\n\nO exportador de fluxos do roteador (IP › Traffic Flow): é ele que manda os eventos de NAT. Desligado, nada sai.\n\nUm só exportador para fluxos e NAT: um socket por coletor, os mesmos templates."),
    ("nat-log.nat_events", "## Sessions\n\nUm registro por **conexão** NAT44 (`natEvent` 4 criada, 5 encerrada; RFC 8158 §4.6.1), com origem antes e depois do NAT. Muito volume: num CGNAT grande, dezenas de milhares por segundo. Desligado por padrão; os blocos de portas já bastam para o Marco Civil no modo blocos.\n\nNo modo determinístico não há bloco a registrar: o mapeamento é a fórmula (RFC 7422) e o histórico das pools responde \"quem era\". As sessões só servem se o coletor precisa delas."),
    ("nat-log.nat_events_destination", "## Session Destination\n\nPõe o destino (endereço e porta) nos registros de sessão. **Desligado por padrão:** o Marco Civil (art. 14) proíbe o provedor de conexão de guardar registros de acesso a aplicações, e a RFC 6888 recomenda não registrar o destino."),
    ("nat-log.nat_limits", "## Limits\n\nOs limites do CGNAT (RFC 8158): pool sem bloco livre (`natEvent` 3), assinante sem porta livre (13, cota por usuário — o mesmo momento do ICMP host unreachable do G2.7) e assinante acima do percentual de alerta da pool (18). No máximo um por minuto por pool ou assinante (§5.2)."),
    ("nat-log.nat_port_blocks", "## Port Blocks\n\nNo modo blocos, um registro por bloco de portas alocado (`natEvent` 16) e liberado (17), RFC 8158 §4.6.10: assinante, IP público, faixa de portas, pool e, quando há sessão PPPoE ou IPoE, o login (`userName`) e a VLAN.\n\nO registro vai ao journal do roteador antes de o primeiro pacote do assinante sair."),
    ("nat-log.queue", "## Queue\n\nEventos de bloco e de limite que o CGNAT entregou ao exportador. **Descartados:** a fila (262 144 eventos) encheu porque o exportador ficou para trás; não deveria acontecer."),
];
