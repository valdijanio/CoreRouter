//! Portuguese labels and explanations of the CGNAT window (G2.3d), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("A subscriber with a public address of its own (1:1), outside every pool.", "Assinante com IP público próprio (1:1), fora de qualquer pool."),
    ("Alert %", "Alerta %"),
    ("Alerts", "Alertas"),
    ("Applied under Safe Mode: confirm with the Safe Mode button, or it rolls back.", "Aplicado em Safe Mode: confirme no botão Safe Mode, ou volta sozinho."),
    ("Apply with Safe Mode", "Aplicar com Safe Mode"),
    ("Asked for (UTC)", "Pedido (UTC)"),
    ("Block Timeout", "Tempo do bloco ocioso"),
    ("Block log", "Log de blocos"),
    ("Blocks", "Blocos"),
    ("CGNAT", "CGNAT"),
    ("CGNAT Exception", "Exceção CGNAT"),
    ("CGNAT Pool", "Pool CGNAT"),
    ("Capacity", "Capacidade"),
    ("Date and Time", "Data e hora"),
    ("Endpoint-Independent Filtering", "Filtro independente do destino"),
    ("Endpoint-Independent Mapping", "Mapeamento independente do destino"),
    ("Every change of the pools, with its time (RFC 7422 §3): who was reads the one in force.", "Cada mudança dos pools, com a hora (RFC 7422 §3): o Quem era? usa a que estava em vigor."),
    ("Exceptions", "Exceções"),
    ("Hairpin", "Hairpin"),
    ("History", "Histórico"),
    ("History kept", "Histórico guardado"),
    ("Hit the limit, 24 h", "Bateram no limite, 24 h"),
    ("ICMP Unreachable", "ICMP inalcançável"),
    ("Inside", "Internos"),
    ("Last", "Última"),
    ("Logging", "Registros de NAT"),
    ("Mapping", "Mapeamento"),
    ("Mapping valid", "Mapeamento válido"),
    ("Max Blocks", "Máx. de blocos"),
    ("Mode", "Modo"),
    ("New CGNAT Exception", "Nova exceção CGNAT"),
    ("New CGNAT Pool", "Novo pool CGNAT"),
    ("New connections dropped for lack of a port (RFC 6888 REQ-11)", "Conexões novas descartadas por falta de porta (RFC 6888 REQ-11)"),
    ("New connections the kernel could not translate: no free port", "Conexões novas que o kernel não traduziu: sem porta livre"),
    ("No pool yet.", "Nenhum pool ainda."),
    ("No suggestion: no readings yet, or a blocks-mode pool (grow max_blocks instead).", "Sem sugestão: ainda sem leituras, ou pool no modo blocos (aumente max_blocks)."),
    ("Out. Interface", "Interface de saída"),
    ("Outside", "Públicos"),
    ("Peak", "Pico"),
    ("Peak distribution", "Distribuição do pico"),
    ("Peak p99, 7 days", "Pico p99, 7 dias"),
    ("Per IP", "Por IP"),
    ("Per public address", "Por IP público"),
    ("Pool", "Pool"),
    ("Pools", "Pools"),
    ("Port Range", "Faixa de portas"),
    ("Ports per Subscriber", "Portas por assinante"),
    ("Preview", "Prévia"),
    ("Preview this value first", "Faça a prévia deste valor antes"),
    ("Public", "Público"),
    ("Public Address", "IP público"),
    ("Public addresses", "IPs públicos"),
    ("Refused", "Recusadas"),
    ("Since", "Desde"),
    ("Subscriber or public", "Assinante ou público"),
    ("Subscribers", "Assinantes"),
    ("Subscribers near the end of their ports: their new connections are checked for a free port", "Assinantes perto do fim das portas: as conexões novas deles são conferidas (há porta livre?)"),
    ("Suggestion", "Sugestão"),
    ("Times", "Vezes"),
    ("Until", "Até"),
    ("Used", "Em uso"),
    ("Waiting for the router…", "Esperando o roteador…"),
    ("Who Was", "Quem era?"),
    ("Who used a public address and port at a given time (Marco Civil, Lei 12.965/2014 art. 13).", "Quem usava um IP público e porta num dado momento (Marco Civil, Lei 12.965/2014 art. 13)."),
    ("Why", "Motivo"),
    ("already right", "já está certo"),
    ("blocks in use", "blocos em uso"),
    ("connections dropped", "conexões derrubadas"),
    ("connections refused", "conexões recusadas"),
    ("days", "dias"),
    ("does not fit", "não cabe"),
    ("in force", "em vigor"),
    ("more than 1 % of the subscribers ran out of ports in 24 h", "mais de 1 % dos assinantes ficou sem portas em 24 h"),
    ("needed of", "necessários de"),
    ("now", "agora"),
    ("of", "de"),
    ("p99 of the 7-day peaks plus 25 %", "p99 dos picos de 7 dias mais 25 %"),
    ("peaks of the last 7 days", "picos dos últimos 7 dias"),
    ("per public address", "por IP público"),
    ("since", "desde"),
    ("subscribers remapped", "assinantes remapeados"),
    ("subscribers seen", "assinantes vistos"),
    ("suggested", "sugerido"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "cgnat.alert_percent",
        "## Alert %

Quando um assinante usa esta parte das suas portas (determinístico) ou do último bloco permitido (blocos), o roteador registra um alerta (log `warning`, tópico `cgnat`, e a aba Alerts). Uma linha por vez que cruza o limite.

**Padrão:** 90 %. 0 desliga. **RFC 7422 §2.2:** alarmes por utilização.",
    ),
    (
        "cgnat.alerts",
        "## Alerts

Assinantes que chegaram perto do limite de portas: quantas usam, o pico, quantas vezes cruzaram o limite e quando. **Recusadas:** conexões novas descartadas porque não havia porta livre, e quantos ICMP o assinante recebeu sobre elas (RFC 6888 REQ-11).

**O que fazer:** mais portas por assinante (aba Capacity), uma exceção 1:1, ou investigar (P2P, máquina infectada) pela aba Connections do Firewall.",
    ),
    (
        "cgnat.block_timeout",
        "## Block Timeout

Modo blocos: quanto tempo um bloco **sem nenhuma conexão** fica com o assinante antes de ser devolvido (e o \"RELEASE\" ir ao log). Devolvido, ele fica 120 s sem ir para ninguém (RFC 6888 REQ-8).

**Padrão:** 2 min. Mais longo = menos linhas de log e mais blocos presos.",
    ),
    (
        "cgnat.blocks",
        "## Blocks

Os blocos de portas em uso (modo blocos): de quem, em que IP, desde quando, qual é o atual (onde entram as conexões novas) e há quanto tempo um bloco está ocioso. Embaixo, o log de blocos (alocação e devolução), que o \"Quem era?\" consulta.",
    ),
    (
        "cgnat.capacity",
        "## Capacity

**O que é:** quantas portas os assinantes deste pool usam de verdade, e quantas portas por assinante isso pede. A cada 10 s o roteador lê as conexões (fora do caminho dos pacotes) e guarda, por assinante, o **pico de cada dia** dos últimos 7 dias.

**Para que serve:** dimensionar `ports_per_subscriber`. Portas demais desperdiçam IP público; de menos, o assinante fica sem conexão nova (\"um site não abre\").

**Vistos:** só entram os assinantes que tiveram conexões nos 7 dias; os outros não pesam na conta.",
    ),
    (
        "cgnat.capacity.apply",
        "## Prévia e Aplicar com Safe Mode

**Prévia:** conta, sem mudar nada, quantos assinantes **mudam de IP ou de portas** (mudar as portas por assinante remapeia o pool inteiro) e quantas **conexões vivas serão derrubadas** — o roteador as derruba no commit, para o \"Quem era?\" continuar exato.

**Aplicar com Safe Mode:** liga o Safe Mode e muda `ports_per_subscriber`. Se a sessão cair ou você não confirmar no botão Safe Mode, tudo volta sozinho. O histórico do \"Quem era?\" guarda a mudança com a hora (RFC 7422 §3).

**Cuidado:** os assinantes perdem as conexões em curso. Prefira a madrugada.",
    ),
    (
        "cgnat.capacity.bands",
        "## Distribuição do pico

Quantos assinantes têm o pico de 7 dias em cada faixa do limite: até 25 %, 25–50 %, 50–75 %, 75–90 %, 90–100 % e **100 %** (encostaram no limite).

Um pool bem dimensionado tem quase todos nas primeiras faixas e poucos acima de 90 %.",
    ),
    (
        "cgnat.capacity.hit",
        "## Bateram no limite, 24 h

Assinantes que tiveram **conexão nova recusada por falta de porta** nas últimas 24 h (RFC 6888 REQ-11), quantas conexões foram recusadas e quantos **ICMP host unreachable** o roteador mandou a eles (com o limite de taxa por assinante).

Zero é o normal. Muitos aqui pedem mais portas por assinante; um só costuma ser P2P ou máquina infectada: veja a aba Alerts e as Connections do Firewall.",
    ),
    (
        "cgnat.capacity.p99",
        "## Pico p99, 7 dias

Pega o **maior uso de cada assinante** nos últimos 7 dias (no protocolo mais cheio: TCP, UDP ou ICMP) e mostra o valor que **99 %** deles não passam. O % é sobre o limite atual.

**Verde** abaixo de 75 %, **âmbar** até 90 %, **vermelho** acima: o 1 % mais pesado já encosta no limite.",
    ),
    (
        "cgnat.capacity.ports",
        "## Ports per Subscriber

O limite de cada assinante hoje: `ports_per_subscriber` (no modo blocos, vezes `max_blocks`), e quantos assinantes cabem em cada IP público com ele.",
    ),
    (
        "cgnat.capacity.suggestion",
        "## Sugestão

**Como é calculada:** o pico p99 dos 7 dias mais 25 % de folga, arredondado para cima em múltiplos de 64, nunca abaixo de 320. Se mais de 1 % dos assinantes ficou sem porta em 24 h, pelo menos 1,5 × o valor de hoje.

**Ganho:** quantos assinantes a mais (ou a menos) cabem em cada IP público, e quantos IPs públicos o pool passa a precisar. \"Não cabe\" quer dizer que faltam IPs públicos para todos os assinantes com esse valor.

**Pode digitar outro valor** antes da prévia. O 1 % mais pesado pode continuar batendo no limite: uma exceção 1:1 resolve o caso dele sem gastar porta de todos.",
    ),
    (
        "cgnat.comment",
        "## Comment

Texto livre para quem lê a configuração.",
    ),
    (
        "cgnat.disabled",
        "## Disabled

O pool fica na configuração mas sai do kernel: os assinantes dele saem sem NAT por ele (e o forward não descarta o bloco público).",
    ),
    (
        "cgnat.endpoint_independent_filtering",
        "## Endpoint-Independent Filtering (EIF, \"full cone\")

Qualquer host da Internet alcança um mapeamento UDP vivo do assinante, não só os que ele procurou. Melhora jogos e P2P.

**Padrão:** desligado. **Cuidado:** expõe o assinante a quem descobrir a porta. Exige EIM. **RFC 4787 REQ-8** e RFC 6888 REQ-7 (EIF recomendado).",
    ),
    (
        "cgnat.endpoint_independent_mapping",
        "## Endpoint-Independent Mapping (EIM)

A mesma porta pública para **todos os destinos** de uma porta UDP do assinante, guardada por 5 min sem tráfego. É o que jogos, VoIP e WebRTC precisam para funcionar atrás de CGNAT.

**Padrão:** ligado. **RFC 4787 REQ-1** (MUST) e REQ-5 (timer ≥ 2 min, 5 min recomendado).",
    ),
    (
        "cgnat.exception",
        "## Exceptions (1:1)

Um assinante com um IP público **só dele** (cliente empresarial, câmera, servidor): sai com as portas originais e recebe todo o tráfego de entrada daquele IP.

O IP precisa estar fora de qualquer pool. O slot do assinante no pool fica reservado e vazio, então criar ou apagar uma exceção não remapeia ninguém.",
    ),
    (
        "cgnat.exception.comment",
        "## Comment

Quem é (contrato, cliente).",
    ),
    (
        "cgnat.exception.public",
        "## Public

O IP público dele, fora de qualquer pool e roteado para o roteador.",
    ),
    (
        "cgnat.exception.subscriber",
        "## Subscriber

O endereço interno do assinante (100.64.x.y).",
    ),
    (
        "cgnat.hairpin",
        "## Hairpin

Um assinante alcança outro pelo IP:porta **público** (o mesmo endereço que um amigo de fora usaria), e quem recebe vê o IP:porta público de quem mandou.

**Padrão:** ligado. **RFC 4787 REQ-9** (MUST).",
    ),
    (
        "cgnat.history_days",
        "## History kept

Quantos dias o roteador guarda o histórico de definições dos pools e o log de blocos, que respondem ao \"Quem era?\".

**Padrão:** 365. O **Marco Civil** (Lei 12.965/2014, art. 13) obriga o provedor de conexão a guardar os registros de conexão por 1 ano. Mude com `ip.firewall.cgnat.set history_days=…`.",
    ),
    (
        "cgnat.icmp_unreachable",
        "## ICMP Unreachable

**O que é:** quando um assinante abre uma conexão nova e não sobra porta livre na faixa dele, o roteador descarta o pacote (RFC 6888 REQ-11a) e **avisa o assinante** com um ICMP *destination unreachable*, código 1 (*host unreachable*), citando o pacote como ele o enviou (REQ-11b). Sem isso, o kernel descarta em silêncio e o aplicativo espera até o tempo esgotar.

**Por que código 1:** é um erro \"leve\" (RFC 1122 §4.2.3.9): o TCP do assinante continua tentando, e conecta assim que uma porta se libera.

**Como funciona:** só os assinantes perto do fim das portas (80 % da faixa, contado a cada 10 s) têm as conexões novas conferidas; os outros nunca saem do kernel. **Limite:** até `icmp_rate` mensagens por segundo por assinante (padrão 2) e 1000 por segundo no roteador, para uma rajada de SYN não virar amplificador.

**Mudar:** `ip.firewall.cgnat.set icmp_unreachable=no` desliga; `icmp_rate=1..100`.",
    ),
    (
        "cgnat.inside",
        "## Inside

As faixas dos **assinantes**, na ordem em que entram na fórmula: `100.64.0.0/22`, `100.64.4.0-100.64.4.99` ou um endereço, separadas por vírgula.

**Padrão:** o espaço compartilhado **100.64.0.0/10** (RFC 6598 §4), feito para CGNAT: não colide com a LAN do cliente (RFC 1918) nem é roteado na Internet.

**Cuidado:** mudar a ordem ou o tamanho remapeia os assinantes depois do ponto mudado (o \"Quem era?\" continua certo: cada mudança fica no histórico). Acrescentar no **fim** não remapeia ninguém.",
    ),
    (
        "cgnat.mapping",
        "## Mapping

A tabela assinante – IP público e portas da fórmula (modo determinístico), uma página de 500 por vez. Filtre por um assinante (a linha dele) ou por um IP público (os assinantes daquele IP, uma sequência contígua).

Assinantes com exceção 1:1 aparecem apagados com o selo do IP próprio.",
    ),
    (
        "cgnat.max_blocks",
        "## Max Blocks

Modo blocos: quantos blocos um assinante pode ter ao mesmo tempo. Ele ganha outro quando o atual passa de 80 % de uso.

**Padrão:** 4. **Cuidado:** um assinante no máximo e com o último bloco cheio não abre conexões novas (o pacote cai: RFC 6888 REQ-11) e aparece em Alerts.",
    ),
    (
        "cgnat.mode",
        "## Mode

- **deterministic** (padrão, RFC 7422): cada assinante tem IP público e faixa de portas fixos, calculados por fórmula. **Nada é registrado** por conexão nem por assinante: o \"Quem era?\" sai da fórmula e do histórico de definições.
- **blocks** (PBA, RFC 6888 §5): o assinante ganha um bloco de portas quando aparece, outro quando enche, e cada bloco dado ou devolvido vira **uma linha de log** (tópico `cgnat`, vai ao syslog remoto).

**Quando mudar:** use *blocks* quando houver mais assinantes que blocos (nem todos online ao mesmo tempo) ou quando a política exigir log por bloco.

**Cuidado:** em *blocks*, sem o serviço `cgnat` rodando ninguém do pool sai (o primeiro pacote espera na fila 7422 e cai). Trocar de modo remapeia todo mundo.",
    ),
    (
        "cgnat.name",
        "## Name

Nome do pool, usado nos comandos e no log (`pool c1`). Único.",
    ),
    (
        "cgnat.out_interface",
        "## Out. Interface

Traduz só o que sai por esta interface (vazio: qualquer uma). Útil com mais de um uplink, quando um deles não deve ter NAT.",
    ),
    (
        "cgnat.outside",
        "## Outside

Os endereços **públicos** do pool, na ordem da fórmula. O bloco deve estar **roteado para o roteador** (o upstream manda o tráfego dele para cá); não precisa estar configurado numa interface.

**Quantos:** assinantes ÷ (portas da faixa ÷ portas por assinante). A validação diz quantos faltam. O planner em Tools › IP Calculator faz a conta.

**Cuidado:** não use o IP do próprio roteador (as conexões dele disputam as portas) nem endereços privados.",
    ),
    (
        "cgnat.pool",
        "## Pool CGNAT

Um conjunto de assinantes (faixas internas) que sai pelos mesmos IPs públicos, com uma faixa de portas para cada um. Os números (assinantes por IP, capacidade, quantos assinantes mudam de lugar ao editar) e as checagens aparecem enquanto você digita; o OK manda exatamente os comandos mostrados.",
    ),
    (
        "cgnat.port_range",
        "## Port Range

As portas de cada IP público que o pool distribui. **Padrão 1024-65535.**

**Cuidado:** abaixo de 1024 ficam as portas bem conhecidas (RFC 4787 REQ-3): um assinante pegaria a porta 80 ou 443 de alguém. A sobra do fim (portas que não completam um bloco) não é usada.",
    ),
    (
        "cgnat.ports_per_subscriber",
        "## Ports per Subscriber

Quantas portas cada assinante tem (determinístico) ou quantas cada bloco tem (blocos). TCP, UDP e o id do ICMP usam a mesma faixa, cada protocolo à parte.

**Quanto:** 1000 é o padrão; abaixo de ~300 um navegador com várias abas e um celular já esgotam. Jogos, P2P e câmeras pedem mais.

**Cuidado:** mais portas = menos assinantes por IP público. Mudar remapeia todo mundo (as conexões vivas são derrubadas para o \"Quem era?\" continuar exato).

**RFC 6888 REQ-4:** o limite por assinante é obrigatório e configurável.",
    ),
    (
        "cgnat.who.port",
        "## Port

A **porta de origem** usada naquele momento. Sem a porta, num CGNAT o IP aponta para dezenas de assinantes: é por isso que a lei pede IP **e porta** (Marco Civil, art. 13; a Anatel e os tribunais pedem a porta lógica de origem).",
    ),
    (
        "cgnat.who.public",
        "## Public Address

O IP público que aparece no ofício ou na reclamação de abuso.",
    ),
    (
        "cgnat.who.time",
        "## Date and Time

Unix ou RFC 3339: `2026-05-03T14:02:00-03:00`. **Escreva o fuso**: ofícios costumam vir em horário de Brasília (-03:00); sem fuso é UTC. Vazio = agora.

A resposta usa a definição de pool **em vigor naquele instante** (RFC 7422 §3) ou, no modo blocos, o bloco que estava com o assinante.",
    ),
];
