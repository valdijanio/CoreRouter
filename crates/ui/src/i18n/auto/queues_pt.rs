//! Portuguese labels and explanations of the Queues window (G4.9), each
//! sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("95th pct", r##"Percentil 95"##),
    ("A dynamic queue comes from a session, a DHCP lease or a DHCP network: change its rate there.", r##"Uma fila dinâmica vem de uma sessão, de um lease ou de uma rede do DHCP: mude a taxa lá."##),
    ("Addresses", r##"Endereços"##),
    ("Advanced", r##"Avançado"##),
    ("At Limit", r##"No limite"##),
    ("Average", r##"Média"##),
    ("BFIFO Limit", r##"Limite BFIFO"##),
    ("Bucket Size", r##"Tamanho do balde"##),
    ("Burst", r##"Rajada"##),
    ("Burst Average", r##"Média da rajada"##),
    ("Burst Limit", r##"Limite de rajada"##),
    ("Burst Threshold", r##"Limiar de rajada"##),
    ("Burst Time", r##"Tempo de rajada"##),
    ("Bytes", r##"Bytes"##),
    ("CAKE RTT", r##"RTT do CAKE"##),
    ("CSV", r##"CSV"##),
    ("Current", r##"Atual"##),
    ("Day", r##"Dia"##),
    ("Disabled", r##"Desativada"##),
    ("Download", r##"Download"##),
    ("Download Mode", r##"Modo de download"##),
    ("Drops", r##"Descartes"##),
    ("Drops/s", r##"Descartes/s"##),
    ("FQ-CoDel ECN", r##"ECN do FQ-CoDel"##),
    ("FQ-CoDel Interval", r##"Intervalo do FQ-CoDel"##),
    ("FQ-CoDel Target", r##"Alvo do FQ-CoDel"##),
    ("General", r##"Geral"##),
    ("History", r##"Histórico"##),
    ("Hour", r##"Hora"##),
    ("IPv6 Mask", r##"Máscara IPv6"##),
    ("Keep History", r##"Guardar histórico"##),
    ("Kept from now on: the first points come within a minute.", r##"Guardado a partir de agora: os primeiros pontos chegam em até um minuto."##),
    ("Kind", r##"Tipo"##),
    ("Limit At", r##"Garantido"##),
    ("Max Limit", r##"Limite máximo"##),
    ("Maximum", r##"Máximo"##),
    ("Name", r##"Nome"##),
    ("New Per-IP Limit", r##"Novo limite por IP"##),
    ("New Per-IP Limit…", r##"Novo limite por IP…"##),
    ("New Queue Type", r##"Novo tipo de fila"##),
    ("New Queue Type…", r##"Novo tipo de fila…"##),
    ("New Simple Queue", r##"Nova fila simples"##),
    ("New Simple Queue…", r##"Nova fila simples…"##),
    ("Not kept: the history would pass the graphing memory cap (Graphs → Settings).", r##"Não guardado: o histórico passaria do teto de memória dos gráficos (Graphs → Settings)."##),
    ("Origin", r##"Origem"##),
    ("PCQ Addresses", r##"Endereços PCQ"##),
    ("PCQ Classifier", r##"Classificador PCQ"##),
    ("PCQ IPv6 Mask", r##"Máscara IPv6 do PCQ"##),
    ("PCQ Rate", r##"Taxa PCQ"##),
    ("PFIFO Limit", r##"Limite PFIFO"##),
    ("Packet Rate", r##"Taxa de pacotes"##),
    ("Packets", r##"Pacotes"##),
    ("Pause", r##"Pausar"##),
    ("Per-IP (PCQ)", r##"Por IP (PCQ)"##),
    ("Per-IP Limit", r##"Limite por IP"##),
    ("Priority", r##"Prioridade"##),
    ("Queue", r##"Fila"##),
    ("Queue (ms)", r##"Fila (ms)"##),
    ("Queue Delay", r##"Atraso na fila"##),
    ("Queue Type", r##"Tipo de fila"##),
    ("Queue Types", r##"Tipos de fila"##),
    ("Queued", r##"Espera na fila"##),
    ("Queued p95", r##"Espera p95"##),
    ("Queues", r##"Filas"##),
    ("Rate", r##"Taxa"##),
    ("Rate Each", r##"Taxa de cada"##),
    ("Resume", r##"Continuar"##),
    ("Settings", r##"Ajustes"##),
    ("Simple Queue", r##"Fila simples"##),
    ("Simple Queues", r##"Filas simples"##),
    ("Sniffer", r##"Sniffer"##),
    ("Statistics", r##"Estatísticas"##),
    ("Target", r##"Alvo"##),
    ("This queue's history is not kept. Turn on Keep History to record it (the live Traffic tab works without it).", r##"O histórico desta fila não é guardado. Ligue Guardar histórico para gravá-lo (a aba Traffic ao vivo funciona sem ele)."##),
    ("Torch", r##"Torch"##),
    ("Traffic", r##"Tráfego"##),
    ("Upload", r##"Upload"##),
    ("Used By", r##"Usado por"##),
    ("Waiting for the router…", r##"Esperando o roteador…"##),
    ("Week", r##"Semana"##),
    ("Window", r##"Janela"##),
    ("at limit", r##"no limite"##),
    ("built-in", r##"embutido"##),
    ("bursting", r##"em rajada"##),
    ("dynamic", r##"dinâmicas"##),
    ("fixed", r##"fixas"##),
    ("in total", r##"no total"##),
    ("left", r##"restantes"##),
    ("max-limit", r##"max-limit"##),
    ("near limit", r##"perto do limite"##),
    ("no limit", r##"sem limite"##),
    ("of", r##"de"##),
    ("off", r##"desligada"##),
    ("per-IP limits", r##"limites por IP"##),
    ("queues", r##"filas"##),
    ("ready", r##"pronta"##),
    ("spent", r##"esgotada"##),
    ("types", r##"tipos"##),
    ("with warnings", r##"com avisos"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    ("menu.queues", "## O que faz\nControla a banda por alvo, como o `/queue` do RouterOS: **Simple Queues** (um endereço, prefixo ou interface com upload/download máximos, burst e o tipo de fila), **Per-IP (PCQ)** (uma taxa igual para cada endereço de uma rede, sem uma fila por cliente) e **Queue Types** (fq-codel, cake, pfifo/bfifo, pcq).\n\nAs filas **dinâmicas** (selo D) vêm das sessões PPPoE/IPoE (perfil ou RADIUS) e dos leases e redes do DHCP; mude a taxa na origem.\n\n## Como funciona\nO download é moldado (EDT + `fq`: os pacotes esperam e saem no ritmo, com CoDel segurando a latência); o upload é policiado. A primeira fila que casa vale (como no RouterOS), e o aviso ⚠ mostra alvo encoberto ou sobreposto."),
    (
        "queues.pcq",
        r##"## O que é
Um limite **por endereço** dentro de um prefixo: "cada IP de 10.0.0.0/16 com 10M/20M". No RouterOS é o PCQ: dois tipos `pcq` (um classificado pela origem para a subida, outro pelo destino para a descida, cada um com a sua `pcq-rate`) e uma fila simples sobre o prefixo que os usa. Este formulário cria os três numa transação; tipos de mesma taxa são reaproveitados.

## Quando usar
Uma rede de clientes sem PPPoE nem DHCP com taxa por cliente: um condomínio, uma rede fixa, um hotspot simples. Para assinantes PPPoE/IPoE o perfil já dá a fila de cada um.

## Cuidado
O **Max Limit** é o teto de todos juntos (0 = sem teto). Editar ou remover a regra é editar ou remover a fila simples (aba Simple Queues); os tipos ficam."##,
    ),
    (
        "queues.pcq.addresses",
        r##"Quantos endereços (sub-fluxos do PCQ) passaram por esta regra recentemente: cada um ganha o seu relógio, criado no primeiro pacote e esquecido quando fica velho (LRU). Contado a cada 10 s."##,
    ),
    (
        "queues.pcq.ipv6_mask",
        r##"Quantos bits de um endereço IPv6 formam um sub-fluxo. **64** (padrão) = um limite por /64, o que um cliente IPv6 recebe; 128 seria um limite por endereço, e um cliente com vários endereços (privacidade, RFC 8981) escaparia dele."##,
    ),
    (
        "queues.pcq.max_limit",
        r##"Teto de todos os endereços juntos, `subida/descida` (0 = sem teto): a fila simples por trás da regra."##,
    ),
    (
        "queues.pcq.rate",
        r##"A taxa de **cada** endereço, `subida/descida` em bits por segundo (`10M/20M`; k, M e G como no RouterOS). 0 num sentido = sem limite por endereço naquele sentido."##,
    ),
    (
        "queues.pcq.target",
        r##"Os prefixos cujos endereços recebem cada um o seu limite (`10.0.0.0/16`, `2001:db8::/48`). Só prefixos: uma interface não se divide em endereços."##,
    ),
    (
        "queues.simple",
        r##"## O que é
Uma fila (RouterOS `/queue simple`): limita a banda de um **alvo** — endereços, prefixos ou uma interface. Todo par é `subida/descida` do ponto de vista do alvo: subida é o que sai dele, descida o que chega.

## Como o CoreRouter segura a taxa
- **Descida**: o que passa da taxa **espera** numa fila (EDT: cada pacote recebe o horário de saída e o `fq` da porta o segura). TCP vê atraso, não perda: mais goodput, menos retransmissão.
- **Subida**: um policer (descarta o que passa), com balde de `bucket-size × taxa`.

## Ordem
Como no RouterOS, a **primeira fila que casa vence**: um alvo dentro do alvo de uma fila acima nunca casa (o formulário avisa). Filas **dinâmicas** (sessões, DHCP) vencem as fixas no próprio endereço.

## Cuidado
`limit-at` e `priority` ficam guardados, mas uma fila sem filhas é moldada no `max-limit` (a árvore de filas é a G4.9e)."##,
    ),
    (
        "queues.simple.bucket_size",
        r##"O balde de cada sentido como fração da taxa (RouterOS v7): **0.1** (padrão) = 100 ms da taxa podem sair de uma vez depois de uma pausa. No policer de subida é o "burst ≈ RTT × taxa" que evita derrubar TCP (Google, 2016); muito pequeno faz o TCP perder pacote à toa, muito grande deixa rajadas longas passarem."##,
    ),
    (
        "queues.simple.burst_limit",
        r##"Taxa durante a **rajada**, `subida/descida`. A rajada vale enquanto a média dos últimos `burst-time` está abaixo do `burst-threshold` (RouterOS). Tem de ser maior que o `max-limit`; 0 = sem rajada."##,
    ),
    (
        "queues.simple.burst_threshold",
        r##"Liga e desliga a rajada: enquanto a média sobre o `burst-time` fica abaixo dele, vale o `burst-limit`; ao alcançá-lo, volta o `max-limit`. Recomendado entre o `limit-at` e o `max-limit`. 0 = o `max-limit`. No longo prazo, um cliente sempre cheio fica com média no limiar."##,
    ),
    (
        "queues.simple.burst_time",
        r##"A janela da **média** que decide a rajada (não é a duração da rajada!). Exemplo do RouterOS: 1M, rajada 2M, limiar 1,5M, 8 s → 6 s a 2M, depois 1M. A média é amostrada em 16 fatias de `burst-time/16`."##,
    ),
    (
        "queues.simple.disabled",
        r##"Desativada fica na config mas sai do plano de dados: o alvo passa sem limite (ou cai na próxima fila que casar)."##,
    ),
    (
        "queues.simple.dropped",
        r##"Pacotes descartados por esta fila nos dois sentidos: na descida, os que esperariam mais que o limite da fila ou que o CoDel escolheu; na subida, os acima da taxa do policer. Num shaper, poucos descartes e fila curta é o desejado."##,
    ),
    (
        "queues.simple.limit_at",
        r##"A taxa **garantida** (CIR) do RouterOS, `subida/descida`. Só faz efeito numa árvore de filas (fila mãe com filhas, G4.9e); hoje fica guardada e cada fila é moldada no seu `max-limit`. Não pode passar do `max-limit`."##,
    ),
    (
        "queues.simple.max_limit",
        r##"A taxa máxima, `subida/descida` em bits por segundo (`10M/50M`; k = 1000, M, G). Um valor só vale para os dois sentidos; **0** = sem limite naquele sentido (a fila só conta)."##,
    ),
    (
        "queues.simple.name",
        r##"Nome único da fila (padrão `queue<N>`, como no RouterOS). Filas dinâmicas têm o nome da origem: `<pppoe-joao>`, `dhcp-ds<host ou MAC>`."##,
    ),
    (
        "queues.simple.origin",
        r##"De onde vem a fila:
- **fixed**: criada aqui (`queue.simple.add`);
- **PPPoE / IPoE**: dinâmica, de uma sessão com `rate-limit` (perfil PPP ou RADIUS `Mikrotik-Rate-Limit`; o CoA muda a taxa sem zerar a fila);
- **DHCP lease**: dinâmica, de um lease estático com `rate_limit`;
- **DHCP network**: dinâmica, de uma rede do DHCP com `rate_limit` (todo cliente dela; não existe no RouterOS).

Selo **D** = dinâmica: não se edita aqui, muda-se na origem. Uma dinâmica vence uma fixa no próprio endereço, e as duas recebem um aviso."##,
    ),
    (
        "queues.simple.priority",
        r##"Prioridade de 1 (maior) a 8 (menor, o padrão), `subida/descida`. Como o `limit-at`, só vale numa árvore de filas (G4.9e); fica guardada."##,
    ),
    (
        "queues.simple.queue",
        r##"Os **tipos de fila** de cada sentido, `subida/descida` (aba Queue Types). Na descida decidem o que fazer com o que espera:
- `pfifo`/`bfifo`: descarta o que passa do limite (o `default-small` do RouterOS é uma FIFO de 10 pacotes: curta para qualquer taxa acima de poucos Mbit/s);
- `fq-codel`/`cake` (**recomendado**): CoDel (RFC 8289) mantém a espera perto de 5 ms e marca ECN em vez de descartar quando o tráfego aceita;
- `pcq`: um limite por endereço dentro do alvo."##,
    ),
    (
        "queues.simple.queued",
        r##"Quanto um pacote que chega agora esperaria na descida desta fila, em milissegundos (o atraso que a fila soma ao ping do cliente). Com `fq-codel`, fica perto de 5–15 ms sob carga; uma FIFO grande pode chegar a centenas."##,
    ),
    (
        "queues.simple.rate",
        r##"Taxa no último segundo, `subida/descida`, medida pelos contadores do plano de dados. O selo **near limit** (ícone de medidor) (perto do limite) aparece quando um dos sentidos está a 90 % do max-limit ou mais: o plano do cliente virou o gargalo. Abra a fila (duplo clique) para ver há quanto tempo, o atraso e os descartes."##,
    ),
    (
        "queues.simple.target",
        r##"O que a fila limita: endereços IPv4/IPv6, prefixos (`10.0.1.0/24`, `2001:db8::/56`) e no máximo uma interface (todo o tráfego dela), separados por vírgula. Alvos de endereço casam antes dos de interface."##,
    ),
    (
        "queues.tab.pcq",
        r##"Limites **por endereço** dentro de prefixos (PCQ do RouterOS): "cada IP de 10.0.0.0/16 com 10M/20M"."##,
    ),
    (
        "queues.tab.simple",
        r##"Todas as filas: as fixas (na ordem: a primeira que casa vence) e as **dinâmicas** de sessões PPPoE/IPoE e do DHCP, com o selo da origem, a fila (ms), os descartes e os avisos de precedência."##,
    ),
    (
        "queues.tab.types",
        r##"Os tipos de fila (`/queue type`): o que uma fila faz com o tráfego que espera. Os embutidos (`default`, `default-small`, `pcq-*-default`, `fq-codel-default`, `cake-default`) existem sempre; editar um guarda uma cópia."##,
    ),
    (
        "queues.type",
        r##"## O que é
Um tipo de fila (RouterOS `/queue type`): `pfifo`, `bfifo`, `pcq`, `fq-codel` ou `cake`. As filas o escolhem por nome, em cada sentido.

## Recomendado
`fq-codel-default` (o padrão das filas dinâmicas aqui; o RouterOS usa `default-small`, uma FIFO de 10 pacotes). `red`, `sfq` e `codel` do RouterOS são recusados: use `fq-codel`."##,
    ),
    (
        "queues.type.bfifo_limit",
        r##"Tamanho da FIFO em **bytes** (padrão 15000). O shaper converte em tempo de espera na taxa da fila."##,
    ),
    (
        "queues.type.cake_rtt",
        r##"RTT de referência do CAKE (padrão 100 ms): o CoDel dele usa alvo = RTT/20 e intervalo = RTT. Diminua numa rede metropolitana (10 ms), aumente para satélite."##,
    ),
    (
        "queues.type.fq_codel_ecn",
        r##"Marcar CE (RFC 3168) num pacote que aceita ECN em vez de descartá-lo: o TCP reduz sem perder o pacote. Ligado por padrão, como no RouterOS."##,
    ),
    (
        "queues.type.fq_codel_interval",
        r##"Janela do CoDel (padrão 100 ms, RFC 8289): a espera tem de ficar acima do alvo por um intervalo inteiro antes do primeiro descarte. Da ordem do RTT dos clientes."##,
    ),
    (
        "queues.type.fq_codel_target",
        r##"A espera aceitável (padrão 5 ms): acima dela por um intervalo inteiro, o CoDel começa a descartar (ou marcar) em ritmo crescente. Tem de ser menor que o intervalo (5–10% dele)."##,
    ),
    (
        "queues.type.kind",
        r##"- `pfifo`: FIFO em pacotes; `bfifo`: FIFO em bytes;
- `pcq`: um limite por endereço (`pcq-rate`), classificado pela origem (subida) ou pelo destino (descida);
- `fq-codel`: CoDel na espera, ECN;
- `cake`: o mesmo CoDel com alvo e intervalo pelo RTT.

Na descida o shaper EDT põe cada pacote na hora certa; o tipo decide quando descartar."##,
    ),
    (
        "queues.type.name",
        r##"Nome do tipo, que as filas e os perfis PPP usam. Os embutidos não mudam de nome."##,
    ),
    (
        "queues.type.pcq_classifier",
        r##"O que forma um sub-fluxo do PCQ: `dst-address` (descida: cada cliente pelo destino) ou `src-address` (subida: cada cliente pela origem). As portas do RouterOS não são usadas: o shaper separa por endereço."##,
    ),
    (
        "queues.type.pcq_mask6",
        r##"Bits do endereço IPv6 de destino que formam um sub-fluxo (128 = cada endereço; 64 = cada /64, o recomendado para clientes IPv6)."##,
    ),
    (
        "queues.type.pcq_rate",
        r##"A taxa de cada sub-fluxo, bits por segundo. 0 = os sub-fluxos só dividem o limite da fila."##,
    ),
    (
        "queues.type.pfifo_limit",
        r##"Tamanho da FIFO em **pacotes** (padrão 50). Curta demais descarta rajadas de TCP; longa demais faz bufferbloat. Para clientes, prefira `fq-codel`."##,
    ),
    (
        "queues.type.settings",
        r##"Os parâmetros do tipo, num resumo: limite da FIFO, taxa e classificador do PCQ, alvo e intervalo do CoDel, RTT do CAKE."##,
    ),
    (
        "queues.type.used_by",
        r##"As filas e os perfis PPP que usam este tipo. Um tipo em uso não pode ser removido nem renomeado."##,
    ),
    ("queues.view", r##"## O que é
A janela de uma fila só (duplo clique numa linha), como a do WinBox: **General** e **Advanced** são os ajustes (só leitura numa fila dinâmica: mude na origem), **Traffic** o tráfego ao vivo, **Statistics** os contadores e **History** o histórico de hora, dia e semana.

## Custo
Enquanto ela está aberta, o roteador é consultado sobre **esta fila** uma vez por segundo (`queue.simple.stats`), sem percorrer as outras; fechada, nada roda."##),
    ("queues.view.advanced", r##"O garantido (limit-at), a prioridade, o tamanho do balde, o tipo de fila e **Guardar histórico**. O limit-at e a prioridade valem quando houver a árvore de filas (G4.9e)."##),
    ("queues.view.at_limit", r##"Há quantos segundos seguidos a fila está a 95 % do max-limit ou mais. A partir de 10 s aparece o selo **no limite**: o plano do cliente é o gargalo."##),
    ("queues.view.burst_average", r##"A média da taxa no burst-time contra o burst-threshold (0 = o max-limit). Entre parênteses, quantos segundos da janela já foram lidos desde que esta janela abriu."##),
    ("queues.view.burst_state", r##"## Estados
- **pronta**: a média está abaixo do burst-threshold; a fila pode passar do max-limit até o burst-limit.
- **em rajada**: está passando do max-limit agora; ao lado, quantos segundos restam até a média alcançar o limiar.
- **esgotada**: a média passou do limiar; a fila volta ao max-limit até a média baixar.
- **desligada**: sem burst-limit.

## Como é calculado
Como no RouterOS: média da taxa no burst-time contra o burst-threshold. A média aqui vem das leituras de 1 s com a janela aberta (estimada; o plano de dados tem o relógio exato)."##),
    ("queues.view.bytes", r##"Bytes contados pela fila desde que ela foi instalada no plano de dados (zera quando a fila é recriada)."##),
    ("queues.view.csv", r##"Salva os pontos da janela mostrada (hora UTC, Unix, upload e download em bits/s, atraso em ms, descartes/s) num arquivo CSV."##),
    ("queues.view.delay", r##"Quanto um pacote que entra agora na fila de download espera até sair, e o **p95** dos últimos 5 minutos. Alguns ms é normal numa fila no limite; dezenas de ms indicam bufferbloat (o CoDel do fq-codel/cake segura isso)."##),
    ("queues.view.download", r##"O que chega ao alvo agora (bits/s) e quanto isso é do max-limit de download. O download é **moldado**: o que passa do limite espera na fila (e só é descartado se a fila encher)."##),
    ("queues.view.download_mode", r##"Como o download desta sessão é limitado: **shaper** (fila: espera e sai no ritmo) ou **policer** (descarta o excesso). Vem do perfil PPP."##),
    ("queues.view.dropped", r##"Pacotes descartados desde o início: no download quando a fila encheu ou o CoDel descartou; no upload quando passaram do policer. Entre parênteses, a fração de todos os pacotes."##),
    ("queues.view.drops", r##"Pacotes descartados por segundo (os dois sentidos) e o total. Numa fila no limite, descartar é o esperado: é assim que o TCP do cliente aprende a taxa. O selo **no limite** aparece quando a fila fica acima de 95 % do max-limit por 10 s seguidos."##),
    ("queues.view.general", r##"Nome, alvo, limite máximo e a rajada (burst) da fila. Numa fila dinâmica (sessão PPPoE/IPoE, lease ou rede do DHCP) os valores vêm do perfil, do RADIUS ou do DHCP e aparecem só para leitura."##),
    ("queues.view.history", r##"## O que mostra
O histórico da fila em **hora** (1 s), **dia** (1 min) e **semana** (5 min), com o máximo de cada intervalo e o **p95** (o valor que o tráfego passa só 5 % do tempo, o que se cobra num link).

## Quando existe
Só para as filas cujo histórico é guardado: as fixas (por padrão) e as dinâmicas que você marcar (**Guardar histórico**). Com 10 mil assinantes, guardar todos custaria GBs de memória (~440 KiB por fila); por isso as dinâmicas vêm desligadas."##),
    ("queues.view.history.avg", r##"A média do intervalo."##),
    ("queues.view.history.current", r##"O último valor do intervalo."##),
    ("queues.view.history.max", r##"O maior valor do intervalo (o pico de cada ponto, não só a média)."##),
    ("queues.view.history.p95", r##"O valor que o tráfego passa só 5 % do tempo no intervalo: ignora os picos curtos; é o que se usa para cobrar um link."##),
    ("queues.view.keep", r##"## O que faz
Guarda o histórico desta fila nos gráficos (`queue:<nome>`: taxas, descartes e atraso), para a aba History e para exportar.

## Padrão
Ligado nas filas fixas, desligado nas dinâmicas. Numa dinâmica a marca fica pelo nome (`<pppoe-ana>`): o cliente que reconecta continua no mesmo histórico.

## Custo
~440 KiB por fila (um ano de pontos), dentro do teto de memória dos gráficos; o que não couber fica de fora e aparece em Graphs → Settings."##),
    ("queues.view.packets", r##"Pacotes contados pela fila desde que ela foi instalada no plano de dados."##),
    ("queues.view.pause", r##"Congela o gráfico para olhar com calma. Os pontos continuam chegando por trás; Continuar volta ao agora."##),
    ("queues.view.pcq", r##"Numa fila com tipo PCQ: quantos endereços (sub-fluxos) estão ativos agora, cada um com o seu limite."##),
    ("queues.view.pps", r##"Pacotes por segundo, da diferença entre duas leituras dos contadores (aparece depois de dois segundos com a janela aberta)."##),
    ("queues.view.queued", r##"Quanto um pacote que entra agora espera na fila (só o download tem fila; o upload é policiado)."##),
    ("queues.view.queued_p95", r##"O p95 da espera nos últimos 5 minutos em que a janela esteve aberta: 95 % do tempo a espera ficou abaixo disso."##),
    ("queues.view.rate", r##"Bits por segundo no último segundo, em cada sentido (upload = o que o alvo manda; download = o que ele recebe)."##),
    ("queues.view.span", r##"O intervalo do histórico: a última hora (ponto de 1 s), o último dia (1 min) ou a última semana (5 min)."##),
    ("queues.view.statistics", r##"Os contadores da fila em cada sentido: taxa, pacotes por segundo, bytes e pacotes desde o início, descartes (e a fração dos pacotes), a espera agora e o seu p95 dos últimos 5 min, há quanto tempo está no limite e o estado da rajada. Numa fila PCQ, quantos endereços estão ativos."##),
    ("queues.view.tools", r##"Abre o **Torch** (quem está usando a banda agora, por fluxo) ou o **Sniffer** (captura de pacotes) já com o endereço do alvo desta fila e, numa sessão, a sua interface."##),
    ("queues.view.traffic", r##"## O que mostra
O tráfego da fila ao vivo, um ponto por segundo, nos últimos 1, 5 ou 15 minutos: **download** em azul e **upload** em vermelho, com o **max-limit** de cada lado tracejado.

## Como ler
Uma linha encostada no tracejado é uma fila **no limite**: o cliente quer mais do que o plano. O atraso na fila e os descartes dizem se isso está doendo (espera alta, descartes subindo).

## De onde vem
Dos contadores do plano de dados, lidos uma vez por segundo pelo serviço `queue`; os pontos ficam nesta janela (e o roteador guarda os últimos 15 min desta fila enquanto alguém olha)."##),
    ("queues.view.upload", r##"O que o alvo manda agora (bits/s) e quanto isso é do max-limit de upload. O upload é **policiado**: o que passa do limite é descartado na entrada, sem fila."##),
    ("queues.view.window", r##"Quantos minutos o gráfico mostra: 1, 5 ou 15. A janela guarda os últimos 15 min, então trocar não perde pontos."##),
];
