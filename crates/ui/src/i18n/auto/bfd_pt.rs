//! Portuguese labels and explanations of the Routing › BFD window (G3.6c),
//! each sorted by key (registered by `build.rs`).

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"Address"##, r##"Endereço"##),
    (r##"Authentication"##, r##"Autenticação"##),
    (r##"BFD Peer"##, r##"Peer BFD"##),
    (r##"BFD Profile"##, r##"Perfil BFD"##),
    (r##"Change"##, r##"Mudança"##),
    (r##"Dampening"##, r##"Dampening"##),
    (r##"Detect Time"##, r##"Tempo de detecção"##),
    (r##"Diagnostic"##, r##"Diagnóstico"##),
    (r##"Disabled"##, r##"Desativado"##),
    (r##"Engine"##, r##"Motor"##),
    (r##"Flaps 24h"##, r##"Quedas 24 h"##),
    (r##"History"##, r##"Histórico"##),
    (r##"Interface"##, r##"Interface"##),
    (r##"Jitter p99"##, r##"Jitter p99"##),
    (r##"Key"##, r##"Chave"##),
    (r##"Key ID"##, r##"ID da chave"##),
    (r##"Local Address"##, r##"Endereço local"##),
    (r##"Min RX"##, r##"Min RX"##),
    (r##"Min RX (ms)"##, r##"Min RX (ms)"##),
    (r##"Min TTL (multihop)"##, r##"TTL mínimo (multihop)"##),
    (r##"Min TX"##, r##"Min TX"##),
    (r##"Min TX (ms)"##, r##"Min TX (ms)"##),
    (r##"Multihop"##, r##"Multihop"##),
    (r##"Multiplier"##, r##"Multiplicador"##),
    (r##"Name"##, r##"Nome"##),
    (r##"New BFD Peer"##, r##"Novo peer BFD"##),
    (r##"New BFD Profile"##, r##"Novo perfil BFD"##),
    (r##"New Peer…"##, r##"Novo peer…"##),
    (r##"New Profile…"##, r##"Novo perfil…"##),
    (r##"No BFD session: + adds a peer; Use BFD Everywhere puts the default profile on every BGP connection and OSPF interface."##, r##"Nenhuma sessão BFD: + adiciona um peer; Usar BFD em tudo põe o perfil default em toda conexão BGP e interface OSPF."##),
    (r##"No state change yet."##, r##"Nenhuma mudança de estado ainda."##),
    (r##"Options"##, r##"Opções"##),
    (r##"Passive"##, r##"Passivo"##),
    (r##"Peer"##, r##"Peer"##),
    (r##"Profile"##, r##"Perfil"##),
    (r##"Profiles"##, r##"Perfis"##),
    (r##"Sessions"##, r##"Sessões"##),
    (r##"State"##, r##"Estado"##),
    (r##"The daemon starts the engine with the first session (none in a GUI without daemon)."##, r##"O daemon liga o motor com a primeira sessão (nenhum numa GUI sem daemon)."##),
    (r##"Time"##, r##"Hora"##),
    (r##"Tx/Rx"##, r##"Tx/Rx"##),
    (r##"Use BFD Everywhere"##, r##"Usar BFD em tudo"##),
    (r##"Used by"##, r##"Usada por"##),
    (r##"engine idle"##, r##"motor parado"##),
    (r##"threads"##, r##"threads"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"bfd.attach"##, r##"## O que faz
Põe um perfil BFD (o `default`, 300 ms × 3) em toda conexão BGP e todo interface-template OSPF que ainda não tem um, próprio ou herdado de template. Depois disso o BGP e o OSPF caem quando o BFD detecta a falha, em vez de esperar o hold time (BGP: 90–180 s) ou o dead interval (OSPF: 40 s).

## Cuidado
O outro lado também precisa de BFD para essa sessão; sem ele, a sessão BFD fica em down e **não** derruba nada (o protocolo só segue o BFD depois que ele subiu uma vez)."##),
    (r##"bfd.engine"##, r##"## O que é
O motor BFD do CoreRouter: N threads (`bfd-0`…), cada uma com as próprias sessões, sockets e timer wheel. **reuseport-cbpf**: um programa BPF no grupo de sockets entrega cada pacote à thread dona da sessão, sem lock. A CPU é a de cada thread, em % de um núcleo.

Com o FRR, o motor é o *data plane* do `bfdd`: o `bfdd` cria as sessões pedidas pelo BGP e pelo OSPF e as entrega ao motor, que manda e recebe os pacotes."##),
    (r##"bfd.history.change"##, r##"## O que é
A mudança de estado da sessão (RFC 5880 §6.2): `down`, `init`, `up`, `admin-down`. **dampened**: a sessão voltou, mas o dampening a mantém caída para os clientes."##),
    (r##"bfd.history.diag"##, r##"## O que é
O diagnóstico da RFC 5880 §4.1: por que a sessão caiu.

- **control-detection-time-expired**: nenhum pacote no tempo de detecção (o enlace ou o vizinho morreu).
- **neighbor-signaled-session-down**: o vizinho disse que caiu (ou foi desligado por quem o opera: admin-down, que não conta como falha, RFC 5882 §3.2).
- **administratively-down**: desligado aqui."##),
    (r##"bfd.history.time"##, r##"## O que é
Quando a mudança aconteceu (relógio do roteador). A data só aparece quando não é o dia do evento mais recente."##),
    (r##"bfd.peer"##, r##"## O que é
Uma sessão BFD explícita (como `peer` do FRR): o endereço do vizinho e o perfil. BGP e OSPF pedem as suas sessões pelo campo `bfd` deles; um peer serve para vigiar um caminho sem protocolo (ou um vizinho estático)."##),
    (r##"bfd.peer.address"##, r##"## O que é
O endereço do vizinho BFD (IPv4 ou IPv6). Junto com multihop e o endereço local, identifica a sessão: dois peers iguais são a mesma sessão."##),
    (r##"bfd.peer.disabled"##, r##"## O que é
Desliga a sessão sem tirá-la da config."##),
    (r##"bfd.peer.interface"##, r##"## O que é
Prende a sessão de salto único a uma interface (opcional). Multihop não usa interface."##),
    (r##"bfd.peer.local_address"##, r##"## O que é
O endereço de origem dos pacotes. **Obrigatório no multihop** (RFC 5883 §3: a sessão é o par de endereços). Vazio no salto único: o da rota."##),
    (r##"bfd.peer.multihop"##, r##"## O que é
Vizinho a mais de um salto (RFC 5883): porta 4784 e TTL mínimo do perfil. Sem multihop (RFC 5881): porta 3784, e só entra pacote com TTL 255, o que impede pacote forjado de fora do enlace.

## Recomendado
Multihop atravessa a rede: use autenticação SHA1 no perfil."##),
    (r##"bfd.peer.name"##, r##"## O que é
O nome do peer. Vazio: o endereço."##),
    (r##"bfd.peer.profile"##, r##"## O que é
O perfil com os intervalos, o multiplicador, o dampening e a autenticação desta sessão."##),
    (r##"bfd.profile"##, r##"## O que é
Um conjunto de timers e opções que BGP, OSPF e os peers usam pelo nome (como `bfd-template` do Cisco e `bfd profile` do FRR). Dois vêm de fábrica: **default** (300 ms × 3, detecção em 900 ms) e **fast** (50 ms × 3, 150 ms). Remover um de fábrica volta aos valores de fábrica."##),
    (r##"bfd.profile.auth"##, r##"## O que é
Autenticação dos pacotes (RFC 5880 §6.7.4): **keyed-sha1** ou **meticulous-keyed-sha1** (número de sequência novo em todo pacote: nenhum replay passa). MD5 e senha simples não são oferecidos.

## Recomendado
meticulous-keyed-sha1 no multihop; no salto único o TTL 255 já protege."##),
    (r##"bfd.profile.auth_key_id"##, r##"## O que é
O número da chave (0–255), igual nos dois lados."##),
    (r##"bfd.profile.auth_secret"##, r##"## O que é
A chave compartilhada, de 1 a 20 bytes, igual nos dois lados. Ao editar, vazio mantém a atual."##),
    (r##"bfd.profile.dampening"##, r##"## O que é
Cada queda soma 1000 de penalidade, que cai à metade a cada 15 s; acima de 2500 (umas 3 quedas seguidas) a sessão fica **dampened**: o BFD continua rodando, mas BGP e OSPF a veem caída até ela ficar quieta (~30 s) ou passarem 120 s.

## Por que ligado
Um enlace que oscila derrubaria e subiria o BGP a cada oscilação (a RFC 5882 §3.2 pede que o cliente amorteça)."##),
    (r##"bfd.profile.detect"##, r##"## O que é
O tempo de detecção: multiplicador × o maior entre Min TX e Min RX (RFC 5880 §6.8.4). É o tempo sem pacotes até a sessão cair."##),
    (r##"bfd.profile.min_rx"##, r##"## O que é
O menor intervalo em que aceitamos receber (Required Min RX, ms). O vizinho manda no maior entre o dele e este."##),
    (r##"bfd.profile.min_ttl"##, r##"## O que é
No multihop, o menor TTL aceito (RFC 5883 §5). 254: o vizinho a um roteador de distância. Não vale no salto único (sempre 255)."##),
    (r##"bfd.profile.min_tx"##, r##"## O que é
O intervalo desejado entre os nossos pacotes depois de up (Desired Min TX, ms). Fora de up é sempre ≥ 1 s (RFC 5880 §6.8.3).

## Cuidado
Abaixo de 100 ms cada sessão manda dezenas de pacotes por segundo: confira a CPU por thread no rodapé de Sessions."##),
    (r##"bfd.profile.multiplier"##, r##"## O que é
Quantos intervalos sem pacote derrubam a sessão (Detect Mult). 3 é o usual; 1 ou 2 caem com uma ou duas perdas."##),
    (r##"bfd.profile.name"##, r##"## O que é
O nome do perfil, como BGP (`bfd`), OSPF (interface-template `bfd`) e os peers o citam."##),
    (r##"bfd.profile.options"##, r##"## O que é
**dampening**: amortece quedas seguidas. **passive**: espera o vizinho falar primeiro (RFC 5880 §6.1). **sha1**: pacotes autenticados."##),
    (r##"bfd.profile.passive"##, r##"## O que é
Modo passivo (RFC 5880 §6.1): não manda nada até o vizinho falar. Útil num servidor de rotas com muitos vizinhos; pelo menos um lado precisa ser ativo."##),
    (r##"bfd.profile.used_by"##, r##"## O que é
Quem usa o perfil: peers, conexões e templates BGP, interface-templates OSPF."##),
    (r##"bfd.session.detect"##, r##"## O que é
O tempo de detecção em vigor: o multiplicador do vizinho × o maior entre o nosso Min RX e o Min TX dele (RFC 5880 §6.8.4)."##),
    (r##"bfd.session.flaps"##, r##"## O que é
Quantas vezes a sessão caiu de up nas últimas 24 h (quedas pedidas pelo operador do outro lado não contam)."##),
    (r##"bfd.session.jitter"##, r##"## O que é
O p99 do atraso dos nossos pacotes periódicos em relação ao horário marcado: mede a carga do motor. Dezenas de µs é o normal; perto de 1 ms, a máquina está ocupada.

Não confundir com o jitter proposital da RFC 5880 §6.8.7 (intervalo de 75 a 100 %), que não entra aqui."##),
    (r##"bfd.session.peer"##, r##"## O que é
O endereço do vizinho. **multihop**: sessão por mais de um salto (RFC 5883)."##),
    (r##"bfd.session.state"##, r##"## O que é
- **up**: a sessão está de pé.
- **down**: sem resposta (veja o diagnóstico em History).
- **init**: o vizinho falou, falta a confirmação (handshake de três vias).
- **dampened**: up, mas mantida caída para os clientes pelo dampening.
- **inactive**: pedida pela config, o motor não a roda (GUI sem daemon, ou o FRR ainda não a entregou)."##),
    (r##"bfd.session.txrx"##, r##"## O que é
O intervalo com que mandamos (o maior entre o nosso Min TX e o Min RX do vizinho) e o Min RX que o vizinho pediu."##),
    (r##"bfd.session.users"##, r##"## O que é
Quem pediu a sessão: **BGP** (conexão com `bfd`), **OSPF** (interface-template com `bfd`), **peer** (routing.bfd.peer) ou **FRR** (digitada no FRR à mão). Quando a sessão cai, todos esses caem juntos."##),
    (r##"bfd.tab.history"##, r##"## O que é
As mudanças de estado das sessões, a mais nova primeiro, com o diagnóstico e o tempo de detecção."##),
    (r##"bfd.tab.profiles"##, r##"## O que é
Os perfis: intervalos, multiplicador, dampening e autenticação compartilhados por BGP, OSPF e peers."##),
    (r##"bfd.tab.sessions"##, r##"## O que é
As sessões BFD ao vivo: quem as usa, o estado, os timers, o tempo de detecção, o jitter do motor e as quedas em 24 h."##),
];
