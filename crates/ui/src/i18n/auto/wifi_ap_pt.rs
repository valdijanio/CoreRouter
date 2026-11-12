//! Portuguese labels and explanations of the access point of Interfaces ›
//! Wi-Fi (G1.30a), each sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"AP"##, r##"AP"##),
    (r##"Clients"##, r##"Clientes"##),
    (r##"Frequency"##, r##"Frequência"##),
    (r##"Interface"##, r##"Interface"##),
    (r##"MAC Address"##, r##"Endereço MAC"##),
    (r##"Mode"##, r##"Modo"##),
    (r##"No radio is an access point: set Mode to ap on a radio (Radios, double click) to see its clients here."##, r##"Nenhum rádio é ponto de acesso: ponha Modo ap num rádio (Radios, duplo clique) para ver os clientes dele aqui."##),
    (r##"Radar Check"##, r##"Checagem de radar"##),
    (r##"Registration"##, r##"Registro"##),
    (r##"Retries"##, r##"Retransmissões"##),
    (r##"Rx Rate"##, r##"Taxa Rx"##),
    (r##"Standard"##, r##"Padrão"##),
    (r##"Tx Rate"##, r##"Taxa Tx"##),
    (r##"Uptime"##, r##"Tempo conectado"##),
    (r##"Width"##, r##"Largura"##),
    (r##"channel chosen automatically"##, r##"canal escolhido automaticamente"##),
    (r##"clients"##, r##"clientes"##),
    (r##"failed"##, r##"falhou"##),
    (r##"not authorized"##, r##"não autorizado"##),
    (r##"passive channel"##, r##"canal passivo"##),
    (r##"radar check"##, r##"checando radar"##),
    (r##"running"##, r##"no ar"##),
    (r##"starting"##, r##"subindo"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "interface.wifi.clients",
        r##"## Clientes
As estações associadas a este ponto de acesso agora. Cada uma é uma linha da aba Registration."##,
    ),
    (
        "interface.wifi.frequency",
        r##"## Frequência (ponto de acesso)
O canal em que o ponto de acesso trabalha: o número do canal (`36`), a frequência em MHz (`5180`) ou `auto`.

**auto** (o padrão) escolhe o canal mais quieto da última varredura, sem detecção de radar, na banda de Band (5 GHz quando o rádio pode abrir rede lá). Escolhido uma vez, fica até as configurações mudarem.

O roteador recusa canal que o país não permite, canal passivo (no-IR: uma estação responde ali, um ponto de acesso não pode abrir rede) e canal que o rádio não tem. Canal com detecção de radar (DFS, 52 a 144) é aceito: o ponto de acesso escuta um minuto (dez nos canais do radar meteorológico, 120 a 128) antes do primeiro beacon.

Estação ignora este campo."##,
    ),
    (
        "interface.wifi.mode",
        r##"## Modo
- **station**: o roteador entra na rede de alguém (uplink, gerência).
- **ap**: o roteador anuncia a rede e os clientes entram nela. Ponha numa bridge para dar a LAN aos clientes, ou dê um endereço e um servidor DHCP para roteá-los.

O rádio faz um de cada vez. Trocar o modo do rádio por onde esta conexão chega pede Safe Mode (ou force)."##,
    ),
    (
        "interface.wifi.radar",
        r##"## Checagem de radar
Num canal com detecção de radar (DFS) o ponto de acesso escuta antes do primeiro beacon: 60 s, 10 minutos nos canais 120 a 128 (IEEE 802.11h, ETSI EN 301 893). Radar ouvido depois fecha o canal por 30 minutos."##,
    ),
    (
        "interface.wifi.registration.interface",
        r##"## Interface
O ponto de acesso em que o cliente está associado."##,
    ),
    (
        "interface.wifi.registration.mac",
        r##"## Endereço MAC
O endereço do cliente. Celulares costumam usar um aleatório por rede (endereço privado)."##,
    ),
    (
        "interface.wifi.registration.rate",
        r##"## Taxa Tx e Rx
A taxa do último quadro enviado ao cliente (Tx) e recebido dele (Rx), com o modo, o MCS e os fluxos. Muda com o sinal e o ruído."##,
    ),
    (
        "interface.wifi.registration.retries",
        r##"## Retransmissões
A parte dos quadros para o cliente que teve de ser enviada de novo. Âmbar a partir de 10 %, vermelho a partir de 20 %: sinal fraco, interferência ou canal cheio."##,
    ),
    (
        "interface.wifi.registration.security",
        r##"## Segurança
Como o cliente entrou: **WPA3** (SAE, com quadros de gerência protegidos), **WPA2** (PSK) ou **aberta**. Com segurança `auto` o ponto de acesso oferece as duas, e cada cliente usa a melhor que tem. **não autorizado**: associado, ainda no handshake."##,
    ),
    (
        "interface.wifi.registration.standard",
        r##"## Padrão
A geração de Wi-Fi que o cliente fala com o ponto de acesso: 802.11n (Wi-Fi 4), ac (5), ax (6), be (7)."##,
    ),
    (
        "interface.wifi.registration.uptime",
        r##"## Tempo conectado
Há quanto tempo o cliente está associado."##,
    ),
    (
        "interface.wifi.width",
        r##"## Largura (ponto de acesso)
A largura do canal: 20, 40, 80 ou 160 MHz, ou `auto`: 20 MHz em 2,4 GHz (40 ali toma dois dos três canais que não se sobrepõem), a maior até 80 MHz em 5 GHz.

Mais largo é mais rápido perto do ponto de acesso e mais exposto aos vizinhos. 160 MHz atravessa canais de radar em 5 GHz. Todos os canais de 20 MHz do bloco precisam ser permitidos no país."##,
    ),
];
