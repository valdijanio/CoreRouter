//! Portuguese labels and explanations of the Networks tab views of
//! Interfaces › Wi-Fi (G1.30i), each sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"2.4 GHz"##, r##"2,4 GHz"##),
    (r##"2.4 GHz band"##, r##"banda de 2,4 GHz"##),
    (r##"5 GHz"##, r##"5 GHz"##),
    (r##"5 GHz band"##, r##"banda de 5 GHz"##),
    (r##"6 GHz"##, r##"6 GHz"##),
    (r##"802.1X"##, r##"802.1X"##),
    (r##"A band is swept by scanning: the radio leaves its channel for a moment every few seconds, and the link stalls while it does."##, r##"Uma banda é varrida com scans: o rádio sai do seu canal por um instante a cada poucos segundos, e o enlace para enquanto isso."##),
    (r##"Air"##, r##"Ar"##),
    (r##"All"##, r##"Todas"##),
    (r##"Asking the radio…"##, r##"Perguntando ao rádio…"##),
    (r##"At least 30 s while the radio is on a network"##, r##"No mínimo 30 s com o rádio conectado a uma rede"##),
    (r##"Auto"##, r##"Auto"##),
    (r##"BSSID"##, r##"BSSID"##),
    (r##"Band"##, r##"Banda"##),
    (r##"Bluetooth"##, r##"Bluetooth"##),
    (r##"Busy share of each channel"##, r##"Ocupação de cada canal"##),
    (r##"Channel"##, r##"Canal"##),
    (r##"Channel usage"##, r##"Uso por canal"##),
    (r##"Channels"##, r##"Canais"##),
    (r##"Duration"##, r##"Duração"##),
    (r##"Each scan takes the radio off its network's channel for a moment: the link stalls (latency) while it does."##, r##"Cada scan tira o rádio do canal da rede dele por um instante: o enlace para (latência) enquanto isso."##),
    (r##"Group by channel"##, r##"Agrupar por canal"##),
    (r##"Least busy channel"##, r##"Canal menos ocupado"##),
    (r##"List"##, r##"Lista"##),
    (r##"Load"##, r##"Carga"##),
    (r##"No network heard in this band: Rescan listens on every channel."##, r##"Nenhuma rede ouvida nesta banda: Varrer de novo escuta todos os canais."##),
    (r##"No samples yet: Start listens for the seconds set."##, r##"Nenhuma amostra ainda: Iniciar escuta pelos segundos escolhidos."##),
    (r##"Note"##, r##"Observação"##),
    (r##"OWE"##, r##"OWE"##),
    (r##"Range"##, r##"Faixa"##),
    (r##"Real-time, average and peak"##, r##"Tempo real, média e pico"##),
    (r##"SSID"##, r##"SSID"##),
    (r##"Security"##, r##"Segurança"##),
    (r##"Signal"##, r##"Sinal"##),
    (r##"Sources"##, r##"Fontes"##),
    (r##"Spectrum"##, r##"Espectro"##),
    (r##"Start"##, r##"Iniciar"##),
    (r##"Stop"##, r##"Parar"##),
    (r##"View"##, r##"Visão"##),
    (r##"WEP/WPA"##, r##"WEP/WPA"##),
    (r##"WPA2"##, r##"WPA2"##),
    (r##"WPA2/WPA3"##, r##"WPA2/WPA3"##),
    (r##"WPA3"##, r##"WPA3"##),
    (r##"Waterfall"##, r##"Cascata"##),
    (r##"Wi-Fi"##, r##"Wi-Fi"##),
    (r##"average"##, r##"média"##),
    (r##"carrier"##, r##"portadora"##),
    (r##"channel in use"##, r##"canal em uso"##),
    (r##"client"##, r##"cliente"##),
    (r##"clients"##, r##"clientes"##),
    (r##"counted on every channel"##, r##"medida em todos os canais"##),
    (r##"estimated airtime"##, r##"tempo de ar estimado"##),
    (r##"hidden"##, r##"oculta"##),
    (r##"hopper"##, r##"saltos de frequência"##),
    (r##"leaves the channel"##, r##"sai do canal"##),
    (r##"microwave oven"##, r##"micro-ondas"##),
    (r##"network"##, r##"rede"##),
    (r##"networks"##, r##"redes"##),
    (r##"networks over it"##, r##"redes sobre ele"##),
    (r##"noise floor"##, r##"piso de ruído"##),
    (r##"nothing stands out of the noise"##, r##"nada se destaca do ruído"##),
    (r##"on"##, r##"ativo"##),
    (r##"open"##, r##"aberta"##),
    (r##"overlaps ch"##, r##"sobrepõe ch"##),
    (r##"peak"##, r##"pico"##),
    (r##"real-time"##, r##"tempo real"##),
    (r##"same channel"##, r##"mesmo canal"##),
    (r##"scanning"##, r##"varrendo"##),
    (r##"shares airtime"##, r##"divide o ar"##),
    (r##"stopped"##, r##"parado"##),
    (r##"the driver counts only the channel in use"##, r##"o driver mede só o canal em uso"##),
    (r##"the driver does not count it"##, r##"o driver não mede"##),
    (r##"unknown"##, r##"desconhecida"##),
    (r##"width"##, r##"largura"##),
    (r##"yours"##, r##"a sua"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "interface.wifi.auto",
        r##"## O que é
Atualiza a aba sozinho:
- em **Lista** e **Canais**, faz um scan novo a cada 10, 30 ou 60 segundos;
- em **Espectro**, começa o spectral scan de novo quando a duração acaba.

Começa desligado. Só roda com a janela aberta nesta aba: fechou a janela ou trocou de aba, ele desliga. **Parar** no espectro também desliga.

## Cuidado
Com o rádio conectado a uma rede (estação), cada scan tira o rádio do canal da rede por um instante, uns 3 s para as duas bandas: o enlace para e a latência sobe enquanto isso. Por isso aparece o selo **sai do canal** e o intervalo mínimo vira 30 s. Num rádio que serve de uplink, deixe desligado ou use 60 s."##,
    ),
    (
        "interface.wifi.band-filter",
        r##"## O que é
Mostra só as redes de uma banda: 2,4 GHz, 5 GHz ou 6 GHz. O número em cada selo é quantos pontos de acesso a varredura ouviu nela. Vale para a lista e para o gráfico de canais."##,
    ),
    (
        "interface.wifi.group",
        r##"## O que é
Agrupa a lista por canal primário: um bloco por canal, com o número de redes nele, a mais forte primeiro. Mostra de relance quais canais estão cheios."##,
    ),
    (
        "interface.wifi.networks.air",
        r##"## O que é
Como as outras redes ouvidas pesam sobre esta:
- **mesmo canal ×N**: N redes com o mesmo canal primário.
- **sobrepõe ch …**: os canais primários das redes cujo canal cobre parte deste. Em 2,4 GHz, canais a menos de 5 de distância se sobrepõem (1 e 5 sim, 1 e 6 não), por isso o costume de usar só 1, 6 e 11.
- **divide o ar ×N**: N redes chegam forte o bastante para que esta espere por elas antes de transmitir.

## A regra (CCA)
Uma estação só transmite com o canal primário livre (clear channel assessment). Ela espera por um quadro Wi-Fi cujo preâmbulo decodifica a −82 dBm ou mais no primário de 20 MHz, e por qualquer energia a −62 dBm ou mais (IEEE 802.11-2020 §17.3.10.6, §19.3.19.5 e §21.3.18.5). Então outra rede divide o ar:
- se o canal primário desta fica dentro do canal dela (mesmo primário, ou ela transmite largo por cima) e ela chega a −82 dBm ou mais;
- se os canais só se sobrepõem (2,4 GHz parcialmente sobreposto, ou ela nos secundários desta) e ela chega a −62 dBm ou mais: ali só a energia conta.

## Cuidado
O nível é o que este rádio ouve, que representa o que o ponto de acesso ao lado dele ouve: é uma estimativa."##,
    ),
    (
        "interface.wifi.networks.channel",
        r##"## O que é
A banda e o canal primário do ponto de acesso, com a largura do canal inteiro (20, 40, 80, 160 ou 320 MHz) e a geração (Wi-Fi 4 a 7).

## De onde vem
Dos elementos que o ponto de acesso põe no beacon (IEEE 802.11-2020 §9.4.2): HT Operation (largura de 40 MHz), VHT Operation (80, 160, 80+80), HE Operation com a informação de 6 GHz e EHT Operation (320 MHz, IEEE 802.11be-2024). Uma rede que não anuncia nada disso fica com 20 MHz."##,
    ),
    (
        "interface.wifi.networks.load",
        r##"## O que é
O que o ponto de acesso diz da própria carga, no elemento BSS Load (IEEE 802.11): quantos clientes estão associados e a parte do tempo em que ele achou o canal ocupado (0 a 100%).

## Como ler
- até 30%: folgado;
- de 30% a 60%: o canal já disputa tempo (âmbar);
- acima de 60%: congestionado (vermelho).

Muitos pontos de acesso domésticos não anunciam o elemento: a coluna fica vazia."##,
    ),
    (
        "interface.wifi.spectral.interference",
        r##"## O que é
O que a energia dos últimos 10 segundos parece, pela forma em frequência e no tempo (as classes do spectral scan do RouterOS, onde cabem):
- **Wi-Fi**: um bloco no canal de uma rede ouvida, com o nível dela, ou um bloco de 15 MHz ou mais;
- **portadora** (cw): um sinal de menos de 1,5 MHz, quase sempre ligado;
- **micro-ondas** (mwo): entre 2440 e 2480 MHz, de 6 a 30 MHz, ligado cerca de metade do tempo e passeando;
- **Bluetooth** ou **saltos de frequência** (fhss): rajadas estreitas e curtas espalhadas por 20 MHz ou mais;
- **desconhecida**: o resto acima do ruído.

## Cuidado
É uma estimativa pela forma, não uma identificação. Não foi conferida numa placa Atheros de verdade."##,
    ),
    (
        "interface.wifi.spectral.range",
        r##"## O que é
O que o spectral scan escuta:
- **canal em uso**: só o canal do enlace, com a resolução do rádio (cerca de 0,3 MHz por ponto). Não interrompe nada.
- **banda de 2,4 GHz** ou **banda de 5 GHz**: a banda inteira, varrida com um scan a cada 4 segundos; as amostras chegam enquanto o rádio visita cada canal.

## Cuidado
Varrer a banda tira o rádio do canal dele por um instante a cada scan: o enlace para enquanto isso, e num ponto de acesso clientes podem cair (o Channel Analysis do OpenWrt e o airView do airMAX M avisam o mesmo)."##,
    ),
    (
        "interface.wifi.spectral.trace",
        r##"## O que é
A potência por frequência, em dBm, em três traços:
- **tempo real**: o último quarto de segundo;
- **média**: a média corrente;
- **pico**: o maior valor desde o início da varredura.

Cada ponto é a potência de um ponto da FFT do rádio (uns 0,3 MHz), não a do canal inteiro."##,
    ),
    (
        "interface.wifi.spectral.usage",
        r##"## O que é
Para cada canal de 20 MHz, a parte do tempo (das amostras) em que uma estação ali acharia o canal ocupado, como o "channel usage" do airView. Vale a regra da CCA sobre a energia acima do ruído, somada no canal:
- energia larga como a do Wi-Fi (um quarto do canal ou mais acima do ruído) a partir de −82 dBm, o nível do preâmbulo;
- qualquer energia a partir de −62 dBm (portadora, Bluetooth, micro-ondas).

Uma portadora fraca aparece nas fontes mas não ocupa o canal."##,
    ),
    (
        "interface.wifi.spectral.waterfall",
        r##"## O que é
A cascata: cada linha é um quarto de segundo, a mais nova em cima, e cada coluna uma frequência. A cor diz a potência acima do piso de ruído: azul escuro no ruído, depois azul, ciano, verde, amarelo e vermelho a 50 dB acima. Guarda o último minuto.

## Como ler
Uma faixa larga e intermitente é Wi-Fi; uma linha fina e contínua é uma portadora; manchas pequenas espalhadas são saltos de frequência (Bluetooth); um bloco que vai e volta perto de 2,45 GHz costuma ser micro-ondas."##,
    ),
    (
        "interface.wifi.suggested",
        r##"## O que é
O canal de 20 MHz de cada banda com menos coisa em cima, para quando você escolher o canal de um ponto de acesso aqui perto.

## Como é calculado
Para cada canal candidato, soma cada rede cujo canal o cobre, pesada por quão forte ela chega aqui (−95 dBm nada, −50 dBm tudo) e por quão ocupada ela diz estar (BSS Load; metade quando não diz), mais a ocupação medida pelo driver quando há. Em 2,4 GHz só 1, 6 e 11 são candidatos. Canais com detecção de radar (DFS) perdem o empate e ganham o selo **DFS**: neles o ponto de acesso espera um minuto antes de transmitir e muda de canal se ouvir radar."##,
    ),
    (
        "interface.wifi.survey",
        r##"## O que é
A parte do tempo em que o canal esteve ocupado, medida pelo próprio driver (nl80211 survey: tempo ativo e tempo ocupado de cada canal), como o `frequency-scan` do RouterOS.

## Medida parcial
Muitos drivers só medem o canal em uso e deixam os outros em zero (medido no mt7925e). Canal sem medida aparece com um traço; o selo ao lado do título diz se a medida é completa, parcial ou não existe."##,
    ),
    (
        "interface.wifi.view",
        r##"## O que é
Três jeitos de ver o que o rádio ouviu:
- **Lista**: uma linha por ponto de acesso, com o canal e a largura, a carga que ele anuncia, os canais que se sobrepõem a ele e quem divide o tempo de ar com ele. Dá para filtrar por banda e agrupar por canal.
- **Canais**: cada rede como uma curva da largura do canal, da altura do sinal (como o Channel Analysis do OpenWrt), e embaixo a ocupação medida de cada canal.
- **Espectro**: o spectral scan, como o airView da Ubiquiti: cascata, traço em tempo real, uso por canal e as fontes de interferência. Só em rádio com spectral scan (chip Qualcomm Atheros: ath9k, ath10k, ath11k); nos outros fica desligado, com o motivo.

## Cuidado
A lista e os canais vêm da varredura (**Varrer de novo**): ela sai do canal por alguns milissegundos em cada canal visitado. Num roteador que é ponto de acesso isso pode derrubar clientes; numa estação, o enlace para por um instante."##,
    ),
];
