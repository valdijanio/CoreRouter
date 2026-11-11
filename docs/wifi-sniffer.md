# Wi-Fi em modo monitor: snooper e captura 802.11 (G1.30j)

Um rádio Wi-Fi do roteador em modo monitor, para análise de segurança e de ocupação do ar. Dois
usos, uma tarefa só por baixo:

- **Snooper** (`interface.wifi.snooper.start`): quem usa o ar, por rede e, dentro dela, por
  estação: tempo de ar em %, quadros, % de retransmissão, taxa (Mb/s, padrão, MCS, fluxos,
  largura), sinal e notas. Em cima, o tempo de ar de cada canal.
- **Captura** (`interface.wifi.sniffer.start`): os quadros 802.11 **inteiros** num pcap com
  cabeçalho radiotap (link type 127) para o Wireshark, com filtro por rede (BSSID ou nome), por
  MAC e por tipo de quadro, e o modo "só o handshake" (EAPOL e um beacon por rede). Lista ao
  vivo dos últimos quadros (`interface.wifi.sniffer.packets`) e download do arquivo em pedaços
  (`interface.wifi.sniffer.download`). A captura também enche a tabela do snooper.

A tabela sai em `interface.wifi.snooper.print`; parar é `tool.task.stop`, como nas outras
ferramentas. Na GUI: Interfaces › Wi-Fi Sniffer, abas **Snooper** e **Capture**.

Decisão do usuário (2026-11-11): é análise de segurança, então o padrão captura tudo o que for
possível (todas as redes, quadros inteiros, sem cortar o cabeçalho) e não há aviso nem
confirmação de privacidade. Continuam valendo os limites operacionais e a proteção contra
perder o acesso.

## O que o roteador nota

| Nota (`code`) | Quando | Tom |
|---|---|---|
| `far-slow` "longe, lento" | estação com 20 quadros ou mais, ≥ 20 % de retransmissão e taxa ≤ 24 Mb/s ou sinal ≤ -75 dBm | âmbar |
| `deauth`, `disassoc` | quantas vezes foi tirada da rede, com o último motivo (IEEE 802.11-2020 Tabela 9-49) ou "cifrado" com 802.11w | âmbar |
| `deauth-flood` | 10 ou mais deauth/disassoc para a mesma estação num segundo | vermelho |
| `handshake` / `handshake-partial` | as 4 mensagens EAPOL-Key do 4-way handshake (§12.7.6) vistas; ou n/4 | verde / neutro |
| `hidden`, `hidden-revealed` | beacon sem nome; o nome dado por uma resposta de probe ou um pedido de associação | neutro / âmbar |
| `evil-twin` | outro BSSID com o mesmo SSID e segurança mais fraca (aberta ou legacy contra WPA2/3) | vermelho |
| `other-security`, `other-vendor` | mesmo SSID com outra segurança; ou outro fabricante (OUI), ambos com MAC de fábrica | âmbar |
| `broadcast-deauth` | deauth/disassoc para todos (endereço de grupo) | âmbar |
| `probing` | estação fora de rede procurando um nome | neutro |

## Lockout: o sniffer nunca tira um rádio da rede

Monitor no rádio por onde chega a gerência derrubaria o acesso. A regra:

- **Rádio ativo** (interface habilitada): o monitor é uma interface a mais ao lado da estação
  (`<rádio>mon`), que continua conectada. Escuta só o canal da estação. Pedir canal, largura,
  hop ou `mode=exclusive` é recusado com a saída: desativar a interface; se esta conexão chega
  por ela, entrar em Safe Mode antes.
- **Rádio desativado**: o sniffer fica com o rádio (`exclusive`), escolhe canal e largura e
  pode pular canais.
- **O rádio volta a ser habilitado** (à mão, ou o Safe Mode desfazendo o `disable` porque a
  conexão caiu): o sniffer exclusivo para no tick seguinte (`watch`, chamado pelo serviço de
  Wi-Fi) com `the radio went back to its network`, e a estação recebe o rádio de volta. Se o
  kernel já recusar a troca de canal antes disso (`EBUSY`), o hop para e o monitor segue o
  canal da estação.

Por que funciona no Linux: o mac80211 põe monitor entre os tipos de interface **de software**
do wiphy (Linux 6.18.59, `net/mac80211/main.c:1355`), que não entram na conta das combinações
de interface: um monitor sempre cabe ao lado da estação. E o kernel só deixa um monitor trocar
de canal quando só há monitores no ar (`net/wireless/chan.c:1550`,
`cfg80211_set_monitor_channel` → `-EBUSY` sem `cfg80211_has_monitors_only`,
`net/wireless/core.h:262`). O `GET_WIPHY` diz as duas coisas (`NL80211_ATTR_SUPPORTED_IFTYPES` e
`NL80211_ATTR_SOFTWARE_IFTYPES`): `interface.wifi.radio`/`WifiRadio.monitor` e
`monitor_shared`. Um driver sem monitor é recusado com o motivo.

## Limites

- No máximo um sniffer por rádio e dois guardados ao mesmo tempo (tabela e arquivo).
- Duração 1 a 86 400 s, padrão 300. Uma tarefa que ninguém consulta por 60 s para sozinha.
- Arquivo até 64 MiB (padrão 16 MiB); cheio, para de crescer e conta `dropped_by_limit`, e o
  snooper continua (como o `pcap-size-limit` do RouterOS).
- Tabela: até 4096 estações e 1024 redes; o resto conta em `overflow`. O `print` mostra até
  200 redes e 64 estações por rede.
- Lista ao vivo: os últimos 512 quadros que passam no filtro.
- Quadros com FCS ruim (o cartão marca) são contados em `bad_fcs` e não entram na tabela.

## Como está feito

| Camada | Arquivo | O que faz |
|---|---|---|
| hal (L1) | `crates/hal/src/ieee80211.rs` | parser radiotap (só a 1ª palavra `present`, campos 0–27 com alinhamento e tamanho do radiotap.org), cabeçalho 802.11 (tipo, flags, endereços, BSSID pela Tabela 9-30), elementos (SSID, DSSS, RSNE com os AKM, WPA1), EAPOL-Key (mensagem 1–4 pela Key Information), taxa pelas tabelas HT/VHT/HE (subportadoras × bits × taxa de código / símbolo), tempo de ar estimado, construtor de radiotap |
| hal | `crates/hal/src/wifi_monitor.rs` | `WifiMonitor`/`MonitorSocket` (modo, canal, largura) |
| hal | `crates/hal/src/lab_wifi_air.rs` | o ar do laboratório: beacons das redes do lab, estações Wi-Fi 4/5/6, uma impressora longe a 6 Mb/s com 45 % de retransmissão, uma TV expulsa a cada 20 s (deauth motivo 7) que volta com autenticação, associação e handshake, uma estação que revela a rede oculta e um gêmeo aberto da rede do lab |
| hal-linux | `crates/hal-linux/src/wifi_monitor.rs`, `nl80211.rs` | `NEW_INTERFACE` (monitor, `control` + `otherbss`), link up, `SET_CHANNEL` com largura e centro, `DEL_INTERFACE` no fim (e de uma sobra de crash), leitura por `AF_PACKET` (`HostCapture`) |
| engine | `crates/engine/src/tools/wifi_snoop.rs` | a tabela (`Snooper`), o filtro, o pcap e o job (hop, tempo por canal, duração) |
| engine | `crates/engine/src/cmd/wifi_sniffer.rs` | os cinco comandos e o `watch` |
| ui | `crates/ui/src/wifi_sniffer.rs` | a janela, a faixa de canais pintada, a tabela, o detalhe das notas, a lista e o download |

## Desempenho e paralelismo

Trabalho por quadro: os parsers e duas buscas em `HashMap` (o transmissor e a estação do quadro
de dados); nada cresce com o número de estações ou redes. A tabela vira JSON uma vez por
segundo, limitada. **Medido** (`cargo bench -p corerouter-engine --bench wifi_snoop`, build
release, 32 núcleos, 2026-11-11), 5 s do ar do laboratório no canal 44 (~2 570 quadros):

| Medição | Tempo |
|---|---|
| parser (radiotap + 802.11 + info + tempo de ar) | 37 ns/quadro (27 M quadros/s) |
| parser + tabela | 74 ns/quadro (13,5 M quadros/s) |
| parser + tabela com 4 096 estações já na tabela | 72 ns/quadro |
| tabela em JSON (uma vez por segundo), laboratório | 15 µs |
| tabela em JSON, 4 096 estações | 216 µs |

Um canal de 802.11 leva da ordem de milhares a algumas dezenas de milhares de quadros por
segundo (cada A-MPDU chega como vários MPDUs): mesmo 100 mil quadros/s custam ~7 ms/s de CPU
(**estimado** a partir do número medido). O gargalo é o `recvmsg` por quadro (~1–2 µs,
**estimado** pelo Torch, `docs/perf.md`), não o parser.

- **Mais threads não ajudam**: um rádio tem uma fila de recepção no mac80211 (um monitor, uma
  interface de rede), e a tabela é uma só. `PACKET_FANOUT` dividiria os quadros entre sockets,
  mas a tabela teria de ser repartida e somada (por transmissor) e a ordem do pcap se perderia;
  o custo medido (74 ns/quadro) não justifica.
- **Lotes**: o job lê até 1024 quadros por chamada e trava o estado compartilhado uma vez por
  lote (não por quadro); a tabela é montada fora da trava. `TPACKET_V3` (anel `mmap`) tiraria
  o `recvmsg` por quadro, mas exige `unsafe` (proibido fora do `dataplane-ebpf`) e o ganho só
  apareceria acima de ~500 mil quadros/s, que um canal de Wi-Fi não leva.
- Thread: a de tarefas do runner (nome `wifi-snooper-<id>`/`wifi-sniffer-<id>`), nunca com o
  lock do `Session`; os comandos leem o `SnoopState` por um `Mutex` próprio.

## O que foi conferido e o que não foi

- **Laboratório** (`--backend virtual`): GUI com `--control` num Xvfb próprio, snooper pulando
  canais e captura no canal 1, screenshots olhados; o pcap baixado pela GUI abre no `tshark`
  (radiotap, taxa HT MCS3 de 26 Mb/s, flag de retry, SSID nos beacons).
- **QEMU com `mac80211_hwsim`** (`cargo xtask os wifi-test`): monitor ao lado da estação
  conectada ao `hostapd` (beacons, a estação, o deauth e o handshake 4/4 de um `reconnect`, o
  pcap com link type 127, a lista ao vivo), e o rádio desativado pulando 1/6/11 até achar o AP no
  canal 1; a interface monitor some no fim.
- **Não conferido em placa**: a RTL8852BE (`rtw89`) do notebook do usuário e a mt7925e do host
  (proibido mexer no Wi-Fi do host). O `rtw89` e o `mt76` têm monitor no mac80211, mas o
  comportamento do firmware (o que ele passa em monitor, `otherbss`, se mede ruído) só aparece
  na placa.
- **Retransmissões no QEMU**: o `mac80211_hwsim` sem `wmediumd` manda cada quadro uma vez
  (`drivers/net/wireless/virtual/mac80211_hwsim.c`, `mac80211_hwsim_tx_frame_no_nl`), então não
  há marca de retry no ar simulado; elas são conferidas no laboratório e nos testes.

## Pesquisa

### MikroTik RouterOS 7

Fontes: <https://manual.mikrotik.com/docs/7.25/wireless/wifi/> (WiFi: Sniffer, Flat-snoop,
Scan, Frequency-scan) e <https://help.mikrotik.com/docs/spaces/ROS/pages/8978446/Wireless+Interface>
(pacote `wireless` legado: Sniffer e Snooper).

- `/interface/wifi/sniffer`: modo monitor, imprime os quadros, grava `pcap-file` com
  `pcap-size-limit` (cheio, para de acrescentar), ou manda por TZSP (`stream-address`,
  `stream-rate`); `duration`; `filter` no estilo libpcap com `addr1`/`addr2`/`addr3`, tipo e
  subtipo (`beacon`), flags (`to-ds`, `from-ds`, `retry`, `power`, `protected`). Escuta o canal
  configurado na interface. Suporte no `hw-caps` do rádio (`sniffer`).
- `/interface/wifi/flat-snoop`: visões `bss`, `frequency` (estações e APs por frequência) e
  `stas`; `freeze-frame-interval` 1 s.
- Legado `/interface/wireless/snooper`: uso da frequência e quem a ocupa, `channel-time` 200 ms,
  `multiple-channels` (pula pela scan-list), `receive-errors`.
- `frequency-scan`: mede `load` (% do tempo ocupado) e ruído, **desconecta** a estação.

### Outros

- **Linux `iw`/OpenWrt**: `iw phy phyN interface add mon0 type monitor flags control otherbss`
  e `iw dev mon0 set channel`; é o caminho nl80211 adotado aqui (sem o `iw`).
- **Kismet**: pula canais, tabela por dispositivo, alertas `DEAUTHFLOOD`, `BCASTDISCON` e
  `APSPOOF` (SSID conhecido vindo de MAC não autorizado): inspirou as notas de deauth e de
  gêmeo.
- **Cisco (AP em modo sniffer / wIPS)**: o AP fixa um canal e manda os quadros ao Wireshark
  (AiroPeek); o wIPS detecta deauth flood e AP impostor. Aqui o pcap fica no roteador e baixa
  pela GUI/CLI/MCP.
- **Wireshark**: decifra WPA/WPA2 com `wpa-pwd senha:SSID` se tiver o handshake EAPOL e o SSID:
  daí o modo "só o handshake" (EAPOL + um beacon por rede).

### Normas

- radiotap: <https://www.radiotap.org> (cabeçalho, campos definidos com alinhamento/tamanho,
  MCS, VHT, HE, namespaces). O exemplo da página virou teste (`the_radiotap_org_example`).
- IEEE Std 802.11-2020: §9.2.4.1 Frame Control; Tabela 9-1 (tipos e subtipos); Tabela 9-30
  (endereços dos quadros de dados); §9.3.3 (corpos de gerência); §9.4.1.7 e Tabela 9-49
  (motivos); §9.4.2.24 RSNE (Tabela 9-151, AKM); §12.7.2 (EAPOL-Key, Key Information) e
  §12.7.6 (4-way handshake: cada mensagem virou teste); §19.5, §21.5 e §27.5 (taxas HT, VHT e
  HE, conferidas contra os valores das tabelas nos testes); Anexo E (planos de canais, centro de
  40/80/160 MHz).
- pcap: link type 127 (`LINKTYPE_IEEE802_11_RADIOTAP`, tcpdump.org/linktypes.html).

### O que entrou além do pedido

- Largura do canal (20/40/80/160) no modo exclusivo: em 20 MHz o rádio não decodifica os dados
  de uma rede de 80 MHz, só os beacons.
- Taxa calculada pelo próprio motor a partir do radiotap (igual à do Wireshark), com MCS,
  fluxos e largura.
- Notas `other-vendor`, `broadcast-deauth` e `probing`.

### Vira gap depois

- **G1.30k** — Streaming TZSP ao vivo para o Wireshark (o `stream-address` do RouterOS) e filtro
  de captura em expressão (estilo libpcap): hoje o arquivo baixa ao fim ou a qualquer momento.
- **G1.30l** — Ruído e ocupação do canal medidos pelo rádio (`NL80211_CMD_GET_SURVEY`: tempo
  ocupado, ruído por canal), ao lado do tempo de ar estimado; é o `frequency-scan` do RouterOS e
  depende da placa (o `rtw89` informa? conferir no notebook).
