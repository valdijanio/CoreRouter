# Wi-Fi em modo estação (G1.30)

O roteador entra numa rede Wi-Fi como cliente, para a gerência ou como uplink. É o caso do PC
ou notebook que vira roteador e só tem cabo para os clientes. O modo AP (G1.30a) está em
`docs/wifi-ap.md`.

A G1.30 entra em três partes:

| Parte | O que entra | Estado |
|---|---|---|
| 1. Imagem | pilha Wi-Fi em módulo, drivers e firmware, `regulatory.db`, `wpa_supplicant`, passada própria no PID 1; rádio deixa de ser confundido com porta Ethernet | este documento, "Imagem" |
| 2. Motor | interface `wifi` em modo `station`, comandos (`interface.wifi.*`), o `wpa_supplicant` dirigido pelo `hal-linux`, teste de ponta a ponta com `mac80211_hwsim` | este documento, "Motor" |
| 3. Telas | janela Interfaces › Wi-Fi e a porta Wi-Fi no setup do console | este documento, "Telas" |

## Imagem (parte 1)

### O que mudou

- **A pilha virou módulo.** `cfg80211`, `mac80211` e `rfkill` vinham embutidos pelo
  `x86_64_defconfig`, sem nenhum driver de placa. Embutido, o cfg80211 pede o `regulatory.db`
  num `late_initcall` (`net/wireless/reg.c`, `regulatory_init_db`), antes de o `/` existir; o
  pedido falha, o kernel guarda `regdb = ERR_PTR(-ENODATA)` e daí em diante nenhuma consulta de
  país funciona. Em módulo, a base é lida na carga, com o `/` montado, e uma máquina sem placa
  Wi-Fi não carrega nada. `bzImage`: −0,95 MiB (**medido**).
- **Drivers** (`os/board/x86_64/nics.fragment`, no fim): Intel `iwlwifi` com `iwlmvm` e
  `iwlmld`, MediaTek `mt7921e` e `mt7925e`, Realtek `rtw88` e `rtw89` (PCIe e USB), e o
  `mac80211_hwsim` para teste.
- **Firmware** na `firmware.lock`, com uma regra própria para o `iwlwifi` (abaixo).
- **`wireless-regdb`** (Buildroot): `regulatory.db` e a assinatura `regulatory.db.p7s`. O kernel
  confere a assinatura (`CFG80211_REQUIRE_SIGNED_REGDB=y`) com a chave que ele mesmo traz.
- **`wpa_supplicant` 2.12** (Buildroot), com nl80211, WPA3 e o socket de controle; sem D-Bus,
  sem `wpa_cli`, sem arquivo de configuração. A parte 2 passa a usá-lo.
- **PID 1:** passada `Wifi` no carregador de módulos, depois do sinal de boot pronto. O `iwlwifi`
  é carregado junto com `iwlmvm` e `iwlmld` (abaixo).
- **Rádio não é porta.** O netdev de uma estação tem `type` 1 e `device`, como uma porta
  Ethernet, e não traz `IFLA_INFO_KIND`. O PID 1 e o `hal-linux` o tratavam como porta: ele
  ganharia lugar na lista "Ethernet ports" do setup, cliente DHCP na imagem live e uma entrada
  `ether` na config. Agora o PID 1 olha o link `phy80211` do sysfs
  (`apps/corerouter-init/src/links.rs`) e o `hal-linux` pergunta ao nl80211
  (`crates/hal-linux/src/wifi_links.rs`): o rádio aparece em `interface.list` como `wifi`,
  não gerenciado, até a parte 2 lhe dar um tipo. A pergunta só é feita quando aparece um link
  novo e com o cfg80211 já no kernel: procurar uma família generic netlink pelo nome faz o
  kernel rodar o `modprobe`, o que carregava `cfg80211` e `rfkill` em toda máquina e somava
  48 ms a todo boot (**medido**, e corrigido antes de entrar).

### Conjunto de drivers e custo

Escolha do dono (2026-11-11): o conjunto "recomendado". Medido antes, com os módulos
compilados numa cópia da árvore do kernel e o firmware baixado da tag travada, em squashfs zstd
com as opções da imagem:

| Grupo | `.ko` MiB | firmware MiB | no squashfs MiB |
|---|---|---|---|
| Pilha: cfg80211, mac80211, rfkill | 5,47 | 0 | 1,03 |
| Intel AX e BE (AX200, AX201, AX210, AX211, BE200, BE201) | 3,35 | 33,45 | 12,80 |
| Intel AC (3160, 3168, 7260, 7265, 8260, 8265, 9260, 9560) | 0 | 12,48 | 5,17 |
| MediaTek MT7921, MT7922, MT7925 (PCIe) | 1,63 | 4,52 | 3,66 |
| Realtek rtw89 (8852AE/BE/CE, 8851BE, 8922AE) | 7,78 | 8,83 | 5,37 |
| Realtek rtw88 (8822BE/CE, 8821CE, 8723DE e USB) | 3,53 | 0,77 | 1,19 |
| **Total do conjunto** | 21,76 | 60,04 | **29,23** |

Ficaram de fora, com o motivo:

- **Intel antigo (`iwldvm`, 1000 a 6000, 2008–2012):** +3,05 MiB para placas de 14 anos.
- **Atheros (ath9k, ath10k, ath11k, ath12k):** o ath11k declara curingas
  (`ath11k/WCN6855/hw2.0/*`) e o ath12k não declara nada; os dois montam o nome do firmware em
  tempo de execução, com arquivos de placa de vários MiB. A trava não consegue acompanhá-los
  sem uma regra por chip.
- **Broadcom (`brcmfmac`):** metade do que declara não está no linux-firmware (chips da Apple,
  arquivos `.txt` de placa); o `b43` não tem firmware redistribuível.
- **Adaptadores USB antigos (rtl8xxxu, mt76x2u, mt7601u, rt2800usb):** +0,76 MiB; viram gap
  se alguém precisar.

### O `iwlwifi` não pede o que declara

A trava de firmware segue o `firmware=` do modinfo de cada driver. Para o `iwlwifi` isso não
basta (**medido**: dos 49 nomes que os módulos da imagem declaram, a tag `20261019` do
linux-firmware não tem 30):

- o `MODULE_FIRMWARE` nomeia a versão **mais nova** que o driver conhece (`-100.ucode`,
  `-c99.ucode`), para os passos de chip que ele lista;
- em tempo de execução o driver monta o nome com o passo que a placa tem e tenta da versão mais
  nova para a mais antiga que aceita (`drivers/net/wireless/intel/iwlwifi/iwl-drv.c`,
  `iwl_request_firmware`: `fw_index--` até `ucode_api_min`; do núcleo 99 cai para a API 101);
- depois pede `<prefixo>.pnvm`, que não declara (`fw/pnvm.c`).

Regra da trava (`xtask/src/os/firmware.rs`, `iwlwifi_requests`): de cada prefixo do `WHENCE`
que o driver construído conhece (declara o prefixo, ou outro passo do mesmo chip), entra a
versão mais nova que o driver tenta, e o `.pnvm` do prefixo. Os nomes declarados que não
existem viram `skip`, com o motivo. Uma família não construída (`iwldvm`) não declara nada e
não ganha nada.

Limite conhecido: a regra usa o teto do driver inteiro (núcleo 99, API 101) e o que o prefixo
declara; o teto exato de cada chip é a interseção do MAC com o RF, que só está no fonte
(`cfg/*.c`, `iwl_get_ucode_api_versions`). Na tag de hoje os dois coincidem. Ao trocar a tag
ou o kernel, confira o diff da trava.

### O módulo de operação do `iwlwifi`

O `iwlwifi` é a metade de barramento do driver. Ele descobre pelo firmware qual metade fala
com a placa (`iwlmvm` até o Wi-Fi 6E, `iwlmld` no Wi-Fi 7) e pede ao kernel que rode
`/sbin/modprobe` (`iwl-drv.c`, `request_module_nowait`). O carregador do PID 1 só responde a
dispositivos (modalias), então ele carrega as duas metades junto com o `iwlwifi`
(`COMPANIONS`, `apps/corerouter-init/src/modules.rs`): quando o firmware chega, a metade certa
já está registrada (`iwl_opmode_register`) e a placa sobe. Custo: os dois módulos na memória
de uma máquina com placa Intel (~2,2 MiB em disco).

### Como testar sem placa

O QEMU não emula placa Wi-Fi. `corerouter.hwsim=N` na linha de comando do kernel faz o PID 1
carregar o `mac80211_hwsim` com N rádios simulados; nenhum dispositivo pede esse módulo, então
ele nunca carrega sozinho.

```sh
cargo xtask os boot-test --wifi    # boot com corerouter.hwsim=2; espera "wifi: 2 test radios"
```

## Motor (parte 2)

### Como se usa

```sh
corerouter-cli run interface.wifi.country.set '{"country":"BR"}'
corerouter-cli run interface.wifi.enable '{"name":"wifi1"}'
corerouter-cli run interface.wifi.scan '{"name":"wifi1"}'
corerouter-cli run interface.wifi.networks '{"name":"wifi1"}'      # alguns segundos depois
corerouter-cli run interface.wifi.set '{"name":"wifi1","ssid":"Casa","passphrase":"…"}'
corerouter-cli run interface.wifi.monitor '{"name":"wifi1"}'
corerouter-cli run ip.dhcp-client.add '{"interface":"wifi1"}'
```

No terminal: `/interface wifi country set country=BR`, `/interface wifi set wifi1 ssid=Casa
passphrase=…`, `/interface wifi monitor wifi1`.

| Comando | O que faz |
|---|---|
| `interface.wifi.list` | os rádios: rede configurada, estado, sinal, canal; a senha sai como `***` (`show_sensitive`, grupo full, mostra) |
| `interface.wifi.set` | a rede (`ssid`, `security`, `passphrase`, `hidden`, `band`, `bssid`), `disabled`, `comment`, `mtu`; `ssid=""` esquece a rede e a senha |
| `interface.wifi.enable` / `.disable` | liga e desliga o rádio |
| `interface.wifi.scan` / `.networks` | começa uma varredura; o que ela ouviu, com o que dá para entrar e por que não |
| `interface.wifi.monitor` | o enlace agora: estado, BSSID, banda, canal, sinal, taxa, segurança negociada, PMF, falha em palavras, reconexões, país pedido e em vigor |
| `interface.wifi.reconnect` | sai e entra de novo |
| `interface.wifi.history` | os eventos (entrando, conectado, caiu, falhou, bloqueado) |
| `interface.wifi.country.set` / `.get` | o país de todos os rádios (ISO 3166-1, duas letras) |
| `interface.wifi.adopt` | põe na config um rádio que apareceu; o tick faz isso sozinho |

`security`: `auto` (WPA3 se o AP oferece, senão WPA2; o padrão), `wpa3`, `wpa2`, `open`.
A senha tem de 8 a 63 caracteres ASCII, ou é a chave de 64 dígitos hexadecimais, que só vale
com `security=wpa2` (o SAE precisa da frase).

### O rádio na config

- O rádio é uma interface de tipo `wifi` (`InterfaceKind::Wifi`, `crates/model/src/wifi.rs`),
  que existe porque a placa existe, como uma porta Ethernet. Ela entra na config pela adoção
  do tick (`interface.wifi.adopt`), depois que o nome ficou igual por três leituras, sempre
  **desligada** e sem rede, como no RouterOS. Não entra na semeadura do primeiro boot: o
  netdev de um rádio aparece quando o driver tem o firmware, depois de o boot nomear as
  portas, e é renomeado em seguida; semeado ali ele entrava na config como `wlan0`
  (**medido** no QEMU: um daemon que subiu 95 ms antes da troca de nome).
- O nome é `wifi1`, `wifi2`… (o do RouterOS 7). Na imagem o PID 1 renomeia o `wlanN` do kernel
  e guarda o nome pelo MAC em `/config/.wifi-names` (`apps/corerouter-init/src/wifi_names.rs`):
  a ordem em que os drivers sondam muda de um boot para outro, o nome não.
- A senha fica selada (`Sealed`, AES-256-GCM, a mesma chave dos segredos PPP). Journal, log,
  `config.diff`, `state.inspect` e `/export` não a mostram; `/export show-sensitive` sim.
- O país é um só para o roteador (`system.wifi.country`): no Linux o domínio regulatório é do
  sistema, não da placa.
- Config antiga carrega igual: o tipo e a seção são novos e não escrevem nada quando vazios.
  Uma versão anterior não lê uma config com um rádio; a volta do A/B usa a cópia da config.

### O que os comandos recusam

- **Rádio ligado sem país** (na validação do commit, para um lote poder definir os dois em
  qualquer ordem): no domínio mundial o rádio não transmite em 5 GHz, e com o país errado
  transmite onde não pode. A mensagem traz o comando a rodar.
- **Mudar a rede do rádio por onde a sessão chega** (`ssid`, senha, segurança, desligar,
  reconectar): pede Safe Mode, em que perder a conexão desfaz a mudança, ou `force=yes`.
- **Estação em bridge** (um AP entra, G1.30a): uma estação leva três endereços no quadro e só o próprio MAC atravessa
  o AP; o kernel também recusa (`IFF_DONT_BRIDGE`). A mensagem diz para rotear.
- **Rádio em bonding** (G1.30m): pelo mesmo motivo, e porque o bonding troca o MAC das portas.
  A janela New/Edit Bonding mostra as portas Wi-Fi cinza, com um ⓘ que explica e aponta o
  `station-bridge` (quatro endereços) como o caminho entre dois CoreRouters.
- **Rede 802.1X, OWE, WEP ou só WPA/TKIP:** aparecem na varredura com `joinable: false` e o
  motivo. Digitada à mão (`interface.wifi.set`, CLI ou MCP), uma rede que a última varredura
  ouviu só assim é aceita com um aviso que diz o motivo, e o `preview` mostra o mesmo aviso;
  sem ele a falha virava "rede não encontrada".

### Como roda

- **Motor** (`crates/engine/src/wifi.rs`): no relógio que já move os clientes DHCP e PPPoE.
  Para cada rádio da config em uso, abre a porta do rádio na plataforma, diz a rede **uma vez
  por mudança** (o que distingue uma config da outra é a caixa selada, não a senha) e lê os
  eventos. A senha só é aberta para o `join`.
- **Plataforma** (`crates/hal/src/wifi.rs`): o trait `WifiPort` (`join`, `leave`, `scan`,
  `scan_results`, `status`, `events`). O laboratório virtual tem um rádio com sete redes
  inventadas (`crates/hal/src/lab_wifi.rs`): os testes do motor e a GUI rodam nele.
- **Linux** (`crates/hal-linux/src/wifi.rs`): um `wpa_supplicant` para todos os rádios,
  iniciado quando o primeiro rádio é aberto (`-B -g <runtime>/wpa/global`), sem arquivo de
  configuração; cada rádio entra por `INTERFACE_ADD` e tem dois sockets, um de comandos e um de
  eventos. A senha vai num `SET_NETWORK` pelo socket, nunca para arquivo. O supplicant
  sobrevive a um restart do daemon (o rádio continua na rede) e termina com o último rádio.
  **Nada disso espera dentro do tick.** Cada rádio tem uma thread própria (`wifi-<nome>`), que
  é a única a falar com o supplicant: abre o rádio, recebe as ordens (`join`, `leave`, `scan`)
  por uma fila de 8 (cheia, responde "ocupado") e deixa o estado, a varredura e os eventos
  numa área que o tick só lê. O `INTERFACE_ADD` só responde depois que o driver sobe a
  interface, e numa placa de verdade é aí que o firmware é carregado no chip (segundos); ele
  tem prazo próprio de 20 s, os outros comandos 2 s. Uma resposta que não chega no prazo
  inutiliza o socket: se chegasse depois, seria lida como resposta do comando seguinte.
  O país vai ao kernel por nl80211 (`NL80211_CMD_REQ_SET_REG`), e o domínio em vigor é lido de
  lá (`NL80211_CMD_GET_REG`).
- **Falhas em palavras:** `wrong-key` ("provavelmente a senha": no WPA2 o AP não diz que a
  senha está errada, só para de responder; sinal muito fraco e filtro de MAC dão o mesmo
  evento), `not-found`, `rejected` com o código do AP traduzido, `no-answer` (várias tentativas
  sem resposta) e o rádio bloqueado (rfkill). **A causa fica na tela:** depois de uma senha
  errada o `wpa_supplicant` deixa aquele AP de lado, a varredura seguinte dele "não acha a
  rede" e ele pausa a rede. Esses dois eventos são consequência; o motor mantém `wrong-key`
  (ou `rejected`) enquanto a rede continuar sendo ouvida. Se ela sumir de verdade, passa a
  `not-found`.

### Teste de ponta a ponta

```sh
cargo xtask os wifi-test
```

Sobe a imagem no QEMU com dois rádios simulados (`mac80211_hwsim`: cfg80211 e mac80211 de
verdade, quadros entre os rádios em software). No primeiro roda um `hostapd` com WPA2 e WPA3; o
segundo é o do roteador, dirigido só por comandos. O AP de teste é uma cópia do `hostapd` da
imagem que o build deixa em `images/test-tools/`, com arquivo próprio, num disco só dele. `corerouter.unmanaged=wifi1`
na linha de comando do kernel mantém o roteador longe do rádio do AP.

## Telas (parte 3)

### Janela Interfaces › Wi-Fi

Painel `crates/ui/src/wifi.rs`, padrão de janela de lista (G0.24). Só desenha e manda
`interface.wifi.*`.

- **Primeira linha:** as abas e o país de todos os rádios, com o selo âmbar `no country`
  enquanto não há um, e `Change…` (um campo, `interface.wifi.country.set`). Quando o kernel
  aplica outro domínio, um selo diz qual.
- **Aba Radios:** uma linha por rádio. Selo de estado (verde `connected`, azul `searching` e
  `connecting`, âmbar `no country` e `blocked`, cinza `disabled`), e ao lado o motivo da
  última falha (`wrong passphrase?`, `network not found`, `refused by the access point`,
  `no answer`). A rede vai em selo colorido pelo nome; o sinal fica verde até −65 dBm, âmbar
  até −75 e vermelho abaixo. Barra: ✓ ✗ 💬, `Scan…` e `Reconnect`. Não tem `+` nem `−`: o
  rádio existe porque a placa existe. Embaixo, o `monitor` do rádio selecionado, com a falha
  em palavras quebrando linha.
- **Aba Networks:** o que a última varredura de um rádio ouviu, com `Rescan` e a idade da
  varredura. Rede em que não dá para entrar fica esmaecida, com o motivo. `Connect…` (ou
  duplo clique) abre o modal do rádio com a rede preenchida e o rádio ligado.
- **Modal** (`list_modal`, alimentado por `interface.wifi.preview`): `set` tentado no candidato
  e desfeito, então os erros e avisos são os do comando. Mostra também se a última varredura
  ouviu a rede, e recusa ligar o rádio sem país antes de o commit recusar. A senha é digitada
  escondida e sai como `•••` nos comandos mostrados.
- **Outra rede pede a própria senha:** trocar o `ssid` sem dar a senha esquece a anterior
  (antes ela era tentada na rede nova e virava "senha errada?" minutos depois).
- Ícone próprio (`WIFI_HIGH` do Phosphor) no menu e na coluna Type da lista de interfaces;
  o log da GUI esconde `passphrase`.

### Janela "Interface <wifi1>" (G1.30g)

Uma porta Wi-Fi tem as abas **General, Wi-Fi, Radio, Hardware, Traffic, Statistics**. As abas
Ethernet, Status e SFP não aparecem nela, e a SFP só aparece numa porta com gaiola de módulo (o
`interface.ethernet.monitor` leu uma, vazia ou não). A janela redimensiona pelo mouse, e as abas
ocupam o espaço.

- **Wi-Fi** (`interface.wifi.monitor`, a cada 1 s) mostra:
  - estado, há quanto tempo e quantas reconexões;
  - rede, segurança, cifra, PMF e ponto de acesso;
  - sinal com selo de qualidade (excellent ≥ −55 dBm, good ≥ −67, fair ≥ −75, poor abaixo),
    médias, sinal por antena, ruído e SNR;
  - faixa, padrão e geração, canal, largura e centro;
  - taxas de TX e RX (Mbit/s, modo e MCS, fluxos, largura, GI), retransmissões em % e
    falhas, beacons perdidos e última vez ouvido;
  - endereços (com a origem DHCP), país e última falha.
- **Radio** (`interface.wifi.radio`, comando novo, a cada 10 s) mostra:
  - driver, firmware (a linha que o driver escreveu no log do kernel) e phy;
  - padrões e, por faixa, padrões, largura máxima, canais liberados, DFS e potência máxima;
  - antenas, potência em uso e o máximo no canal atual;
  - país e chave do rádio (rfkill);
  - a lista de canais de cada faixa, recolhida.
- O que o driver não informa sai das tabelas e fica numa linha "Not reported by this driver: …",
  inclusive na aba Hardware.

De onde vem no Linux (`crates/hal-linux/src/nl80211.rs`, `wifi.rs`):

- `SIGNAL_POLL`/`STATUS` do `wpa_supplicant`: ruído, largura, centro, geração e cifra.
- nl80211 `GET_STATION`: taxas, MCS, fluxos, GI, sinal médio e por cadeia, retransmissões,
  beacons perdidos e inatividade.
- `GET_WIPHY` (dump dividido): faixas, capacidades HT/VHT/HE/EHT, canais com potência e radar,
  antenas.
- `GET_INTERFACE`: potência em uso.
- `/sys/class/ieee80211/<phy>/rfkill*`: a chave do rádio.
- `/dev/kmsg`: o firmware. Não há atributo nl80211 para ele, e o `ETHTOOL_GDRVINFO` pede ioctl,
  que exigiria `unsafe`.

Números das constantes: `include/uapi/linux/nl80211.h` do kernel 6.18.59, com a linha citada no
código. Um `radio()` custa 13 ms na primeira chamada (lê o log inteiro e procura a família
genl) e 0,4 ms depois (**medido** num mt7925e).

### Porta Wi-Fi no assistente do console

`apps/corerouter-init/src/setup_wifi.rs`. O assistente do primeiro boot lista os rádios junto
das portas (`wifi1`, `Wi-Fi`). Escolhido um rádio, entra um passo a mais, `[2/5] Wi-Fi network`:

1. **País**, se o roteador ainda não tem (duas letras; o motor valida).
2. **Varredura:** o rádio é ligado para varrer, e o assistente avisa. Lista numerada das redes
   em que dá para entrar, a mais forte de cada nome primeiro; `r` varre de novo, `h` é rede
   oculta (digita-se o nome).
3. **Senha**, lida sem eco. O `interface.wifi.preview` confere antes de seguir; rede aberta
   pede confirmação.
4. **Endereço:** `dhcp` (o padrão num rádio) ou endereço/prefixo e gateway.

Depois do resumo e do sim, o rádio tem 30 s para entrar. Se não entrar (senha errada, AP que
recusa), a rede é tirada, o rádio volta a ficar desligado e o motivo aparece. Cancelado no
meio, o rádio volta a como estava; o país fica (é um fato sobre onde o roteador está). O nome
das redes passa por `style::ascii` antes de ir para a tela: qualquer um no alcance escolhe um
SSID.

`cargo xtask os wifi-test --only setup` responde ao assistente num segundo console da VM, como
uma pessoa: país inválido, senha curta, senha errada (nada fica aplicado), depois a certa e um
endereço fixo. O segundo console é virtio (`hvc0`) e não uma segunda serial: o kernel aceita um
console por tipo de dispositivo, e a serial fica com o shell de manutenção do teste.

### Aba Networks: lista, canais e espectro (G1.30i)

Três visões do que o rádio ouviu, escolhidas na segunda linha da aba (`crates/ui/src/wifi_scan.rs`).
Na linha do `Rescan`, a caixa **Auto** com o intervalo (10, 30 ou 60 s) refaz o scan sozinha na
Lista e nos Canais e começa de novo o spectral scan quando a duração acaba. Ela começa desligada,
só roda com a aba desenhada e desliga ao fechar a janela, ao trocar de aba ou com **Stop** no
espectro. Com o rádio conectado a uma rede, mostra o selo âmbar `leaves the channel` (cada scan
tira a estação do canal, e a latência sobe) e o intervalo mínimo vira 30 s.
O motor calcula tudo (`crates/engine/src/wifi_air.rs`, `wifi_spectrum.rs`,
`cmd/wifi_scan.rs`); a GUI só desenha, com o painter do egui.

- **Lista** (`interface.wifi.networks`): canal com selo de largura (20 a 320 MHz) e geração
  (Wi-Fi 4 a 7), carga do BSS Load (clientes e % de ocupação, âmbar de 30%, vermelho de 60%) e
  a coluna **Air**: `same channel ×N`, `overlaps ch …` e `shares airtime ×N`. A rede em uso tem
  o selo verde `yours`. Filtro por banda em selos com contagem (`All`, `2.4 GHz`, `5 GHz`,
  `6 GHz`), `Group by channel` (um cabeçalho por canal primário) e, embaixo, o canal menos
  ocupado de cada banda (com o selo `DFS` quando é um).
- **Canais** (`interface.wifi.frequency-scan`): por banda, cada rede é uma curva da largura do
  canal, da altura do sinal (como o Channel Analysis do LuCI). Embaixo, uma barra por canal
  com a ocupação medida pelo driver (`NL80211_CMD_GET_SURVEY`), e um traço onde ele não mediu.
  O selo do título diz se a medida é completa, parcial (só o canal em uso: mt7925e, **medido**)
  ou não existe.
- **Espectro** (`interface.wifi.spectral-scan`, `spectral-data`): como o airView. Mostra a
  cascata (último minuto, quatro linhas por segundo, do piso de ruído até 50 dB acima), os
  traços de tempo real, média e pico, e o uso de cada canal de 20 MHz (a parte das amostras em
  que a CCA acharia o canal ocupado: energia larga como Wi-Fi a partir de −82 dBm, qualquer
  energia a partir de −62 dBm). Também lista as fontes: `Wi-Fi`, `carrier`
  (cw), `microwave oven` (mwo), `Bluetooth`/`hopper` (fhss) e `unknown`, classificadas pela
  forma. A faixa é o canal em uso, a banda de 2,4 GHz ou a de 5 GHz; a banda é varrida com um
  scan a cada 4 s, e a tela avisa que o enlace para durante cada um. Só existe em rádio com
  spectral scan (Qualcomm Atheros: ath9k, ath10k, ath11k, por debugfs). Nos outros o botão fica
  desligado, e a dica diz o motivo, por exemplo "this radio (rtw89_8852be) has no spectral
  scan: it needs a Qualcomm Atheros chip".

**Sobreposição e disputa** (`wifi_air.rs`):

- Cada rede ocupa `centro ± largura/2`, lidos dos elementos do beacon: HT, VHT, HE com a
  informação de 6 GHz e EHT (IEEE 802.11-2020 §9.4.2.56, §9.4.2.158, §9.4.2.249; IEEE
  802.11be-2024 §9.4.2.311). Em 2,4 GHz, 1 MHz a mais de cada lado (a máscara DSSS), então
  canais a menos de 5 de distância se sobrepõem.
- Outra rede divide o ar desta nos dois casos da CCA (IEEE 802.11-2020 §17.3.10.6, §19.3.19.5,
  §21.3.18.5):
  - o primário desta cai num dos 20 MHz do canal dela e ela chega a −82 dBm ou mais (preâmbulo);
  - os canais só se sobrepõem e ela chega a −62 dBm ou mais (energia).
- O nível é o que este rádio ouve, uma estimativa do que o ponto de acesso ao lado ouve.

**Como o scan chega** (`hal-linux`):

- O `BSS <n>` passou a pedir só os campos usados (`MASK=0x1c86`).
- Antes, a máscara padrão trazia também os elementos do beacon. Uma resposta acima de 4096 bytes
  (`ctrl_iface.c`, `reply_size`) volta vazia, e isso parecia o fim da lista: um ponto de acesso
  com muitos elementos cortava a varredura. Agora, se a resposta vem vazia, a mesma entrada é
  pedida de novo sem os elementos.
- O survey é lido junto com o resultado de cada scan.

**O spectral scan no Linux:**

- O spectral scan roda numa thread `wifi-spectral-<rádio>`. Ela escreve `background` (ou
  `chanscan` no ath9k, ao varrer uma banda) e `trigger` em `spectral_scan_ctl`, e lê os
  arquivos relay `spectral_scan<cpu>`.
- As amostras vão para uma fila de até 4096, e a mais velha sai primeiro. O formato é o de
  `drivers/net/wireless/ath/spectral_common.h` (HT20, HT20/40, ath10k, ath11k).
- A potência por bin segue a conta do FFT_eval:
  `ruído + rssi + 20·log10(bin << max_exp) − 10·log10(Σ bin²)`.
- O laboratório gera o espectro no formato do ath10k e o lê pelo mesmo parser.

## Pesquisa

Feita antes do código (2026-11-11). Os arquivos completos, com todos os links e a marca
conferido/não conferido de cada item, ficaram na pasta de notas da sessão; aqui vai o que
decidiu o desenho.

### MikroTik RouterOS 7.25

Fontes: <https://manual.mikrotik.com/docs/7.25/wireless/wifi/>,
<https://help.mikrotik.com/docs/spaces/ROS/pages/8978446/Wireless+Interface>,
<https://manual.mikrotik.com/docs/7.25/wireless/user-guides/wireless-station-modes/>,
<https://help.mikrotik.com/docs/spaces/ROS/pages/40992872/Packages>.

- Menu novo `/interface/wifi`: `configuration.mode` = `ap` (padrão), `station`,
  `station-bridge`, `station-pseudobridge`; `security.authentication-types` com `wpa2-psk`,
  `wpa3-psk`, `owe` e os EAP; `passphrase` até 63 caracteres, mínimo 8 em WPA2;
  `management-protection` exigido em WPA3; `scan` com endereço, canal, segurança, sinal e
  SSID; a interface nasce desativada; país padrão `Latvia`.
- Uma rede por interface: o menu novo não tem `connect-list`.
- No x86 e no CHR só existe o pacote `wireless` legado, que não tem WPA3, SAE nem OWE; os
  `wifi-qcom*` são de arm e arm64. Não há lista oficial de chips Wi-Fi para x86.
- Estação simples não entra em bridge: o quadro 802.11 comum leva três endereços.
- `export` esconde o segredo; `show-sensitive` mostra.

### Outros

- **VyOS** (<https://docs.vyos.io/en/latest/configuration/interfaces/wireless.html>):
  `type station`, `wpa_supplicant` por baixo, país global, senha validada em 8–63. Guarda a
  senha em texto puro na config.
- **OpenWrt** (<https://openwrt.org/docs/guide-user/network/wifi/basic>,
  <https://openwrt.org/docs/guide-user/network/wifi/connect_client_wifi>): `mode sta`,
  `encryption psk2/sae/sae-mixed/owe`; LuCI com "Scan → Join Network"; o pacote travelmate
  traz redes salvas com prioridade, portal cativo e MAC aleatório.
- **OPNsense e pfSense** (<https://docs.opnsense.org/manual/wireless.html>,
  <https://docs.netgate.com/pfsense/en/latest/wireless/configuration-wan.html>): recomendam AP
  externo; cliente Wi-Fi como WAN existe e não faz bridge.

### Normas

- WPA2-PSK: senha de 8 a 63 caracteres ASCII ou chave de 64 dígitos hexadecimais.
- WPA3-Personal (SAE): RFC 7664 (Dragonfly; §3.2 hunting-and-pecking, §3.3 Commit, §3.4
  Confirm) e o hash-to-element; PMF obrigatório. 6 GHz só com WPA3 ou OWE (RFC 8110).
- Regulatório: `wireless-regdb`, `country BR: DFS-FCC` (2400–2483,5 MHz a 30 dBm; 5150–5350
  só interno; 5470–5725 com DFS; 5925–7125 a 12 dBm, interno). No domínio mundial `00` todo o
  5 GHz é só escuta. Estação não inicia transmissão em canal DFS.

### Fonte do kernel 6.18.59

- Em `iwlwifi`, `mt76`, `rtw88` e `rtw89` a autenticação SAE e o 4-way handshake rodam em
  espaço de usuário: o mac80211 só oferece `.auth` e `.assoc` (`net/mac80211/cfg.c`); em toda
  a árvore só o `brcmfmac` anuncia `4WAY_HANDSHAKE_STA_PSK` e `SAE_OFFLOAD`.
- Placa Intel é autogerida (`REGULATORY_WIPHY_SELF_MANAGED`, `mvm/mac80211.c`): o núcleo
  regulatório a pula (`reg.c`) e o país configurado não muda nada; o firmware decide. Em
  MediaTek e Realtek o país vale.
- Com `RFKILL_INPUT=y` o próprio kernel liga e desliga os rádios na tecla de modo avião
  (`net/rfkill/input.c`).
- `mac80211_hwsim`: os comandos de criar rádio são `GENL_UNS_ADMIN_PERM`, então rádios podem
  ser criados dentro de um namespace sem privilégio, depois que root carrega o módulo; scan e
  conexão também rodam assim; definir o país exige root (`GENL_ADMIN_PERM`).

### Rust puro × `wpa_supplicant` × iwd

| | `wpa_supplicant` 2.12 | Rust puro | iwd 3.0 |
|---|---|---|---|
| Na imagem (zstd) | 2,36 MB com OpenSSL e libnl (**medido**, bibliotecas do host) | 0,2–0,4 MB (**estimado**) | 1,0–1,2 MB (**estimado**) |
| Memória parada | 4,1–4,2 MB RSS (**medido**) | 0,3–1 MB (**estimado**) | 5–8 MB com dbus-daemon (**estimado**) |
| Processos a mais | 1 para todos os rádios | 0 | 2 |
| Esforço | 80–140 h (**estimado**) | 1 000–1 700 h (**estimado**) | 120–200 h (**estimado**) |
| Wi-Fi 7 (MLO) | sim | a escrever | não |

- A vazão é igual nas três: o caminho de dados fica no kernel e no driver; o espaço de usuário
  só vê os quadros de autenticação e os EAPOL. O tempo para associar é o scan (~3 s,
  **estimado** pelos tempos de permanência por canal de `net/mac80211/scan.c`).
- Não existe implementação Rust mantida do lado estação. O `wl-nl80211` cobre netlink e
  codecs, sem máquina de estados nem criptografia; o SAE do Fuchsia não está no crates.io e
  depende do BoringSSL por FFI.
- O `wpa_supplicant` tem 4 477 casos de teste hwsim na tag `hostap_2_12` (**medido**) e 30
  avisos de segurança desde 2014; 11 alcançam uma estação PSK/SAE, e 4 desses são falhas de
  protocolo ou de canal lateral, que uma implementação nova teria também.
- O iwd exige D-Bus e 20 opções de kernel a mais, e não faz MLO.

**Decisão: orquestrar o `wpa_supplicant`**, com a leitura de estado do rádio pelo cliente
generic netlink que o `hal-linux` já tem. É o caso em que correção e interoperabilidade pesam
mais que desempenho (como o BGP e o OSPF no FRR): o plano de controle de uma estação não é
gargalo, e um supplicant próprio poria erros de autenticação dentro do processo que é o plano
de controle do roteador. Rever se aparecer um supplicant Rust maduro.

O que a escolha traz: OpenSSL entra na imagem pela primeira vez (o SAE do `wpa_supplicant` só
existe com OpenSSL ou wolfSSL) e um processo C a mais, supervisionado pelo PID 1.

### Visões do scan (G1.30i)

- **MikroTik** (<https://help.mikrotik.com/docs/spaces/ROS/pages/224559120/WiFi>):
  - `/interface/wifi/frequency-scan` (`duration`, `frequency`, `rounds`, `save-file`) dá por
    canal `networks`, `load`, `nf`, `max-signal` e `min-signal`, com as flags P e S. Avisa que
    derruba os clientes do AP.
  - `/interface/wifi/spectral-scan` só existe no `wifi-qcom`, a partir da 7.16. Os parâmetros
    são `range`, `duration`, `peak-hold-duration` e `show-interference`, e as classes são MWO,
    CW, WIFI, CORDLESS24/5, BLUETOOTH e FHSS.
  - O legado `/interface wireless spectral-scan` e o `spectral-history`
    (<https://help.mikrotik.com/docs/spaces/ROS/pages/139526162/Spectral+scan>) são Atheros
    802.11n. Eles tiram janelas de 20 MHz em passos de 10 MHz, com `range` 2.4ghz, 5ghz ou
    current-channel. Não funcionam em QCA98xx nem IPQ-4018.
  - Adotamos os nomes `frequency-scan` e `spectral-scan`, as colunas do frequency-scan e as
    classes do spectral-scan.
- **Ubiquiti airView** (<https://dl.ui.com/datasheets/airmax/UBNT_DS_airView.pdf>;
  <https://help.uisp.com/hc/en-us/articles/22590893851927-airMAX-Guide-to-Channel-Scanning-with-airView>):
  - Mostra a cascata (cores frias a quentes, do piso de ruído ao máximo), a waveform, o tempo
    real com Max Hold, Average e Real-time, e o "Channel Usage".
  - No airMAX M avisa para não rodar com estações conectadas, porque o enlace pode cair. No
    airMAX AC usa um rádio dedicado.
  - Adotamos a cascata, os três traços e o uso por canal. O UniFi (Environment, Channel AI)
    sugere canal, e adotamos a sugestão do canal menos ocupado.
- **OpenWrt LuCI Channel Analysis** (`channel_analysis.js`):
  - Desenha um trapézio por rede, largura do canal por altura do sinal, e lê HT, VHT (CCFS1 a 8
    de distância = 160 MHz), HE e EHT.
  - No fórum, o scan derruba clientes
    (<https://forum.openwrt.org/t/feedback-request-new-channel-analysis-feature-in-webui/79564/61>).
    Por isso o aviso nos ⓘ e na varredura de banda.
- **Normas:**
  - CCA: −82 dBm de preâmbulo no primário de 20 MHz e −62 dBm de energia, nas cláusulas OFDM, HT
    e VHT de IEEE 802.11-2020 (§17.3.10.6, §19.3.19.5, §21.3.18.5). O HE fica no 802.11ax-2021,
    cláusula 27; a subcláusula exata não foi conferida.
  - Elementos: §9.4.2.26 do BSS Load (numeração do 802.11-2024, a do kernel), §9.4.2.56,
    §9.4.2.158 com a regra CCFS1 do 160/80+80, §9.4.2.249 com a informação de 6 GHz.
  - O CCA de canal secundário (−72 dBm) não foi conferido no texto da norma e ficou de fora: o
    secundário entra pela regra de energia.
- **Fonte:**
  - Linux 6.18.59: `spectral_common.h`, `ath9k/common-spectral.c`, `ath10k/spectral.c` e
    `ath11k/spectral.c`, com os comandos do `spectral_scan_ctl` e `relay_open("spectral_scan",
    …)`, um arquivo por CPU.
  - Os números de `nl80211.h` foram conferidos compilando o cabeçalho: `GET_SURVEY` = 50,
    `ATTR_SURVEY_INFO` = 84.
  - wpa_supplicant 2.12: `print_bss_info` e `reply_size = 4096`.
  - Uma placa real: um AP Wi-Fi 7 de 160 MHz lido do host com nl80211 (VHT CCFS0 106, CCFS1
    114). Virou teste, com o nome trocado e sem os elementos com MAC.
- **Melhorias sobre os outros:**
  - a disputa pela regra da CCA, não só "mesmo canal";
  - o motivo de cada coisa no ⓘ;
  - o survey parcial dito como parcial, em vez de 0%;
  - o espectro em comandos que o MCP e a CLI também leem;
  - a varredura de banda com aviso.

### O que ficou de fora e por quê

- **Modo AP:** G1.30a, `docs/wifi-ap.md`.
- **Wi-Fi na ISO live:** o kernel da ISO fica sem a pilha (`installer.fragment`). Entrar numa
  rede é coisa do roteador instalado (G1.30c). A raiz do live é a da imagem e vai para a RAM,
  então o firmware de Wi-Fi custa RAM ali mesmo sem uso: o mínimo do live subiu de 320 para
  448 MiB (`docs/os-image.md`).
- **WPA-Enterprise (802.1X), OWE, redes salvas com prioridade, portal cativo, MAC aleatório:**
  gaps depois da parte 2.
- **Bridge de uma estação (4 endereços/WDS):** só funciona com AP que fale WDS; fica para
  quando houver pedido.
