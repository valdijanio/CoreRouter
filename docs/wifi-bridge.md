# Wi-Fi station-bridge e pares (G1.30m)

Um enlace Wi-Fi entre dois roteadores que leva a LAN: o rádio de um lado é um **ponto de
acesso** que aceita **pares** cadastrados, o do outro é um **station-bridge**, um cliente cujos
quadros levam quatro endereços. Os dois são portas de bridge (e, na parte 2, membros de um
bonding). É o "PTP bridge" de um provedor, a ligação até um prédio do outro lado da rua.

| Parte | O que entra |
|---|---|
| 0 | portas Wi-Fi cinza com ⓘ na janela de bonding (#625) |
| 1 | `mode=station-bridge`, `bridge_protocol`, `station_bridge` no AP, pares (`interface.wifi.peer.*`), bridge |
| 2 | bonding sobre os enlaces, diagnóstico por par, teste com dois enlaces |

## Por que quatro endereços

Um quadro de uma estação comum leva três endereços: o rádio que envia, o que recebe e o destino
final (IEEE 802.11-2020 §9.3.2.1, "To DS"). O ponto de acesso só passa o que sai do MAC da
própria estação. Uma bridge atrás da estação encaminha quadros de outras máquinas, e o AP os
descarta. Por isso o kernel recusa uma estação numa bridge: o cfg80211 marca `IFF_DONT_BRIDGE`
(`net/wireless/util.c:1243-1252`) e a bridge recusa a porta (`net/bridge/br_if.c:597`, Linux
6.18.59). Com quatro endereços (o quarto é a origem verdadeira), a marca sai e a interface é uma
porta como outra qualquer.

O IEEE 802.11 define o quadro de quatro endereços, mas não como combiná-lo. Daí os dois
protocolos:

- **`multi-ap`** (o padrão): o backhaul do Wi-Fi EasyMesh (Multi-AP). A estação diz na
  associação que é um backhaul (o elemento Multi-AP) e o AP lhe dá quatro endereços. No
  `wpa_supplicant` é `multi_ap_backhaul_sta=1`; ele liga os quatro endereços quando o AP aceita.
  No hostapd do AP é `multi_ap=3` (backhaul e clientes) ou `1` (só backhaul).
- **`wds`**: quatro endereços ligados à mão desde o início, sem negociação: o que o OpenWrt
  (`option wds 1`) e outros chamam de WDS. O CoreRouter liga o `NL80211_ATTR_4ADDR` antes de
  entregar o rádio ao supplicant (`iw dev … set 4addr on`); o AP precisa de `wds_sta=1`.

Nenhum dos dois fala com o `station-bridge` do MikroTik, que é próprio e só funciona entre
RouterOS.

## Como se usa

Lado do AP (roteador A):

```sh
corerouter-cli run interface.wifi.set '{"name":"wifi1","mode":"ap","ssid":"Backhaul","passphrase":"…","station_bridge":"yes","disabled":false}'
corerouter-cli run interface.wifi.peer.add '{"radio":"wifi1","name":"peer1","mac_address":"<MAC do rádio do B>"}'
corerouter-cli run interface.bridge.port.add '{"bridge":"bridge1","interface":"wifi1"}'
corerouter-cli run interface.bridge.port.add '{"bridge":"bridge1","interface":"peer1"}'
```

Lado do cliente (roteador B):

```sh
corerouter-cli run interface.wifi.set '{"name":"wifi1","mode":"station-bridge","ssid":"Backhaul","passphrase":"…","disabled":false}'
corerouter-cli run interface.bridge.port.add '{"bridge":"bridge1","interface":"wifi1"}'
```

Na GUI: Interfaces › Wi-Fi, duplo clique no rádio, Mode `station-bridge` ou `ap` com Station
Bridge `yes`; aba **Peers** para cadastrar e ver os pares.

## Os pares

Cada par é uma **interface própria** (tipo `wifi-peer`) com o nome que o operador escolheu. Ela
existe enquanto o par está associado e pode ser porta de bridge ou membro de bonding. Com o par
ausente, a configuração dela espera, como a de uma porta desconectada (`corerouter_hal::absent`;
`interface.list` a mostra inválida com "peer not associated").

- O hostapd cria a interface do par (`wds_sta=1`: `<rádio>.sta<AID>`, `driver_nl80211.c`
  `i802_set_wds_sta`) e avisa no socket (`WDS-STA-INTERFACE-ADDED ifname=… sta_addr=…`). A thread
  do AP a renomeia para o nome do par (desce, renomeia, sobe) e o motor a põe onde a
  configuração diz.
- **Só os pares cadastrados ganham quatro endereços.** Uma estação que pede e não está cadastrada
  é desligada (`DEAUTHENTICATE`), e o histórico diz por quê.
- O hostapd procura a interface pelo nome antigo para apagá-la quando o par sai; a thread do AP
  apaga a renomeada.

`station_bridge`: `no` (o padrão: ninguém ganha quatro endereços), `yes` (clientes e pares),
`only` (só pares: um AP de backhaul, só estações Multi-AP).

## Segurança por padrão

- Desligado por padrão: `station_bridge=no`, e só os MACs cadastrados entram.
- **Backhaul só WPA3** (SAE, quadros de gerência protegidos): `wpa2` e `open` são recusados num
  station-bridge e num AP com pares; `auto` vira WPA3 no station-bridge e no AP `only`.
- **Laço:** as bridges do CoreRouter não rodam spanning tree. Dois enlaces de backhaul na mesma
  bridge dão aviso: dois enlaces entre os mesmos roteadores vão num bonding (parte 2).

## Como roda

- **Estação** (`crates/hal-linux/src/wifi.rs`): `multi_ap_backhaul_sta=1` na rede, ou o 4addr
  por nl80211 antes dela (`NL80211_CMD_SET_INTERFACE` com `NL80211_ATTR_4ADDR`). Depois de
  conectar, a thread do rádio põe a interface na bridge (`link_set::set_master`). Antes disso o
  kernel a recusaria, e por isso o `plan` não põe porta Wi-Fi em bridge (G1.30a).
- **AP** (`crates/hal-linux/src/wifi_ap.rs`): `wds_sta=1` e `multi_ap`; os eventos `WDS-STA-*`
  viram `PeerUp`/`PeerDown`, e a tabela de clientes marca o par.
- **Laboratório virtual:** o AP do laboratório recebe os pares cadastrados (WPA3, Wi-Fi 6,
  −55 dBm), e a interface do par aparece no `interface.list` enquanto ele está associado.

## Teste de ponta a ponta

```sh
cargo xtask os wifi-test --only bridge
```

O teste roda no QEMU com dois rádios `mac80211_hwsim`:

1. **O roteador como AP com par:** o rádio de teste é uma estação Multi-AP de backhaul (o
   `wpa_supplicant` da imagem com `multi_ap_backhaul_sta=1`). Confere que:
   - o par sobe como `peer1`, dentro da `bridge1`;
   - o nome do hostapd some.

   Depois o par é trocado por outro MAC, e confere que a mesma estação é desligada, com o motivo
   no histórico.
2. **O roteador como station-bridge:** o hostapd de teste, com `multi_ap=3` e `wds_sta=1`, é o
   AP. Primeiro em `multi-ap`, depois em `wds`. Confere que:
   - o rádio do roteador conecta (WPA3) e entra na `bridge1`;
   - o AP de teste cria a interface de quatro endereços dele.

O que o teste não mostra:

- **Tráfego de dados entre os dois lados.** Os dois rádios estão no mesmo kernel, que entrega os
  pacotes pelo `lo`.
- **Hardware real:** falta um segundo aparelho com Wi-Fi. O teste numa placa fica para quando
  houver um segundo rádio.

## Pesquisa

Notas completas em `G1.30a-G1.30m-pesquisa.md`, na pasta de notas da sessão principal.

- **MikroTik v7** (<https://help.mikrotik.com/docs/spaces/ROS/pages/224559120/WiFi> e "Wireless
  Station Modes" do pacote antigo):
  - `station-bridge` é proprietário e só funciona entre RouterOS; no pacote antigo, o AP aceita
    com `bridge-mode` (ligado por padrão), qualquer estação RouterOS com a senha;
  - `station-pseudobridge` traduz o MAC e só serve para um dispositivo atrás;
  - `station-wds` cria uma interface WDS por estação no AP.
- **hostapd 2.12** (fonte da imagem):
  - `wds_sta` e o nome `<ifname>.sta<aid>` (`driver_nl80211.c:9312`);
  - `wds_bridge`, que cai para `bridge` quando vazio (`ap_drv_ops.c:398`);
  - o evento `WDS-STA-INTERFACE-*` (`drv_callbacks.c:2389`);
  - `multi_ap` 1/2/3, e o BSS só de backhaul recusa estação sem o elemento Multi-AP
    (`ieee802_11.c`, `check_multi_ap`).
- **wpa_supplicant 2.12:** `multi_ap_backhaul_sta` (`wpa_supplicant.conf:1785`) liga o 4addr
  sozinho quando o AP aceita.
- **OpenWrt:** `option wds 1` nos dois lados; **Ubiquiti:** "WDS transparent bridge". Os WDS de
  fabricantes diferentes não se garantem entre si: o padrão define o quadro, não a negociação.
- **Wi-Fi Alliance EasyMesh (Multi-AP):** BSS de backhaul e estação de backhaul; perfis 1 e 2
  (o hostapd usa o 2 por padrão).
- **Kernel 6.18.59:** `IFF_DONT_BRIDGE` (`net/wireless/util.c:1243`, `core.c:1568`); o mac80211
  anuncia 4addr para AP e estação (`main.c:862`).

**Adotado, melhor que o MikroTik:**

- interoperável (Multi-AP é padrão; o WDS fala com o OpenWrt);
- pares cadastrados por MAC, com nome fixo, em vez de "qualquer estação com a senha";
- WPA3 obrigatório no backhaul;
- aviso de laço;
- a configuração do par espera por ele como a de uma porta.

**Fora, e por quê:**

- interoperar com o `station-bridge` do MikroTik: formato proprietário sem especificação, a
  mesma decisão da G5;
- `station-pseudobridge`: tradução de MAC, um dispositivo só; rotear resolve melhor;
- spanning tree nas bridges: não existe no CoreRouter, e o aviso de laço cobre o caso comum.

## Desempenho e paralelismo

- **Por item:** nada por pacote. O caminho de dados é do mac80211 (o AP_VLAN do par) e da
  bridge. Por par há um evento ao associar e outro ao sair (renomear, apagar). A tabela de
  pares é a de clientes, lida a cada 2 s.
- **Threads:** as do rádio (G1.30, G1.30a). Renomear e pôr na bridge são pedidos netlink
  síncronos de dezenas de µs, feitos na thread do rádio, nunca no tick do motor.
- **Mais núcleos não ajudam aqui.** O que limita um enlace de backhaul é o ar (a taxa e as
  retransmissões), não a CPU. Somar enlaces é a parte 2 (bonding), que divide o tráfego por
  enlace.
