# Wi-Fi como ponto de acesso (G1.30a)

O rádio anuncia uma rede e os clientes entram nela: o roteador de uma loja, de um escritório
pequeno, de uma casa. É a parte 1 da G1.30a, o **AP mínimo** que o dono aprovou em 2026-11-11:
SSID, WPA2/WPA3, canal e largura, país obrigatório, porta de bridge, tabela de clientes e a
recusa do que o rádio não permite. O resto da G1.30a (lista de acesso, RADIUS, vários SSIDs por
rádio) vem depois; o station-bridge entre dois CoreRouters é a G1.30m.

## Como se usa

```sh
corerouter-cli run interface.wifi.country.set '{"country":"BR"}'
corerouter-cli run interface.wifi.set '{"name":"wifi1","mode":"ap","ssid":"Loja","passphrase":"…","disabled":false}'
corerouter-cli run interface.bridge.port.add '{"bridge":"bridge1","interface":"wifi1"}'   # os clientes na LAN
corerouter-cli run interface.wifi.monitor '{"name":"wifi1"}'
corerouter-cli run interface.wifi.registration-table.print '{}'
```

No terminal: `/interface wifi set wifi1 mode=ap ssid=Loja passphrase=…`,
`/interface wifi registration-table print`. Na GUI: Interfaces › Wi-Fi, duplo clique no rádio,
Mode `ap`; a aba **Registration** lista os clientes.

| Parâmetro (`interface.wifi.set`) | No AP |
|---|---|
| `mode` | `station` (o padrão, a G1.30) ou `ap` |
| `ssid`, `hidden` | o nome anunciado; `hidden`: beacon sem o nome |
| `security` | `auto` (o padrão): WPA2 e WPA3 juntos (transição, MFP oferecido); `wpa3` (só SAE, MFP obrigatório); `wpa2`; `open` |
| `passphrase` | 8 a 63 caracteres; a chave de 64 dígitos só com `wpa2` (o SAE precisa da frase) |
| `frequency` | canal (`36`), MHz (`5180`) ou `auto` |
| `width` | 20, 40, 80, 160 MHz ou `auto` |
| `band` | a banda do canal automático (`2ghz`, `5ghz`) |
| `bssid` | recusado: é a escolha de AP de uma estação |

**Canal automático:** o canal mais quieto da última varredura (`crate::wifi_air::suggest`, o
mesmo da aba Networks) entre os que o país deixa abrir rede sem radar; sem varredura, o primeiro
deles. A banda é 5 GHz quando o rádio pode abrir rede lá, senão 2,4. A largura é 20 MHz em
2,4 GHz (40 ali toma dois dos três canais que não se sobrepõem) e a maior até 80 MHz em 5 GHz
que caiba inteira em canais permitidos e sem radar. Escolhido, o canal fica até as
configurações mudarem.

## O que é recusado (e onde)

Tudo no comando, com o motivo, antes de qualquer coisa ir ao rádio (`crate::wifi_ap::plan`, a
partir do que o nl80211 diz do rádio no país em vigor):

- canal que o país não permite (`disabled`), canal passivo (`NO_IR`: uma estação responde ali,
  um AP não pode abrir rede), canal que o rádio não tem;
- largura maior que a do rádio na banda, ou um bloco de 40/80/160 MHz com um canal de 20 MHz
  proibido ou passivo;
- AP em 6 GHz (por enquanto, G1.30n) e rádio cujo driver não tem o modo AP (`NL80211_IFTYPE_AP`
  fora dos tipos que o wiphy oferece);
- rádio ligado sem país (a validação do commit, como na estação);
- `bssid` num AP, e voltar a `station` com o rádio numa bridge (a estação não pode ser porta);
- trocar o modo do rádio por onde a sessão chega, fora do Safe Mode (o `guard_link` da G1.30).

Canal com radar (DFS, 52 a 144) é aceito com aviso: o AP escuta um minuto antes do primeiro
beacon (dez nos canais do radar meteorológico, 120 a 128). O modal da GUI mostra o canal que o
AP vai usar, ou o motivo de não poder, no próprio campo.

## Como roda

- **Motor** (`crates/engine/src/wifi_ap.rs`): no mesmo relógio da estação. Um rádio em `ap`
  fecha a estação primeiro e abre a porta de AP da plataforma; diz a rede **uma vez por
  mudança** (o que distingue uma da outra é a caixa selada da senha, não a senha) e lê os
  eventos; o estado e os clientes a cada 2 s. Por rádio e por tick o trabalho é uma leitura de
  eventos; nada cresce com o tráfego, e os clientes são no máximo 256 por rádio.
- **Plataforma** (`crates/hal/src/wifi_ap.rs`): o trait `WifiApPort` (`start`, `stop`,
  `status` com os clientes, `events`). O laboratório virtual (`lab_wifi_ap.rs`) sobe o AP, passa
  dois polls em checagem de radar num canal DFS e recebe dois clientes inventados (um celular
  WPA3 Wi-Fi 6 e um notebook WPA2 Wi-Fi 5, que não entra numa rede só WPA3).
- **Linux** (`crates/hal-linux/src/wifi_ap.rs`): um `hostapd` 2.12 para todos os rádios,
  iniciado só com o socket global (`-B -g <runtime>/hostapd/global`), **sem arquivo de
  configuração e sem log** (`-d`, `-f`, `-s` levariam os valores do `SET`). Cada rádio entra
  por um `ADD <ifname> <dir> nl80211` dinâmico (`hostapd_add_iface`: interface com os padrões e
  sem arquivo), recebe os campos um `SET` por vez no socket dele (`hostapd_set_iface` →
  `hostapd_config_fill`, o mesmo leitor do arquivo) e sobe com `ENABLE`. O SSID vai em hex
  (`ssid2`); a senha vai num `SET` e em nenhum outro lugar. Mudou a configuração: `REMOVE` e
  um `ADD` novo, sem resto da anterior. O `hostapd` termina com o último AP (o `hostapd` não tem
  `INTERFACES` nem `TERMINATE` no socket global: a pasta `if/` vazia diz que acabou, e ele leva
  `SIGTERM` pelo pid, conferido no `/proc/<pid>/comm`). Sobrevive a um restart do daemon, com
  os clientes conectados.
- **Uma thread por rádio** (`wifi-ap-<nome>`), a única que fala com o hostapd, com fila de 8
  ordens ("ocupado" quando cheia); estação e AP do mesmo rádio se revezam pela mesma trava
  (`turn_of`), então o AP só entra depois de a estação sair do `wpa_supplicant`. Um daemon
  reiniciado depois de trocar o modo tira o rádio do outro lado também (`INTERFACE_REMOVE` no
  supplicant, `REMOVE` no hostapd).
- **Bridge:** quem põe o AP na bridge é o hostapd (`bridge=`), depois de transformar a
  interface em AP. Antes disso o kernel recusa uma estação numa bridge (`IFF_DONT_BRIDGE`), e o
  `plan` do `hal-linux` deixa de pôr porta Wi-Fi em bridge por conta própria
  (`plan.rs`, `master`).
- **Clientes:** quem está associado vem do hostapd (`STA-FIRST`/`STA-NEXT`: autorizado, AKM →
  WPA3/WPA2, geração pelos flags HT/VHT/HE/EHT); o enlace de cada um (sinal, taxas com MCS,
  pacotes, retransmissões, tempo conectado, inatividade) vem do nl80211 `GET_STATION` em dump,
  a mesma leitura da estação (G1.30g).
- **Eventos em palavras:** `AP-ENABLED`, `AP-DISABLED`, `INTERFACE-DISABLED`,
  `AP-STA-CONNECTED`/`DISCONNECTED`, `AP-STA-POSSIBLE-PSK-MISMATCH` ("wrong passphrase on the
  client"), `DFS-CAC-START`, `DFS-RADAR-DETECTED` (hostapd 2.12 `src/common/wpa_ctrl.h`); vão
  para o histórico (`interface.wifi.history`) e o log do roteador.

### Campos do hostapd

| Campo | Valor |
|---|---|
| `country_code`, `ieee80211d` | o país; `1` (o elemento de país no beacon) |
| `ieee80211h` | `1` num canal com radar (exige `ieee80211d`) |
| `hw_mode`, `channel` | `g` ou `a`; o número do canal |
| `wmm_enabled`, `ieee80211n`, `ht_capab` | `1`; `1`; `[HT40+]`/`[HT40-]` a 40 MHz ou mais |
| `ieee80211ac`, `vht_oper_chwidth`, `vht_oper_centr_freq_seg0_idx` | 5 GHz: `1`; `1` (80) ou `2` (160); o canal do centro |
| `ieee80211ax`, `he_oper_chwidth`, `he_oper_centr_freq_seg0_idx` | quando o rádio fala ax; os mesmos de VHT em 5 GHz |
| `ssid2`, `ignore_broadcast_ssid` | o SSID em hex; `1` se oculta |
| `wpa_passphrase` ou `wpa_psk`, `ieee80211w`, `sae_pwe`, `sae_require_mfp`, `rsn_pairwise`, `wpa_key_mgmt`, `wpa` | `auto`: `WPA-PSK SAE`, MFP `1`, `sae_pwe=2`, `sae_require_mfp=1`; `wpa3`: `SAE`, MFP `2`; `wpa2`: `WPA-PSK`, MFP `1`; `CCMP`; `2` |
| `bridge` | a bridge da porta |

O centro do canal de 40/80/160 MHz vem dos blocos de 20 MHz da banda (IEEE 802.11-2020 Anexo E;
`corerouter_hal::wifi_ap::channel_block`): 36–48 → 42, 52–64 → 58, 149–161 → 155, e o par de
40 MHz em que o primário está diz `HT40+` ou `HT40-`.

## Imagem

O `hostapd` 2.12 entra na imagem (`/usr/sbin/hostapd`; antes era só ferramenta de teste em
`images/test-tools/`). Configuração do Buildroot: nl80211, WPA3/SAE, 802.11n/ac/ax/be, sem
RADIUS, sem VLAN e sem ACS (o canal automático é do motor).

## Teste de ponta a ponta

```sh
cargo xtask os wifi-test --only ap
```

A imagem no QEMU com dois rádios `mac80211_hwsim`. O do roteador (`wifi2`) vira AP só por
comandos; o do teste (`wifi1`) é o cliente, com o `wpa_supplicant` da própria imagem e um
arquivo em `/tmp`. Confere: as recusas (6 GHz, `bssid`), o AP de pé com o canal escolhido, o
`hostapd` da imagem com a senha em nenhum arquivo e em nenhuma linha de comando, a interface na
`bridge1` pelo hostapd, o cliente na tabela com WPA3 e depois WPA2, uma senha errada dita em
palavras no histórico, e a volta para estação (fora da bridge, o `hostapd` encerrado).

O que o QEMU não mostra: uma placa de verdade (a RTL8852BE do notebook declara AP no `rtw89`,
`core.c:6327`, mas não foi posta no ar: mudar o modo do rádio do notebook pede o OK do dono) e
tráfego de dados entre AP e cliente (os dois rádios estão no mesmo kernel, que entrega os
pacotes pelo `lo`; a G1.30m leva o teste para namespaces).

## Pesquisa

Fontes (lidas em 2026-11-11; notas completas em `G1.30a-G1.30m-pesquisa.md` na pasta de notas da
sessão principal):

- MikroTik RouterOS 7, `/interface/wifi`:
  <https://help.mikrotik.com/docs/spaces/ROS/pages/224559120/WiFi>. Nomes adotados: `mode`
  (`ap`, `station`), `ssid`, `hide-ssid` (aqui `hidden`, o nome que a G1.30 já usava),
  `channel.frequency`, `channel.width`, `security.passphrase`, `registration-table`.
  - O MikroTik abre a rede **aberta** por padrão (`authentication-types` vazio) e usa canais DFS
    por padrão (`skip-dfs-channels=disabled`).
  - O país padrão é a Letônia.
  - O WPA3-PSK do MikroTik não tem tamanho mínimo de senha.
- hostapd 2.12: `hostapd/hostapd.conf`, `hostapd/ctrl_iface.c`, `src/ap/hostapd.c`
  (`hostapd_add_iface`), `src/ap/ctrl_iface_ap.c` (`STATUS`, `STA`), `src/common/wpa_ctrl.h`,
  lidos na árvore da imagem (`/srv/build/os-out/G1.6zd/build/build/hostapd-2.12`).
- VyOS (`interfaces wireless … type access-point`): país obrigatório e `channel 0` explícito para
  o automático; OpenWrt (`wifi-iface`, `encryption sae-mixed`, `ieee80211w`): reinicia o BSS num
  radar em vez de CSA.
- IEEE 802.11-2020 §12.6.3 (MFP), Anexo E (canais), Tabela 9-151 (AKM: 2 PSK, 8 SAE); WPA3
  Specification v3.2 §2.4 (modo de transição); ETSI EN 301 893 (DFS: 60 s, 10 min em 5600–5650 MHz).

**Adotado e melhor que o MikroTik:** seguro por padrão (`auto` = WPA2 e WPA3 juntos, nunca
aberta sem pedido; rede aberta e `wpa3` só dão aviso); país obrigatório; canal automático sem
radar (o operador escolhe DFS de propósito, com aviso do minuto mudo); a recusa do que o rádio
não permite **antes** do commit, com o motivo e o canal previsto no modal; a senha nunca em
arquivo.

**Fica para depois:** lista de acesso, RADIUS e WPA-Enterprise, vários SSIDs por rádio,
isolamento de clientes e VLAN por SSID, AP em 6 GHz, troca de canal por radar (CSA), 802.11r
(G1.30a e G1.30n).

## Desempenho e paralelismo

- **Trabalho por item:** por rádio e por tick, uma leitura de eventos; a cada 2 s, um `STATUS`,
  um `STA-*` por cliente e um dump `GET_STATION` (até 256 clientes). Nada por pacote: o caminho
  de dados é do kernel (mac80211 e a bridge).
- **Threads:** uma por rádio (`wifi-ap-<nome>`), só ela fala com o hostapd; o tick do motor só lê
  o que ela deixou (`Seen`, um `Mutex` curto, sem E/S dentro). Rádios diferentes não esperam
  um pelo outro, salvo no `ADD`/fim do hostapd (um `Mutex` do processo, para um rádio não
  encerrar o hostapd enquanto outro entra).
- **Mais núcleos não ajudam aqui:** o hostapd é um processo de um laço só e o custo por cliente é
  uma resposta de socket local (dezenas de µs); o tráfego dos clientes não passa por ele.
