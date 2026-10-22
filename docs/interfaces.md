# Interfaces: estado, hardware e contadores

O diálogo "Interface <nome>" da GUI tem as abas do WinBox: **General**, **Ethernet**,
**Status**, **SFP**, **Hardware**, **Traffic** e **Statistics** (G1.19 + G1.20). General edita
MTU, comentário e Disabled (G1.9); Ethernet edita o link da porta física (G1.20, abaixo); as
outras leem comandos de consulta do engine, que valem também no terminal, na CLI e no MCP.

A semântica segue o RouterOS (`/interface ethernet monitor`, `/interface ethernet print stats`,
`link-downs` / `last-link-up-time` de `/interface print detail`); os nomes de campo seguem o
padrão do CoreRouter (`snake_case` no JSON, `kebab-case` no terminal).

## Comandos

| Comando | O que devolve | Terminal |
|---|---|---|
| `interface.ethernet.monitor {name}` | Estado ao vivo: `status` (`link-ok`/`no-link`), `rate` (`1Gbps`), `full_duplex`, `auto_negotiation` (`done`/`incomplete`/`disabled`), `port`, `mdix`, modos suportados/anunciados/do outro lado, controle de fluxo, `link_downs`, `carrier_changes`, `down_reason`, `last_link_up_time`/`last_link_down_time` | `/interface ethernet monitor ether1` |
| `interface.hardware {name}` | A placa: fabricante/modelo (ids PCI e nomes), driver, versão, firmware, serial, barramento, NUMA, filas, canais, IRQs, rings, offloads, MAC atual e de fábrica, faixa de MTU | `/interface hardware ether1` |
| `interface.ethernet.set {name, …}` | Muda o link da porta física (G1.20, abaixo); é ação (journal, revisão) | `/interface ethernet set ether1 auto-negotiation=no speed=100Mbps` |
| `interface.ethernet.cable-test {name}` | Tarefa: resultado por par (G1.20) | `/interface ethernet cable-test ether1` |
| `interface.stats {name}` | Contadores por grupo: `interface` (stats64 do kernel) e, quando o driver preenche, `eth-phy`, `eth-mac`, `eth-ctrl`, `rmon` (com histograma por tamanho) e `pause` | `/interface stats ether1` |

Regras comuns (das consultas):

- São consultas: não entram no journal nem criam revisão, e o grupo `read` (G0.3) pode rodar.
- Valem para toda interface que existe, na config ou só na plataforma (links não gerenciados
  do G1.18 também; consultar não muda nada).
- **Não suportado não é erro.** Se a plataforma ou o driver não sabe responder, o resultado
  vem com `available: false` e `reason`, e cada campo desconhecido é `null`/lista vazia; o
  `notes` diz o que faltou e por quê ("link modes: not supported by the driver"). A GUI mostra
  "not supported". Só interface inexistente é erro (`no interface 'x' (see interface.list)`).
- `interface.stats` sempre tem ao menos o grupo `interface` com bytes/pacotes (os mesmos de
  `interface.list`).

## Horário das subidas e quedas

O kernel conta as transições de portadora (`IFLA_CARRIER_CHANGES`, `IFLA_CARRIER_DOWN_COUNT`),
mas não guarda horários. O engine anota as transições que vê, com o relógio da sessão: a cada
`Session::tick` (a thread de relógio do daemon e da GUI nativa, uma vez por segundo) e a cada
`interface.list` (`engine::link_watch`). Daí:

- `last_link_up_time` / `last_link_down_time` em segundos Unix; `null` quando não houve
  transição desde `watching_since` (a GUI escreve "up since before watching began (5m ago)").
- `link_downs` é a contagem do kernel quando a plataforma tem uma; senão, a que o engine viu.
- Sem relógio (GUI web no lab) os horários ficam `null` e a GUI diz "unknown".
- É estado operacional: não é salvo, recomeça a cada partida do daemon. Quedas mais curtas que
  1 s podem não ter horário, mas entram na contagem do kernel.

## De onde vem cada dado no Linux (`hal-linux`)

Tudo sem `unsafe` e sem ioctl:

| Fonte | Dados |
|---|---|
| rtnetlink (`RTM_GETLINK` do link) | operstate, MAC atual e de fábrica (`IFLA_PERM_ADDRESS`), min/max MTU, filas rx/tx, barramento e endereço do dispositivo pai (`IFLA_PARENT_DEV_*`, kernel ≥ 5.16), contadores de portadora, stats64 completo |
| ethtool netlink (`genl.rs` + `ethtool.rs`, família genérica `ethtool`) | `LINKMODES` (velocidade, duplex, autoneg, modos), `LINKINFO` (porta, MDI-X), `LINKSTATE` (motivo da queda), `PAUSE` (+ contadores de pause frames), `FEATURES` (offloads; "fixed" = fora do conjunto `hw`, como no `ethtool -k`), `RINGS`, `CHANNELS`, `STATS` (grupos padrão eth-phy/eth-mac/eth-ctrl/rmon, kernel ≥ 5.13) |
| devlink netlink (família `devlink`, `INFO_GET`) | firmware e serial, só para drivers que registram devlink (mlx5, ice, …) |
| sysfs `/sys/bus/<bus>/devices/<dev>/` | ids PCI (vendor/device/subsystem), NUMA, driver (link `driver`), IRQs (`msi_irqs/` ou `irq`); só o dispositivo que o próprio link aponta, então funciona em network namespace (devices não são por namespace, ao contrário de `/sys/class/net`) |
| `/sys/module/<driver>/version` | versão do driver, quando o módulo declara uma |
| `pci.ids` do sistema (`/usr/share/hwdata/pci.ids`, `/usr/share/misc/pci.ids`) | nomes de fabricante/modelo/subsistema; sem o arquivo, a GUI mostra os ids |

Sem ioctl ficam de fora: a versão de firmware de drivers sem devlink (o `ethtool -i` usa
`ETHTOOL_GDRVINFO`) e piscar o LED da porta (`ETHTOOL_PHYS_ID`). Links de software (veth,
bridge, VLAN, dummy) não têm dispositivo: o driver é o tipo do link, como no `ethtool -i`.

As respostas do kernel são entrada hostil: o codec genérico (`genl.rs`) percorre atributos com
limites e para no primeiro malformado (proptest), listas têm teto (`hal::nic::MAX_ITEMS`) e o
`pci.ids` é lido com limite de tamanho e analisado sem pânico (proptest).

## Lab virtual (`VirtualHal`)

Valores simulados, coerentes e determinísticos: portas `ether1..N` com 1 Gb/s full duplex
(a última, 10 Gb/s), autonegociação feita, parceiro anunciando o mesmo; algumas quedas "de
antes" por porta e mais uma a cada vez que a porta é reabilitada; fabricante "CoreRouter",
modelo "Virtual NIC", driver `corerouter-virt`; erros raros (um CRC a cada meio milhão de
quadros) e os grupos eth-mac/rmon/pause. VLAN/bridge/loopback respondem "not an Ethernet port"
no monitor.

## GUI

- As consultas saem com o refresh da UI enquanto o diálogo está aberto: monitor e contadores a
  cada segundo, hardware a cada 10 s, uma de cada por vez; fechar o diálogo para tudo. Também
  na GUI remota (G0.4); um daemon antigo sem os comandos deixa a aba com o motivo (G1.16).
- **Traffic**: bps e pps de Rx/Tx calculados das diferenças dos contadores (≈ 2 min de
  histórico), mesmo gráfico (`egui_plot`) do Tools › Ping.
- **Statistics**: todos os grupos; "Zero view" passa a contar dali em diante **só na janela**
  (nenhum contador do kernel é zerado); "Show totals" volta.
- Enter/Ctrl+Enter/Esc, maximizar e os botões cinza continuam valendo em qualquer aba.

## Pesquisa

- RouterOS v7 (help.mikrotik.com, Ethernet): `monitor` e `print stats` dão os nomes e valores
  (`link-ok`, `rate`, `auto-negotiation`, `link-partner-advertising`, `orig-mac-address`,
  `l2mtu`).
- VyOS: `show interfaces ethernet <if> physical` (saída do ethtool, driver, bus-info) separado dos
  contadores e do `transceiver`; daí as abas Status / Hardware / Statistics.
- Junos: `clear interfaces statistics` guarda a linha de base; aqui a linha de base fica só na
  janela ("Zero view"), sem apagar nada do roteador.
- A mais que o MikroTik: "não suportado" com motivo, hora da última subida/queda, offloads
  "fixed", contadores padrão IEEE 802.3/RMON do kernel. Fora: LED e firmware sem devlink (ioctl).

## Ethernet configurável (G1.20)

`interface.ethernet.set {name, …}` é o `/interface ethernet set` do RouterOS para portas físicas
(tipo `ether`); VLAN, bridge, loopback e VRF são recusados com o motivo.

| Parâmetro | Valores | Notas |
|---|---|---|
| `auto_negotiation` | `true`/`false` | `true` limpa a velocidade forçada; `false` limpa o `advertise` |
| `speed` | `10Mbps`, `100Mbps`, `1Gbps`, `2.5Gbps`, `10Gbps`…, `1000` (Mb/s) ou um modo (`100M-baseT-full`, `1000baseT/Full`) | só com `auto_negotiation=false`; o modo também dá o duplex |
| `duplex` | `full`/`half` | só com `auto_negotiation=false` |
| `advertise` | lista ou `a,b,c` de modos; `all` = todos os que a porta suporta | só com autonegociação; nomes do kernel (`1000baseT/Full`) ou do RouterOS 7.12+ (`1G-baseT-full`, `10G-baseSR-LR`) |
| `rx_flow_control`, `tx_flow_control` | `off`, `on`, `auto` | `auto` = resolvido com o parceiro (pause autoneg) |
| `offloads` | `gro:off,tso:on` ou `{"rx-gro": false}` | nome curto (`GRO`, `TSO`, `LRO`…) ou a feature do kernel |
| `reset` | `true` | esquece tudo: a porta volta ao que era antes do CoreRouter mexer |
| `force` | `true` | ver "porta de gerência"; também liga LRO |

Regras, todas checadas **antes** de aplicar, contra o que a própria porta diz (`supported` do
monitor, offloads do `interface.hardware`):

- Modo que a porta não suporta é recusado dizendo o que ela suporta
  (`this port does not support 10G-baseSR-LR (it can do 10baseT/Half, …)`).
- `speed`/`duplex` com autonegociação ligada é recusado: "adicione `auto_negotiation=false`, ou
  mantenha a autonegociação e limite o que ela oferece com `advertise`" (o RouterOS guarda e ignora
  em silêncio; aqui o operador sabe).
- 1 Gb/s ou mais em par trançado forçado é recusado: o IEEE 802.3 (cl. 40/55) exige
  autonegociação no BASE-T a partir de 1G (o link não sobe); a mensagem sugere
  `advertise=1000baseT/Full`. 1000BASE-X/SFP pode ser forçado.
- Offload `fixed` pelo driver é recusado; LRO ligado só com `force` (LRO junta pacotes recebidos e
  quebra encaminhamento e bridge; o próprio Linux o desliga em portas que encaminham).
- Driver sem leitura de link (`available: false`) recusa a mudança de link com o motivo; sem pause
  frames, recusa o controle de fluxo.

Na config: os valores ficam em `interfaces.<nome>.ethernet` (só o que foi definido; ausente = o
padrão do driver), então entram no journal, no histórico, no `config.diff`, no
`config.rollback`, no Safe Mode e no armazenamento (G0.6). O monitor mostra `configured` com o que
está definido.

### Porta de gerência e Safe Mode

Mudar autonegociação, velocidade, duplex ou modos anunciados derruba o link por um instante, e um
desencontro com o outro lado o deixa caído — junto com o único caminho de volta. Por isso, numa
conexão remota (canal de controle/TLS/WebSocket; não a GUI local nem o terminal local), a porta por
onde o cliente chega é detectada: as portas físicas sob os endereços cuja sub-rede contém o IP do
cliente (passando por VLAN, bridge e VRF); se nenhuma contém (conexão roteada), todas as portas com
endereço. Nessa porta, fora do Safe Mode, a mudança é recusada:

```
parameter 'name': 'ether1' carries this connection (from 10.0.0.9): changing its speed, duplex or
auto-negotiation drops the link for a moment, and a mismatch keeps it down. Enter Safe Mode first
(config.safe-mode.enter) so that losing the connection undoes it, or pass force=yes
```

Em Safe Mode passa (com aviso), e se a conexão cair o G1.4 desfaz tudo. O teste de cabo segue a
mesma regra (o link cai durante o teste). Offloads e controle de fluxo não renegociam o link e não
pedem nada.

### Como o Linux aplica (`hal-linux`)

`apply` escreve por ethtool netlink (`LINKMODES_SET`, `PAUSE_SET`, `FEATURES_SET`), antes do plano
rtnetlink; se algo falha, as portas já mexidas voltam (tudo ou nada, como o resto do `apply`). Na
primeira mudança de uma porta, o estado dela é guardado (autoneg, modos anunciados, velocidade,
pause, features); um valor que sai da config volta ao guardado (`ether::target`, puro e testado).
Só os bits de velocidade do `advertise` mudam (máscara), `Pause`/`Asym_Pause`/`Autoneg` ficam como
estão. Depois de `FEATURES_SET` o estado é relido: feature que o driver manteve (dependências) vira
erro com o nome.

## SFP / SFP+ / QSFP (G1.20)

`interface.ethernet.monitor` ganha `sfp`: `null` com `sfp_reason` numa porta sem gaiola (cobre) ou
driver sem acesso ao EEPROM; `module_present: false` numa gaiola vazia; e com módulo:

- identidade: `kind` (`SFP/SFP+/SFP28`, `QSFP+`, `QSFP28`…), `spec` (`SFF-8472`/`SFF-8636`),
  `connector`, `compliance` (`10GBASE-SR`, `1000BASE-LX`, `100GBASE-LR4`…), `cable` (DAC/AOC),
  `nominal_rate_mbd`, fabricante/OUI/PN/revisão/serial, `manufacturing_date`, `wavelength_nm`,
  `link_length` por meio (`smf`, `om1`…`om4`, `cable`), `rx_loss`, `tx_fault`, `checksum_ok`;
- DOM: `dom: [{name, lane, value, unit, limits, level}]` — temperatura (°C), tensão (V), corrente
  de bias (mA), potência TX/RX (dBm, piso -40 = sem luz), por lane num QSFP; `limits` são os
  limites de alarme/aviso **do próprio módulo** (A2h bytes 0–39 no SFF-8472, página 03h no
  SFF-8636); `level` = `ok`, `low-warning`, `high-warning`, `low-alarm`, `high-alarm`;
- `alerts`: as leituras fora da faixa, em texto (`rx-power -16.00 dBm (low-alarm)`).

O decodificador (`hal::sff`) é código puro: calibração interna e externa (SFF-8472 §9), checksum
base/estendido, proptest com bytes hostis e testes com **dumps reais publicados** (Finisar
FTLF8524P2BNV SFP com DOM, QSFP28 AOC com página 03h, DAC passivo SFP+, QSFP28 LR4 da lista netdev;
fontes no cabeçalho de `crates/hal/tests/sff/*.hex`). Módulos CMIS (QSFP-DD, OSFP) são só nomeados.
No Linux o EEPROM vem de `MODULE_EEPROM_GET` (página 0 de 0x50, depois A2h em 0x51 ou a página 3).

Alertas: o engine (`dom_watch`) lê os módulos a cada `interface.ethernet.monitor` e a cada 30 s no
`tick`, e registra no log **só a travessia** (aviso/alarme ao cruzar, "back to normal" ao voltar,
módulo inserido/removido) — não a cada leitura. Porta desabilitada tem o laser desligado de
propósito: TX não alerta. Na GUI, a aba SFP colore a leitura (âmbar aviso, vermelho alarme), mostra
os alertas no topo e o rótulo da aba vira `SFP ⚠`.

## Teste de cabo (G1.20)

`interface.ethernet.cable-test {name, force?}` (`/interface ethernet cable-test ether1` no terminal)
é uma tarefa (G6.1): devolve o id e o resultado vem por `tool.task.poll` — um evento por par
`{pair: A..D, status, distance_m}` e o resumo com `cable_pairs` no formato do RouterOS
(`ok,ok,short:23.5,ok`). `status`: `ok`, `open`, `short`, `cross-short`, `impedance-mismatch`,
`noise`, `unknown`; `distance_m` só quando o PHY mede (um par aberto no fim dá o comprimento do
cabo). No Linux: `CABLE_TEST_ACT` e a notificação `CABLE_TEST_NTF` do grupo multicast `monitor`;
PHY que não faz → a tarefa falha com `not supported: …` (veth, a maioria dos NICs PCIe com firmware
próprio). O link cai durante o teste.

## Lab virtual (G1.20)

`ether8` (a última porta) é uma gaiola SFP+ com um módulo 10GBASE-SR "CoreRouter Lab
CR-SFP10G-SR" (EEPROM SFF-8472 gerado e decodificado pelo mesmo `hal::sff`), modos `1000baseX/Full`
e `10000baseSR/Full`; as outras são cobre 1G. O monitor reflete o que `interface.ethernet.set`
aplicou (velocidade forçada, modos anunciados — o parceiro aceita tudo e o melhor modo anunciado
vence —, controle de fluxo, offloads). Teste de cabo: portas ok; `ether7` com o par C em curto a
23,5 m; porta desabilitada com os pares abertos no comprimento do cabo; `ether8` "não suportado"
(fibra).

## Fora (vira gap se pedirem)

- Piscar o LED (`ETHTOOL_PHYS_ID`) e a versão de firmware sem devlink: só por ioctl (`unsafe`).
- `/export` das configurações de `/interface ethernet` (ficam salvas na config; o `/export` lê
  menus com `print`).
- FEC (`fec-mode`), `sfp-rate-select`, `sfp-shutdown-temperature` e a política de potência do
  módulo (`MODULE_SET`); TDR bruto (`CABLE_TEST_TDR_ACT`).

## Histórico de revisão

- 2026-10-22 — criado (G1.19).
- 2026-10-22 — G1.20: Ethernet configurável, SFP/DOM, teste de cabo.
