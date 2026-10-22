# Interfaces: estado, hardware e contadores

O diálogo "Interface <nome>" da GUI tem as abas do WinBox: **General**, **Status**,
**Hardware**, **Traffic** e **Statistics** (G1.19). Só a General edita (MTU, comentário,
Disabled, como no G1.9); as outras leem três comandos de consulta do engine, que valem também
no terminal, na CLI e no MCP.

A semântica segue o RouterOS (`/interface ethernet monitor`, `/interface ethernet print stats`,
`link-downs` / `last-link-up-time` de `/interface print detail`); os nomes de campo seguem o
padrão do CoreRouter (`snake_case` no JSON, `kebab-case` no terminal).

## Comandos

| Comando | O que devolve | Terminal |
|---|---|---|
| `interface.ethernet.monitor {name}` | Estado ao vivo: `status` (`link-ok`/`no-link`), `rate` (`1Gbps`), `full_duplex`, `auto_negotiation` (`done`/`incomplete`/`disabled`), `port`, `mdix`, modos suportados/anunciados/do outro lado, controle de fluxo, `link_downs`, `carrier_changes`, `down_reason`, `last_link_up_time`/`last_link_down_time` | `/interface ethernet monitor ether1` |
| `interface.hardware {name}` | A placa: fabricante/modelo (ids PCI e nomes), driver, versão, firmware, serial, barramento, NUMA, filas, canais, IRQs, rings, offloads, MAC atual e de fábrica, faixa de MTU | `/interface hardware ether1` |
| `interface.stats {name}` | Contadores por grupo: `interface` (stats64 do kernel) e, quando o driver preenche, `eth-phy`, `eth-mac`, `eth-ctrl`, `rmon` (com histograma por tamanho) e `pause` | `/interface stats ether1` |

Regras comuns:

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

## Próximo (G1.20)

Configurar Ethernet (autonegociação, velocidade, duplex, controle de fluxo, modos anunciados,
offloads via ethtool, com Safe Mode), módulos SFP com leituras DOM e alertas de limite, e teste
de cabo. Veja `docs/gaps.md`.

## Histórico de revisão

- 2026-10-22 — criado (G1.19).
