# Vizinhos ARP/ND (`/ip arp`, `/ipv6 neighbor`) — G1.27d

A tabela de vizinhos é o que o roteador sabe dos hosts ligados a ele: IP → MAC, com o estado da
resolução. O CoreRouter a lê do kernel em Rust puro, a mantém por eventos (sem polling) e a
mostra paginada, com busca, contagens e alertas. Os nomes seguem o RouterOS v7.

## O que existe

| Comando | O que faz |
|---|---|
| `ip.arp.list`, `ipv6.neighbor.list` | Página da tabela (`offset`, `limit` até 5000), busca por IP, CIDR, prefixo de MAC (`00:50:56`) ou texto; filtros `interface`, `state`, `source`; contagens da tabela inteira por estado, interface e origem; uso da tabela do kernel × `gc_thresh3` |
| `ip.arp.add`, `set`, `remove` | Entrada estática (`address`, `mac_address`, `interface`, `published`, `disabled`, `comment`), com journal e rollback |
| `ip.arp.make-static` | O MAC aprendido de um vizinho vira entrada estática |
| `ip.arp.flush`, `ipv6.neighbor.flush` | Apaga as entradas aprendidas (de uma interface, de um estado); **nunca** o gateway de uma rota ativa nem o vizinho da conexão de gerência (lista os que ficaram e por quê) |
| `ip.arp.ping` | ARP ping (tarefa, como `tool.ping`): alcançabilidade de um host que descarta ICMP |
| `ip.arp.settings.print`, `ip.arp.settings.set` | Modo `arp` por interface (`enabled`, `disabled`, `reply-only`, `proxy-arp`, `local-proxy-arp`) e `arp_timeout` (`auto` ou segundos); limites do kernel |
| `ip.route.list` / `ip.route.page` / `ip.route.detail` | `gateway_status = incomplete` quando o gateway não resolve na camada 2 |

Estados (RFC 4861 §7.3.2; o Linux usa os mesmos para ARP): `incomplete`, `reachable`, `stale`,
`delay`, `probe`, `failed`, `permanent`, `noarp`. Flags como no RouterOS: X disabled, I invalid,
D dynamic, P published, C complete.

Os limites da tabela (`gc_thresh1/2/3`) já são parâmetros de `system.tuning` (G1.26) e não se
repetem: a aba Settings mostra e edita os mesmos. Passando de 80 % do `gc_thresh3`, o log
(`arp`, `warning`) avisa uma vez e sugere valores (t3 = 2 × entradas, em potência de 2).

Alertas no estilo arpwatch, no log com tópico `arp`: um endereço que responde de outro MAC
("changed ethernet address") e que volta ao MAC anterior ("flip flop": dois hosts disputam o IP,
IP duplicado ou ARP spoofing). No máximo 20 linhas por segundo; o resto vira uma linha de contagem.

## Como funciona

- **Leitura (`hal-linux/src/neigh.rs`):** socket rtnetlink síncrono, sem o crate `rtnetlink` nem
  tokio. Um dump `RTM_GETNEIGH` das duas famílias; mensagens decodificadas no lugar, com
  proptest contra bytes hostis. Dump marcado como interrompido (`NLM_F_DUMP_INTR`) é relido.
- **Eventos:** um socket no grupo `RTNLGRP_NEIGH` recebe cada `RTM_NEWNEIGH`/`RTM_DELNEIGH`. O
  serviço `neighbors` do daemon (thread própria, sob o supervisor) aplica os eventos na tabela do
  motor (`engine/src/neigh_table.rs`), que tem trava própria: **o lock do `Session` nunca é
  pego por evento**. `ENOBUFS` (o leitor ficou para trás) é contado e dispara um dump novo.
- **Tabela do motor:** `Vec<Row>` compacto + `HashMap<(interface, IP), índice>`; inserir,
  atualizar e remover são O(1) (remoção por `swap_remove`). A página ordena só o pedaço pedido
  (`select_nth_unstable` + sort da página).
- **Sem o daemon** (lab no navegador, `corerouter-cli run`, testes): a lista lê o backend uma vez
  por consulta.
- **Aplicação (`apply`):** entradas estáticas por `RTM_NEWNEIGH` `NUD_PERMANENT` (e `NTF_PROXY`
  para `published`), desfeitas se o resto do commit falhar. Modos:
  - `disabled`: `IFF_NOARP` no link;
  - `proxy-arp`: `conf/<if>/proxy_arp=1` (RFC 1027);
  - `local-proxy-arp`: `conf/<if>/proxy_arp_pvlan=1`;
  - `reply-only`: `ucast/mcast/app_solicit=0` (o kernel nunca resolve um endereço sem entrada
    estática; vai direto a `failed`) e o serviço apaga, por evento, o que o kernel aprender na
    porta a partir de requests dirigidos a nós. O Linux não tem esse modo pronto; a pesquisa
    não achou receita de terceiros.
  - `arp_timeout`: `neigh/<if>/base_reachable_time_ms`.
  Cada parâmetro guarda o valor original do kernel e volta a ele quando o modo volta ao padrão.
- **Segurança por padrão:** `disabled`, `reply-only` e `proxy-arp` pedem `confirm=true`;
  `disabled`/`reply-only` na porta por onde vem a gerência (ou o gateway de uma rota ativa) sem
  entrada estática para ele é recusado como lockout (Safe Mode ou `force=true` liberam).
- **Laboratório virtual (`hal/src/lab_neigh.rs`):** cada sub-rede do roteador tem hosts 1–12 e
  254 que respondem; um gateway fora disso fica `incomplete`. Os estados envelhecem
  (reachable → stale → delay → probe → reachable).

## Pesquisa

Notas completas com URL por afirmação: pasta de notas da sessão principal,
`G1.27d-research.md`.

- **MikroTik RouterOS v7** ([/ip arp](https://help.mikrotik.com/docs/spaces/ROS/pages/100892687/ARP),
  [CLI ip/arp](http://manual.mikrotik.com/docs/cli-reference/ip/arp/),
  [ipv6/neighbor](http://manual.mikrotik.com/docs/cli-reference/ipv6/neighbor/),
  [ip/settings](http://manual.mikrotik.com/docs/cli-reference/ip/settings/),
  [dhcp-server](http://manual.mikrotik.com/docs/cli-reference/ip/dhcp-server/)): propriedades
  `address`, `mac-address`, `interface`, `published` (padrão `no`); status `delay`, `failed`,
  `incomplete`, `permanent`, `probe`, `reachable`, `stale`; flags X I H D P C; modo `arp` da
  interface com cinco valores (padrão `enabled`); `arp-timeout` = `base_reachable_time`
  (validade sorteada entre metade e 1,5×); `max-neighbor-entries` = `gc_thresh3` (2048 a 16384
  pela RAM); `add-arp` do servidor DHCP (padrão `no`, flag H). `make-static` e `flush` não estão
  documentados (existem no WinBox); adotamos os dois.
- **Cisco IOS:** `show ip arp`, `clear arp-cache`; `arp timeout` padrão 4 h
  ([Cisco](https://www.cisco.com/c/de_de/support/docs/ip/address-resolution-protocol-arp/117398-qanda-arp-timeout-00.html));
  Dynamic ARP Inspection confere IP+MAC contra o DHCP snooping (ideia para o `add-arp` +
  `reply-only`, parte (c)).
- **Juniper Junos:** `aging-timer` padrão 20 min
  ([Junos](https://www.juniper.net/documentation/us/en/software/junos/multicast-l2/topics/task/configuring-arp-aging-timer.html)).
- **OPNsense / pfSense** ([OPNsense](https://docs.opnsense.org/manual/diagnostics_interfaces.html),
  [pfSense](https://docs.netgate.com/pfsense/en/latest/monitoring/arp-table.html)): colunas de
  fabricante (OUI) e hostname (lease DHCP, depois DNS reverso) — adotado na janela (parte b).
- **arpwatch** ([man](https://www.mankier.com/8/arpwatch)): new station, changed ethernet
  address, flip flop, reused old ethernet address, bogon. Adotamos changed e flip flop.
- **RFCs:**
  - [RFC 826](https://www.rfc-editor.org/rfc/rfc826) (ARP): campos remetente/alvo do
    request do ARP ping.
  - [RFC 5227](https://www.rfc-editor.org/rfc/rfc5227) §2.1.1, §2.4: sondagem (já em
    `ip.address.add`) e defesa; o alerta de flip flop cobre o aviso ao administrador do §2.4(c).
  - [RFC 1027](https://www.rfc-editor.org/rfc/rfc1027): proxy ARP (`proxy-arp`), por isso pede
    confirmação (puxa tráfego do segmento).
  - [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861) §7.3.2 (estados), §10 (REACHABLE_TIME
    30 s, RETRANS_TIMER 1 s, DELAY_FIRST_PROBE_TIME 5 s, MAX_*_SOLICIT 3);
    [errata](https://www.rfc-editor.org/errata/rfc4861): 2709 (Verified) e 2797 (Held) tocam o
    NUD, sem efeito na leitura.
  - [RFC 7048](https://www.rfc-editor.org/rfc/rfc7048): UNREACHABLE com backoff; o Linux expõe
    como `failed`.
  - [RFC 9131](https://www.rfc-editor.org/rfc/rfc9131): roteador cria STALE com NA não
    solicitado (Linux `accept_untracked_na`, padrão 0); não mexemos.
  - [RFC 6583](https://www.rfc-editor.org/rfc/rfc6583) §6, §7: exaustão da tabela ND por
    varredura; daí o alerta de 80 % do `gc_thresh3` com sugestão.
- **Kernel:** [ip-sysctl](https://docs.kernel.org/networking/ip-sysctl.html) (`gc_thresh`
  128/512/1024, `proxy_arp`, `proxy_arp_pvlan`, `*_solicit`, `base_reachable_time_ms`).

**O que ficou para depois:** a janela IP › Neighbors e os extras de tela (parte b), o
fabricante pelo OUI (aguarda decisão de licença do usuário) e o `add-arp` do DHCP (parte c).

## Desempenho e paralelismo

Ver `docs/changes/G1.27d-a.md` (§ perf). Resumo: um evento custa ~110 ns na tabela (O(1)); uma
página de 100 mil vizinhos sai em poucos ms; o dump do kernel é serial (o kernel percorre a
tabela num socket só, em ordem), então uma thread basta: dividir o dump ou os eventos só
acrescentaria lock.
