# Cliente PPPoE (`/interface pppoe-client`, G3.9ga)

O CoreRouter disca para o servidor PPPoE de um provedor e usa a sessão como WAN, como o
`/interface pppoe-client` do RouterOS v7. O BNG (servidor) está em `docs/pppoe.md`; esta página
trata do lado do cliente.

## 1. Como funciona

| Camada | Onde | O que faz |
|---|---|---|
| Protocolo | `crates/proto-pppoe/src/client.rs` | `Client` sans-IO: Discovery como Host (RFC 2516 §5), LCP, PAP/CHAP/MS-CHAP, IPCP/IPv6CP, keepalive por eco |
| Modelo | `crates/model/src/pppoe_client.rs` | `InterfaceKind::PppoeClient`, tipo `pppoe-out`, com as configurações e os padrões do RouterOS |
| Comandos | `crates/engine/src/cmd/pppoe_client.rs` | `interface.pppoe-client.{add,set,remove,enable,disable,reconnect,list,monitor,history,check}` |
| Execução | `crates/engine/src/pppoe_client.rs` | um `Client` por cliente ativo, no relógio do DHCP client (`dhcp_service`); endereço, rota até o BNG, rota padrão e DNS como entradas dinâmicas (`D`) via `Session::effective` |
| Transporte | `crates/hal/src/pppoe_client.rs` | `PppoeClientPort` (quadros de controle e relé da sessão); `SimPppoePort` e o BNG simulado do laboratório (`LabBng`) |
| Plano de dados | `crates/hal-linux/src/pppoe_client_io.rs` | par veth `pppoe-out1` ↔ `pppoe-out1-r` e o relé `AF_PACKET`, com uma thread por sentido |

- **A interface é uma veth.** O `apply` cria `pppoe-out1`, que é o lado que o kernel roteia e
  que o firewall nomeia, e o par oculto `pppoe-out1-r` (`LinkSpec::PppoeOut`, sem ARP). A
  posse (G1.18) classifica o par como "relay end of PPPoE client 'pppoe-out1'", então ele
  nunca entra como porta.
- **O relé.** O que o kernel manda por `pppoe-out1` chega ao par. O relé põe os cabeçalhos
  PPPoE e PPP (RFC 2516 §4: VER/TYPE 0x11, CODE 0) e manda pela porta Ethernet. Os dados da
  sessão que o BNG manda vão no sentido contrário: são escritos no par, e o kernel os recebe
  em `pppoe-out1` como qualquer pacote recebido (prerouting, conntrack e `in-interface` veem).
- **Controle.** Discovery, LCP, autenticação e NCP vão ao engine por uma fila limitada (256
  quadros; o excedente é descartado e contado). O engine manda os quadros dele por um socket
  clonado.
- **Fora da sessão.** Dados de outra sessão (uma sessão órfã) são descartados.

## 2. Comportamento

- **Padrões do RouterOS v7:**
  - `add-default-route=no`, `default-route-distance=1`;
  - `use-peer-dns=no`, `profile=default`;
  - `max-mtu`/`max-mru` = 1460, `keepalive-timeout=60`, `allow=mschap2,mschap1,chap,pap`;
  - `max-mtu` acima de 1492 pede o RFC 4638 (PPP-Max-Payload).
- **Keepalive.** Um eco a cada `keepalive-timeout/3`; três sem resposta derrubam o enlace.
- **Rediscagem com espera crescente.** Começa em 1 s e dobra até 60 s, com ±20 % de jitter;
  depois de falha de autenticação, espera no mínimo 30 s (como o `holdoff` do VyOS). Uma
  sessão que ficou de pé por um minuto zera a contagem. Assim, uma senha errada ou um BNG
  fora do ar não martelam o BNG do provedor.
- **PADT da sessão anterior (RFC 2516 §5.5).** Enquanto a sessão está de pé, o MAC do AC e o
  session-id ficam no estado `pppoe-client-sessions`. Na partida seguinte (reboot, queda do
  daemon), o cliente manda PADT para essa sessão antes do PADI: o BNG a libera na hora, em vez
  de esperar o keepalive dele. O pppd não faz isso.
- **Motivo da queda.** `last_down.reason` traz um código (`no-offer`, `service-error`,
  `ac-error`, `padt`, `lcp`, `auth-failed`, `ncp`, `keepalive`, `local`), que a GUI explica em
  português, e `last_down.message` traz as palavras do BNG. Do MS-CHAP (RFC 2759 §6) fica só a
  parte `M=`.
- **MSS clamp.** É feito no relé, em IPv4 e IPv6 (o RouterOS só faz IPv4), salvo
  `change-tcp-mss=no` no perfil. MSS = MTU − 40 (v4) ou − 60 (v6); o checksum é corrigido de
  forma incremental (RFC 1624).
- **Avisos no `add`/`set` e no `check` do modal:**
  - outra rota padrão (estática, DHCP client, outro PPPoE) na mesma distância, que dividiria o
    tráfego em ECMP;
  - nenhuma rota padrão;
  - MTU acima de 1492;
  - sem senha.
- **Senha.** É lacrada como a dos `/ppp secret` (`crate::sealing`). A `list` mostra `***`;
  `show_sensitive` (grupo full) mostra a senha em claro; o journal mascara.
- **IPv6.** Com `use-ipv6=yes` no perfil, o IPv6CP negocia o link-local. O prefixo vem de
  `ipv6.dhcp-client interface=pppoe-out1`, como no RouterOS. O PD automático pelo perfil virou
  gap (abaixo).

## 3. Pesquisa

- **MikroTik RouterOS v7.** Fontes:
  [help PPPoE](https://help.mikrotik.com/docs/spaces/ROS/pages/2031625/PPPoE),
  [CLI 7.25 pppoe-client](https://manual.mikrotik.com/docs/7.25/cli-reference/interface/pppoe-client/) e
  [PPP AAA](http://manual.mikrotik.com/docs/7.25/authentication-authorization-accounting/ppp-aaa/).
  - Nomes e padrões estão acima.
  - O `monitor` traz status, uptime, ac-name, ac-mac, mtu/mru e local/remote-address.
  - O `default-route-tables` não existe: a rota padrão vai sempre para a `main`.
  - O intervalo de reconexão não é documentado.
  - O 7.20 passou a ajustar o MSS no perfil `default`.
- **VyOS** (`interfaces pppoe`):
  - `holdoff` padrão de 30 s e `mru` 1492;
  - `default-route-distance`/`no-default-route`;
  - `adjust-mss clamp-mss-to-pmtu` em v4 e v6;
  - `reconnect interface` destacado da sessão CLI, que é seguro pela própria WAN.
- **OpenWrt** (`proto pppoe`):
  - `keepalive "5 1"` adaptativo e `mtu` 1492;
  - `ipv6 auto`, que sobe o DHCPv6 filho;
  - `persist` com `maxfail 0`, sem espera crescente.
- **Junos** (`pp0`): `underlying-interface` obrigatório, `auto-reconnect` 0 (imediato) e
  `idle-timeout`.
- **RFCs:**
  - **2516:**
    - exatamente um Service-Name no PADI;
    - Host-Uniq ecoado e AC-Cookie devolvido;
    - §5.5: depois de um PADT, nada de PPP;
    - §7: MRU ≤ 1492, sem ACFC/ACCM;
    - §8: PADI repetido dobrando a espera;
    - errata 5634 (sem NUL nas strings de erro), 7746, 4759–4761 e 5788.
  - **4638:** PPP-Max-Payload no PADI e no PADR.
  - **1661:** Restart 3 s, Max-Configure 10; eco só em Opened.
  - **1332 + 1877:** endereço e DNS pedidos com 0.0.0.0.
  - **5072:** IID estável, só link-local.
  - **7084/9096:** IPCP e IPv6CP independentes, IAID estável na reconexão PPP.
- **O que adotamos:**
  - os nomes e padrões do RouterOS;
  - o MSS clamp em v6, do VyOS;
  - o `holdoff` de 30 s depois de falha de autenticação, do VyOS;
  - o `reconnect` que roda no daemon;
  - o PADT da sessão anterior, que nenhum dos quatro faz.
- **Ficou de fora, com motivo:**
  - `dial-on-demand`, `mrru`/multilink e rota padrão numa tabela ou VRF (G3.9gc): pouco uso em
    WAN de provedor;
  - PD automático pelo perfil (G3.9gd): o caminho do RouterOS, DHCPv6 client sobre o
    pppoe-out, já funciona;
  - caminho rápido em XDP (G3.9gb): o relé de usuário dá conta de 1 Gbit/s misto.

## 4. Plano de dados: kernel `ppp` × TUN × veth (**medido**)

O protótipo descartável fica em `side-session-notes`, e o relé real no teste
`crates/hal-linux/tests/netns_pppoe_client.rs`.

**Protótipo**, VM `corerouter-lab` (8 vCPU, kernel 7.0, release, mediana de 3 rodadas,
2026-10-29), em pps, uma thread por sentido e um pacote por syscall:

| | saída 64 B | saída 1400 B | entrada 64 B | entrada 1400 B |
|---|---|---|---|---|
| kernel `ppp`+`pppoe` (`/dev/ppp`) | ≥ 0,95 M (limite do gerador) | ≥ 1,14 M | ≥ 0,80 M | 0,79 M |
| TUN + relé | 0,93 M | 0,55 M | 0,42 M | 0,71 M |
| veth + relé | 0,74 M | 0,60 M | 0,26 M | 0,37 M |

**O relé real** (`LinuxPppoeClientPort`), host Ryzen AI MAX+ 395, userns+netns, release, 3
rodadas, 2026-10-29:

| sentido | 64 B | 1400 B |
|---|---|---|
| kernel → fio | 1,13–1,18 Mpps (o gerador era o limite) | 1,07–1,14 Mpps (≈ 12,5 Gbit/s) |
| fio → kernel | 0,67–0,69 Mpps | 0,70–0,72 Mpps (≈ 7,9 Gbit/s) |

**Decisão: veth e o relé.**
- **Por que não o kernel `ppp`:** ele é o mais rápido, mas pede os ioctls `PPPIOCGCHAN`,
  `PPPIOCATTCHAN`, `PPPIOCNEWUNIT` e `PPPIOCCONNECT`, que são `unsafe` e proibidos fora do
  `dataplane-ebpf`. Orquestrar o `pppd` também não serve: perderíamos o `Client` próprio, com a
  espera crescente, o PADT órfão, o motivo da queda e o `monitor` estruturado.
- **Por que não o TUN:** pede o `TUNSETIFF` (dependência nova `tun-rs`) e a interface morre com
  o daemon.
- **O que a veth dá:**
  - é criada por netlink seguro;
  - mantém a interface (e as regras que a nomeiam) entre rediscagens e reinícios;
  - abre o caminho rápido em XDP (G3.9gb): no uplink, desencapsula e redireciona ao par; no
    par, encapsula e redireciona ao uplink.
- **Escala:** uma WAN de 1 Gbit/s com tráfego misto é ~100–300 kpps, e o relé dá conta com
  folga num núcleo por sentido.

## 5. Desempenho e paralelismo

- **Trabalho por item:**
  - por pacote: um `recvmsg` e um `send`, e no SYN o clamp em O(opções TCP);
  - por lote: a sessão é lida uma vez sob um `Mutex` (até 256 quadros), nunca por pacote.
  Nada cresce com o total de clientes ou de rotas.
- **Threads.** Duas por cliente, `pppoe-rx-<nome>` e `pppoe-tx-<nome>`, com `thread::Builder`
  nomeado e `poll` de 200 ms para ver o pedido de parada.
  - Vários clientes (várias WANs) dividem-se sozinhos, uma dupla de threads cada.
  - Num cliente só, a ordem dos pacotes de um fluxo precisa ser mantida e o gargalo é o socket
    único. Dividir por hash de fluxo exigiria `PACKET_FANOUT` no uplink e vários sockets no
    par; o ganho de ir além de ~0,7 Mpps na entrada vem antes do XDP (G3.9gb), que tira o
    usuário do caminho.
- **Engine.** O plano de controle roda no relógio de 250 ms, sob o lock do `Session`, com um
  orçamento de 64 quadros por cliente e por chamada. O envio é um `send` não bloqueante no
  socket clonado; o relé nunca toca o lock.
- **Tempo de subida.** No teste em namespace contra o BNG do CoreRouter, com MS-CHAPv2, a
  sessão sobe em 3,5–3,8 s depois do `add`. Isso inclui o commit, a criação da veth e o
  relógio de 250 ms (**medido**, debug).
