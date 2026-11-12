# WireGuard (G1.31)

Interfaces WireGuard com os nomes e padrões do RouterOS v7.25 (`/interface wireguard` e
`/interface wireguard peers`). O caminho de dados é o WireGuard do kernel; a config e o estado
são nossos, em Rust, por generic netlink (decisão e números em `docs/architecture.md`).

Partes:

- **PR 1 (este):** modelo, comandos, chaves, push para o kernel, estado por par, testes.
- **PR 2:** janela Interfaces › WireGuard (abas Interfaces e Peers, modais).
- **PR 3:** config do cliente com QR, `wg-import`/`wg-export`, saúde "sem handshake", endpoint
  por nome DNS, checagem de firewall, Safe Mode na `wg` de gerência, e a opção de criar rotas
  estáticas para os allowed addresses no modal do par.

## Comandos

| Comando | O que faz |
|---|---|
| `interface.wireguard.add {name?, listen_port?, mtu?, private_key?, disabled?, comment?}` | Cria a interface. Nome padrão `wireguard1`, porta 13231 (ou a primeira livre acima), MTU 1420, chave privada gerada no roteador e selada. Devolve a chave pública. |
| `interface.wireguard.set {name, listen_port?, mtu?, private_key?, …}` | `private_key=auto` faz um par novo: todos os pares precisam da pública nova (aviso). |
| `interface.wireguard.remove/enable/disable {name}` | `remove` leva os pares junto. |
| `interface.wireguard.list {show_sensitive?}` | Porta, MTU, chave pública, `running`, pares e pares `up`, erro do último push. A privada só com `show_sensitive` (grupo `full`). |
| `interface.wireguard.peers.add {interface, name?, public_key? \| private_key?, preshared_key?, endpoint_address?, endpoint_port?, allowed_address, persistent_keepalive?, responder?, …}` | Nome padrão `peerN`, único no roteador. `private_key=auto` gera o par de chaves do cliente (para a config do cliente, PR 3). `preshared_key=auto` gera a PSK. |
| `interface.wireguard.peers.set {name, new_name?, …}` | Mesmos campos; `endpoint_address=""` volta a esperar o par. |
| `interface.wireguard.peers.remove/enable/disable {name}` | |
| `interface.wireguard.peers.list {interface?, show_sensitive?}` | Estado (`up`, `idle`, `no-handshake`, `never`, `disabled`), segundos desde o último handshake, rx/tx, endpoint atual e `roamed`, e uma dica quando não há handshake. |

Como interface comum, uma `wg` também aceita `interface.set` (renomear, MTU), `ip.address.add`,
rotas, firewall e interface lists.

```sh
corerouter-cli run interface.wireguard.add '{"name":"wg0"}'
corerouter-cli run ip.address.add '{"address":"10.9.0.1/24","interface":"wg0"}'
corerouter-cli run interface.wireguard.peers.add '{"interface":"wg0","name":"notebook","public_key":"<chave do cliente>","allowed_address":"10.9.0.2/32"}'
corerouter-cli run interface.wireguard.peers.list
```

## Validações (mais fortes que os avisos do RouterOS)

O kernel esconde três erros; o engine os recusa antes do commit:

- **o mesmo prefixo em dois pares da mesma interface:** o kernel o passa em silêncio para o último
  par configurado (`drivers/net/wireguard/allowedips.c`, `add()`), e o primeiro deixa de recebê-lo.
  O RouterOS só avisa desde a 7.24;
- **par com a chave pública da própria interface:** o kernel o ignora em silêncio (`netlink.c`,
  `set_peer`);
- **a mesma chave pública duas vezes numa interface.**

Também:

- a porta de outra interface WireGuard é recusada (o kernel recusaria o `bind`, `EADDRINUSE`);
  porta de serviço do roteador (DNS, NTP, DHCP, RADIUS, IPsec) gera aviso;
- `allowed_address` é obrigatório, normalizado para a rede (`10.20.1.0/16` vira `10.20.0.0/16`,
  com aviso, como o kernel guarda);
- `endpoint_address` e `endpoint_port` vão juntos;
- avisos: `0.0.0.0/0` num par que divide a interface com outros; endpoint dentro do próprio
  allowed address (laço se uma rota mandar o endpoint para dentro do túnel).

`allowed_address` não cria rota, como no RouterOS, no VyOS e no pfSense.

## Estado de um par

Regra única no engine (`corerouter_model::wireguard::PeerState`), pelos timers do protocolo
(whitepaper §6.1, `drivers/net/wireguard/messages.h`):

| Estado | Quando |
|---|---|
| `up` | último handshake há ≤ 180 s (`REJECT_AFTER_TIME`) |
| `idle` | handshake mais velho e nada pede outro: par sem keepalive sem tráfego (normal) |
| `no-handshake` | o roteador tenta (endpoint e keepalive, ou tráfego para enviar) e não há resposta |
| `never` | nunca houve handshake e o roteador só espera (sem endpoint, ou `responder`) |
| `disabled` | par ou interface desativados |

## Como chega ao kernel

1. `Hal::apply` cria e apaga o link `wireguard` como qualquer outro (`LinkSpec::Wireguard`). As
   chaves e os pares não fazem parte do spec: mudar um par nunca recria o link.
2. Depois do commit, o engine abre as chaves seladas e chama `Hal::wireguard_set` para cada
   interface cujo estado desejado mudou (`crate::wireguard`). O relógio de serviço tenta de novo
   o que falhou e, a cada 30 s, compara com o que o link tem (um link recriado, um par apagado com
   `wg`).
3. O `hal-linux` lê o link (`WG_CMD_GET_DEVICE`, juntando um par que continua na mensagem
   seguinte) e manda só a diferença (`WG_CMD_SET_DEVICE`), em blocos de até 32 KiB.
   - Nunca usa `WGDEVICE_F_REPLACE_PEERS`, que derrubaria todas as sessões.
   - O endpoint só vai quando o par é novo ou quando o *configurado* mudou: o kernel segue o par
     que muda de IP (roaming), e o roteador não o puxa de volta.
4. A chave privada nunca aparece em log: o `Debug` de `WgDevice` a esconde, e o buffer da
   requisição é zerado depois do envio.

## Desempenho e paralelismo

- **Por item:** aplicar é O(pares que mudaram), não O(total). Ler o estado é um dump por
  interface: 5 ms com 1 000 pares e 63 ms com 50 000 (**medido**, VM do laboratório). Cada
  `peers.list` faz um dump por interface; com dezenas de milhares de pares isso pesa, e um cache
  por tick fica para quando houver medição na GUI (PR 2).
- **Núcleos:** a cifra é do kernel, que espalha os lotes por todos os núcleos online (decifra em
  paralelo e entrega em ordem por par). No caminho de dados não há trabalho nosso.
- **Plano de controle:** o push roda sob o lock da sessão, como o resto do commit. Uma mudança de
  par custa 3–6 ms (**medido**). Criar milhares de pares de uma vez cresce mais que linear no
  kernel (10 000 em 0,7 s, 50 000 em 11,7 s, **medido**). O perfil mostra IPI, provavelmente a
  alocação por CPU do `dst_cache_init` de cada par. Daí o teto de 20 000 pares por interface.

## Medição: kernel × espaço de usuário (2026-11-12)

Bare metal: o host de desenvolvimento (AMD Ryzen AI Max+ 395, Zen 5, 32 threads, kernel 7.0),
dentro de `unshare -Urnmp`, sem root. Quatro namespaces: cliente → roteador A → túnel →
roteador B → servidor. `iperf3` 3.16, 10 s por teste, mediana de 2. **Medido.**

| Teste | sem túnel | kernel | BoringTun 0.7.1 | wireguard-go 0.0.20250522 |
|---|---|---|---|---|
| TCP, 1 fluxo | 94,9 Gb/s | 7,3 Gb/s | 2,6 Gb/s | 16,8 Gb/s |
| TCP, 4 fluxos | 330 Gb/s | 7,1 Gb/s | 2,6 Gb/s | 10,7 Gb/s |
| UDP 64 B, 4 fluxos | 1 958 kpps | 631 kpps | 389 kpps | 338 kpps |
| UDP 1400 B, 1 fluxo | 6,2 Gb/s | 4,9 Gb/s, 444 kpps, 2 % perda | 4,5 Gb/s, 410 kpps, 55 % | 3,5 Gb/s, 316 kpps, 63 % |
| UDP 1400 B, 4 fluxos | 21 Gb/s | 6,7 Gb/s, 607 kpps | 3,4 Gb/s, 312 kpps | 3,5 Gb/s, 315 kpps |
| ping com 4 fluxos TCP | 0,012 ms | 13,5 ms | 0,30 ms | 9,8 ms |

Na VM do laboratório (8 vCPUs, kernel 7.0) o kernel cai para 1,5 Gb/s em TCP, contra 9,1 Gb/s
do wireguard-go. O perfil mostra:

- IPI (`asm_sysvec_call_function_single`, 4,8 %), lock e escalonador no topo;
- a cifra em AVX-512 (`chacha_8block_xor_avx512vl`, `poly1305_blocks_avx512`) com ~5 %;
- com os vCPUs presos acordados, nada mudou.

A causa é o despacho em rodízio por núcleo (`queueing.h`, `queue_work_on` no próximo núcleo
online): cada IPI sai para o hipervisor.

Os scripts ficaram fora do repositório (pasta de notas da sessão): `wg-host.sh` (bare metal),
`wg-bench.sh` e `wg-prof.sh` (VM).

## Pesquisa

**MikroTik RouterOS 7.25** (manual.mikrotik.com/docs/7.25, `virtual-private-networks/wireguard` e
`cli-reference/interface/wireguard`; o help.mikrotik.com antigo está congelado):

- interface: `listen-port` 13231 (única por interface desde 7.14), `mtu` 1420, `private-key`
  gerada (`auto`/`none` desde 7.12), `public-key` só leitura, `vrf` do socket cifrado (7.21);
- par: `public-key` ou `private-key=auto`, `preshared-key`, `endpoint-address/port` (IP ou nome),
  `allowed-address`, `persistent-keepalive`, `responder` e `name` (7.15), `client-*` e
  `show-client-config` com QR (7.12; QR sensível desde 7.21);
- estado: `last-handshake`, `rx`, `tx`, `current-endpoint-*` (roaming);
- `allowed-address` não cria rota; sobreposição só gera aviso (7.24+); refaz a consulta DNS do
  endpoint (7.10/7.11), sem parâmetro.

**Outros:**

- **VyOS:** valida no commit (chave duplicada, chave igual à da interface, porta), gera config de
  cliente com QR e refaz a consulta DNS quando o handshake passa de 360 s.
- **OPNsense:** cria rotas por padrão ("Disable routes"); o gerador de par escolhe o próximo IP e
  não guarda a privada.
- **pfSense:** refaz a consulta DNS a cada 300 s.
- **OpenWrt:** `route_allowed_ips` com rota de host para o endpoint; aplica com `wg syncconf` sem
  derrubar sessões; o `wireguard_watchdog` refaz a consulta DNS acima de 180 s.

**Protocolo:**

- Whitepaper (wireguard.com/papers/wireguard.pdf): §5.2 PSK; §5.4.6 overhead de 32 B por pacote,
  60/80 B com UDP e IP, daí 1420; §6.1 timers (REKEY_AFTER_TIME 120 s, REJECT_AFTER_TIME 180 s,
  REKEY_TIMEOUT 5 s, KEEPALIVE_TIMEOUT 10 s); §2.1 roaming.
- Não há `docs.kernel.org/networking/wireguard`. O contrato é `include/uapi/linux/wireguard.h`
  (e a especificação YNL do genetlink).

**Kernel 6.18.59** (o da imagem):

- `netlink.c`: `SET_DEVICE` incremental; a porta reabre o socket e falha antes do resto; a chave
  privada nova expira as sessões de todos os pares.
- `allowedips.c`: o prefixo repetido passa para o último par.
- `socket.c`: o pacote cifrado sai pela tabela principal com `fwmark`, sem `oif`.

**O que adotamos:**

- nomes e padrões do RouterOS;
- validação no estilo do VyOS, recusando o que o kernel esconderia;
- aplicação incremental do OpenWrt;
- estado do par pronto (nenhum dos outros o calcula).

**O que fica para depois** (gaps no `docs/changes/G1.31.md`):

- rota automática opcional;
- VRF do socket cifrado;
- clamp de MSS;
- fila na `wg`;
- medição em VM;
- PSK rotativa pós-quântica (Rosenpass).
