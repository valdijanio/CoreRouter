# IPv6 › ND: anúncio de roteador (G3.9ha)

O kernel do Linux nunca envia Router Advertisement (RA). Sem um emissor, um host ou um RouterOS
atrás do CoreRouter não faz SLAAC nem pega o gateway IPv6. Fora do BNG PPPoE, que anuncia a
cada sessão (`pppoe_bng6`), o CoreRouter não tinha emissor. Este documento descreve o
`/ipv6 nd` e o `/ipv6 nd prefix` (RouterOS v7) e o emissor do daemon.

## Como usar

```sh
corerouter-cli run ip.address.add '{"address":"2001:db8:5::1/64","interface":"ether2"}'
corerouter-cli run ipv6.nd.add '{"interface":"ether2"}'          # ou "all"
corerouter-cli run ipv6.nd.list                                    # entradas, interfaces, contadores
corerouter-cli run ipv6.nd.prefix.list                             # dinâmicos, estáticos, depreciados
corerouter-cli run ipv6.nd.prefix.add '{"prefix":"2001:db8:9::/64","interface":"ether2","autonomous":false}'
```

Na GUI, o caminho é IPv6 › ND, com as abas Interfaces e Prefixes no padrão de lista e modal
(G0.24); o modal mostra a pré-visualização do engine.

## Pesquisa

### MikroTik RouterOS v7

Fontes:
- [IPv6 Neighbor Discovery](https://help.mikrotik.com/docs/display/ROS/IPv6+Neighbor+Discovery)
- manual 7.25: [`/ipv6 nd`](https://manual.mikrotik.com/docs/7.25/cli-reference/ipv6/nd/) e
  `/ipv6 nd prefix`
- [IP Addressing](https://help.mikrotik.com/docs/display/ROS/IP+Addressing)
- [fórum, 7.23.2](https://forum.mikrotik.com/t/7-23-2-stable-is-released/271470/86)

**`/ipv6 nd`.** Parâmetros e padrões:

| Parâmetro | Padrão |
|---|---|
| `interface` | `all` cobre as interfaces em execução |
| `ra-interval` | 3m20s-10m |
| `ra-delay` | 3s |
| `ra-lifetime` | 30m |
| `ra-preference` | medium |
| `hop-limit`, `mtu`, `reachable-time`, `retransmit-interval` | não especificados |
| `managed-address-configuration`, `other-configuration` | no |
| `advertise-mac-address` | yes |
| `advertise-dns` | — (`dns` nas versões novas) |
| `pref64` | — |

**`/ipv6 nd prefix`.** `on-link` e `autonomous` valem yes; `valid-lifetime` 4w2d;
`preferred-lifetime` 1w. Um endereço com `advertise=yes` cria um prefixo dinâmico. Quando o
endereço muda ou sai, o prefixo velho vai 3 vezes com lifetime 0.

**Mudanças na 7.x:**
- A 7.23 passou a anunciar em toda interface com `advertise-dns`, mesmo sem prefixo, e houve
  queixas.
- A 7.24rc3 desfez isso para as entradas migradas, segundo um relato no fórum (não está no
  changelog).

### Outros

- **[VyOS `service router-advert`](https://docs.vyos.io/en/latest/configuration/service/router-advert.html)**
  usa o radvd por baixo:
  - prefixo curinga `::/64`;
  - `deprecate-prefix` e `decrement-lifetime`;
  - RA final com lifetime 0 ao sair (`no-remove-on-exit` desliga);
  - prefixo com valid de 30 d e preferred de 4 h.
- **[Junos `router-advertisement`](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/router-advertisement-edit-protocols.html)**:
  - `virtual-router-only`: o RA sai só do mestre VRRP;
  - lifetime de DNS por servidor;
  - proxy de RA;
  - limites para RAs recebidos.
- **[OpenWrt odhcpd](https://github.com/openwrt/odhcpd/blob/master/README.md)**:
  - o `ip6assign` divide o prefixo delegado (PD) entre as LANs;
  - os lifetimes têm teto de 45m/90m (os limites da RFC 9096);
  - o `piodir` guarda os prefixos anunciados para depreciá-los depois de um reboot.
- **[radvd](https://man.archlinux.org/man/radvd.conf.5)**:
  - um processo e **um** socket raw ICMPv6 para todas as interfaces;
  - `IPV6_RECVPKTINFO`, hop limit 255, filtro só para RS e RA;
  - `RemoveAdvOnExit` e `DeprecatePrefix`.
- **[FRR zebra](https://docs.frrouting.org/en/latest/ipv6.html)**: RA desligado por padrão; o
  prefixo tem valid de 30 d e preferred de 7 d.

### RFCs

- **[RFC 4861](https://www.rfc-editor.org/rfc/rfc4861)**, com a [errata](https://errata.rfc-editor.org/rfc4861)
  3154 e 4461:

  | Seção | O que diz |
  |---|---|
  | §6.1.1 | validação do RS: hop limit 255, código 0, opções de tamanho não zero, sem SLLAO vindo de `::` |
  | §6.2.1 | padrões; Min ≥ 3 s e ≤ 0,75 × Max |
  | §6.2.2 | entrar em ff02::2 |
  | §6.2.3 | conteúdo do RA; origem link-local |
  | §6.2.4 | 3 RAs iniciais a ≤ 16 s, depois em tempo aleatório |
  | §6.2.5 | RAs finais com lifetime 0 |
  | §6.2.6 | resposta ao RS em 0–0,5 s; no máximo um multicast a cada 3 s |
  | §6.2.7 | conferir os RAs de outros roteadores e logar |

- **[RFC 8319](https://www.rfc-editor.org/rfc/rfc8319)**: Max e lifetime até 65535.
- **[RFC 4862 §5.5.3](https://www.rfc-editor.org/rfc/rfc4862)**: SLAAC só com /64; a regra das
  2 h.
- **[RFC 4191 §2.2](https://www.rfc-editor.org/rfc/rfc4191)**: preferência do roteador; o 10 é
  reservado.
- **[RFC 9096 §3.5](https://www.rfc-editor.org/rfc/rfc9096)**: o prefixo que sai vai com
  preferred e valid 0.
- **[RFC 8106](https://www.rfc-editor.org/rfc/rfc8106)** (RDNSS e DNSSL) e
  **[RFC 7084](https://www.rfc-editor.org/rfc/rfc7084)** (RA só na LAN).

### O que adotamos

- Comandos com os nomes e os padrões do RouterOS: `ipv6.nd.*`, `ipv6.nd.prefix.*` e as
  pré-visualizações `ipv6.nd.check` e `ipv6.nd.prefix.check`.
- Os prefixos dinâmicos vêm de cada endereço global /64 da interface.
  - Um prefixo estático igual substitui o dinâmico; desativado, o esconde. Isso faz o papel do
    `advertise=no`.
  - O campo `advertise` no `ip.address` virou a gap G3.9hi: são 44 construções do
    `AddressEntry`, num ponto quente.
- O prefixo do DHCPv6-PD (um endereço `from_pool` na LAN) entra com os lifetimes que restam da
  delegação, com teto de 5400/2700 s (RFC 9096 §3.4). A contagem regressiva não reinicia a
  rajada de RAs iniciais; um PD novo deprecia o velho.
- RDNSS/DNSSL (RFC 8106), com `advertise_dns`, `dns` e `dnssl`. Os servidores vêm da entrada,
  ou deste roteador quando ele responde DNS, ou do `/ip dns` e do DHCPv6. O lifetime é
  3 × Max, e o RA final manda 0.
- O emissor implementa a RFC 4861:
  - três RAs iniciais;
  - intervalo aleatório;
  - resposta ao RS em multicast;
  - SLLAO, MTU, M/O, preferência e hop limit;
  - RA final com lifetime 0 ao desativar ou parar;
  - prefixo que sai depreciado três vezes;
  - divergência de outro roteador no log e no selo `conflict`.

### Melhorias sobre o RouterOS (segurança por padrão)

- A config nova vem **sem** entrada `all`.
- O `all` deixa de fora:
  - a WAN: cliente DHCPv6, RA aceito, rota padrão IPv6;
  - as portas de servidor PPPoE, onde o BNG anuncia;
  - portas de bridge e de bond, loopback e VRF;
  - interfaces sem prefixo.

  Cada uma aparece como `skipped`, com o motivo.
- Uma entrada explícita numa interface com cara de WAN é aceita, com aviso.
- Uma entrada numa porta PPPoE é recusada.
- O modal mostra onde o RA vai sair antes de aplicar.

### Ficou de fora (gaps)

| Gap | O quê | Por quê |
|---|---|---|
| G3.9hf | Route Information (RFC 4191 §2.3) e PREF64 (RFC 8781) | — |
| G3.9hg | RA só no mestre VRRP | Depende do VRRP |
| G3.9hh | Prefixos anunciados persistidos para depreciar depois de um reboot | — |
| G3.9hi | `advertise`/`eui-64`/`no-dad` no `ip.address` | — |
| G3.9hj | RA guard nas portas de LAN (RFC 6105) | — |

## Decisão: Rust puro × radvd

Medido em 2026-10-29, no Ryzen AI MAX+ 395, em namespace de user e de rede com interfaces
dummy:

| | 100 interfaces | 1000 interfaces |
|---|---|---|
| Rust, 1 socket raw | 1,26 µs/RA | 12,2 µs/RA, 1 fd |
| Rust, 1 socket por interface | 2,57 µs/RA | 39,5 µs/RA, 1000 fds |
| radvd 2.19, até a 1ª rodada | 57 ms, 2,5 MB | 2,4 s, 3,6 MB, 5,4 s de CPU |
| radvd, SIGHUP | 72 ms | morreu com o sinal |

**Fica o emissor próprio em Rust**, com uma thread e um socket. Os motivos:
- o codec já existia, com fuzz (`proto-pppoe/src/nd.rs`);
- não há processo, arquivo nem sinal externos;
- o estado é estruturado: contadores, prefixos depreciados, conflitos;
- o radvd não tem API transacional e pesa com muitas VLANs.

O custo por RA cresce com o número de interfaces. A causa provável é a busca de rota multicast
no kernel, sem confirmação. Mesmo assim, 1000 interfaces dão ~12 ms a cada 200–600 s: mais
threads não ajudam.

## Extras e riscos

- **RA na WAN:** os hosts do provedor tomariam este roteador por gateway. Mitigação: as
  exclusões do `all` e o aviso nas entradas explícitas.
- **Dois emissores na porta PPPoE:** mitigação: a entrada é recusada e o `all` pula a porta.
- **`ra-lifetime 0` por engano** tira o gateway dos hosts. Mitigação: o selo "no gateway" e o
  texto do modal.
- **O emissor precisa de CAP_NET_RAW**, que o daemon já tem. No laboratório virtual o emissor
  fica parado e a lista diz `sender stopped`.
