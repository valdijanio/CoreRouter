# Avisos ao assinante (Subscriber Notices, G4.10)

Página de bloqueio e de aviso para provedores: o assinante em atraso (ou com um aviso a ler) **vê
a página**, sem erro de certificado, no celular, no notebook e atrás do roteador dele, e nada
além do que o operador liberou passa. Aprovado pelo usuário em 2026-10-26 ("aprovado, pode abrir
a sessão da página de bloqueio com essa ideia do Detecção de portal do sistema").

| Peça | Onde | Parte |
|---|---|---|
| Modelo (perfis, walled garden, páginas, logins, ajustes) | `crates/model/src/subscriber_notice.rs` | G4.10a |
| Comandos `ip.subscriber-notice.*`, `ip.dhcp-server.lease.notice`, `ppp.secret.notice` | `crates/engine/src/cmd/subscriber_notice.rs` | G4.10a |
| Estado de execução (quem viu, log de visualizações, variáveis por assinante) | `crates/engine/src/subscriber_notice.rs` | G4.10a |
| Sondas de detecção de portal de cada sistema (tabela de dados) | `crates/model/src/subscriber_notice/probes.rs` | G4.10a |
| Plano de dados (nftables, listas reservadas, rejeição rápida) | `crates/firewall/src/notice.rs` | G4.10b |
| Servidor do portal, API RFC 8908, opção 114, webhook | `apps/corerouter-daemon/src/service/notice.rs` | G4.10c |
| Janela Subscriber Notices | `crates/ui/src/subscriber_notice.rs` | G4.10d |
| Laboratório (sondas simuladas por sistema, atrás de NAT e direto) | `tests/netns_notice.rs` | G4.10e |

## Como funciona

```text
assinante na lista do perfil ──► nftables (tabela inet corerouter, cadeias notice_*)
   │
   ├─ DNS (53)                         passa (resolver do roteador ou o do cliente)
   ├─ walled garden (IPs resolvidos)   passa (site do provedor, PIX, boleto)
   ├─ TCP 80 (sonda do sistema ou qualquer site HTTP)
   │        └─ redirect para o portal do próprio roteador (porta 8880)
   │              ├─ sonda conhecida  → 302 para a página (o sistema abre "Entrar na rede")
   │              └─ outro site HTTP  → 511 com a página (RFC 6585 §6)
   └─ o resto (HTTPS, QUIC, apps)      bloqueio: TCP RST / ICMP admin-prohibited na hora
                                       aviso/redução: passa
```

- **Tudo por endereço IP**: o perfil aponta uma *address list* do firewall; PPPoE, IPoE, DHCP e
  endereço fixo funcionam igual. Quem põe o assinante na lista: o operador (lista estática), o
  lease do DHCP ("Block (com página)" = a lista do perfil em `address_lists`), o secret do PPP
  ("Block (com página)" = `ppp.secret.notice`, o endereço da sessão entra na lista enquanto ela
  está de pé), o RADIUS (`Mikrotik-Address-List` no Access-Accept, já existente), o CoA (G4.3d),
  a API e o MCP (`ip.firewall.address-list.add`).
- **Sem derrubar o PPPoE**: entrar ou sair da lista muda só um elemento de um conjunto do
  nftables; a liberação vale no próximo pacote (segundos contando o tick do serviço).
- **Modos**:
  - `block` — só DNS, o portal, o walled garden e o que o perfil libera; o resto é recusado na hora
    (TCP RST, ICMP *administratively prohibited*), para o app falhar rápido em vez de travar;
  - `notice` — internet normal; só as sondas de detecção de portal (e, com `intercept=http`, o HTTP
    simples) vão para a página, até o assinante vê-la ou passar `timeout`; depois, de novo a cada
    `interval`;
  - `throttle` — como `notice`, com a banda reduzida por uma fila dinâmica (Queues, G4.9).

## A peça principal: a detecção de portal do próprio sistema

Todo sistema, ao entrar numa rede (e de tempos em tempos), faz uma requisição **HTTP simples**
(sem TLS) a um endereço conhecido e compara a resposta com a esperada. Resposta diferente =
"esta rede tem portal": o sistema mostra a notificação "Entrar na rede / Sign in to network" e
abre um mini navegador. Como a sonda é HTTP, o roteador responde no lugar do servidor **sem
certificado nenhum**, e funciona mesmo para quem só usa apps e HTTPS, com DoH, e atrás do roteador
do cliente (o CPE faz NAT, mas o celular atrás dele faz a própria sonda).

Respostas esperadas (a tabela de dados vive em `crates/model/src/subscriber_notice/probes.rs`;
mudou um sistema, muda uma linha):

| Sistema | Sonda (HTTP) | Resposta de "internet ok" |
|---|---|---|
| Android (AOSP `NetworkMonitor`) | `connectivitycheck.gstatic.com/generate_204`; reserva `www.google.com/gen_204`, `play.googleapis.com/generate_204` | 204 (200 com corpo vazio também conta) |
| Chrome OS / Chromium | `clients3.google.com/generate_204`, `connectivitycheck.android.com/generate_204` | 204 |
| Samsung, Xiaomi, Huawei (ROMs com sonda própria) | `connectivitycheck.samsung.com/generate_204`, `connect.rom.miui.com/generate_204`, `connectivitycheck.platform.hicloud.com/generate_204` | 204 |
| Apple iOS / macOS (`CaptiveNetworkSupport`) | `captive.apple.com/hotspot-detect.html`, `www.apple.com/library/test/success.html` | 200 com `Success` |
| Windows 10/11 (NCSI) | `www.msftconnecttest.com/connecttest.txt` (`ipv6.msftconnecttest.com`); antigo `www.msftncsi.com/ncsi.txt` | `Microsoft Connect Test` / `Microsoft NCSI` |
| Firefox | `detectportal.firefox.com/canonical.html`, `/success.txt` | o `meta refresh` da Mozilla / `success` |
| NetworkManager (Fedora, Ubuntu, Arch, GNOME, KDE, Debian) | `fedoraproject.org/static/hotspot.txt`, `connectivity-check.ubuntu.com/`, `ping.archlinux.org/nm-check.txt`, `nmcheck.gnome.org/check_network_status.txt`, `networkcheck.kde.org/`, `network-test.debian.org/nm` | `OK`, 204 ou `NetworkManager is online` |

Decisões que saem dessa tabela:

- **A sonda recebe 302** para a página do portal. É o que todos tratam como portal. O Android
  classifica pelo código: 200–399 é portal, **4xx/5xx é "sem internet"** (não abre a página),
  então a sonda **nunca** recebe 511. O 511 (RFC 6585 §6) fica para o HTTP comum de navegador,
  com a página no corpo (o navegador mostra o corpo; um cliente de API entende que é a rede).
- **`Cache-Control: no-store`** em toda resposta interceptada (RFC 6585 §6 diz que o 511 não pode
  ir para cache; a 302 de uma sonda também não deve).
- **O DNS nunca é desviado** (decisão do brief): desviar todo o DNS quebra apps e é invasivo. A
  checagem de DNS do Windows (`dns.msftncsi.com` → 131.107.255.255) continua funcionando.
- **Os IPs das sondas** (para o modo `notice`, que só intercepta as sondas) vêm do resolver do
  roteador: o serviço resolve os nomes da tabela de tempos em tempos e mantém a lista reservada
  `sn-probe`. Um cliente com DoH chega nos mesmos IPs (CDN anycast), salvo exceção rara; para esse
  caso, `intercept=http` intercepta todo HTTP simples.

## Normas

- **RFC 8910** (obsoleta a RFC 7710 e muda o código DHCPv4 de 160 para **114**; atualiza a RFC
  3679): opção DHCPv4 114, DHCPv6 103 e opção 37 do RA, com a URI da **API** (RFC 8908), não da
  página. §2: a URI SHOULD NOT ter IP literal; o mesmo valor nos três; o cliente ainda faz as
  sondas (a interceptação continua necessária para clientes antigos). §2.3: a opção do RA é
  completada com zeros até múltiplo de 8 bytes. `urn:ietf:params:capport:unrestricted` diz "sem
  portal". Sem errata registrada (conferido em 2026-10-26).
- **RFC 8908** (API do portal): a URI **MUST** ser `https` (§4) e o cliente **MUST** validar o
  certificado contra o nome (§4.1); sem certificado válido o cliente age como se a API não
  existisse. Resposta `application/captive+json` (§5), chave obrigatória `captive` (bool),
  opcionais `user-portal-url` (MUST TLS), `venue-info-url`, `can-extend-session`,
  `seconds-remaining`, `bytes-remaining`; `Cache-Control: private` ou mais restrito.
  **Consequência:** as opções 114/37 só vão quando o operador configura `capport_url` com um nome
  e certificado válidos (o mesmo que o MikroTik exige: `dns-name` e certificado). Sem isso, nada é
  anunciado e a interceptação das sondas faz todo o trabalho — e ela já basta para "o cliente
  sempre vê a página".
- **RFC 6585 §6** (511 Network Authentication Required): para intercepção, com a página (link de
  login) no corpo, não pode ir para cache; um servidor de origem não deve gerá-lo.
- **RFC 2131/2132** para a opção DHCP; **RFC 4861** para a opção do RA.

## Como os outros fazem

- **MikroTik RouterOS v7 HotSpot** ([doc](https://help.mikrotik.com/docs/spaces/ROS/pages/56459266/HotSpot+-+Captive+portal)):
  `walled-garden` (HTTP/HTTPS por `dst-host`, curinga `*`, `:`regex) e `walled-garden ip`
  (endereço, protocolo, porta); `https-redirect=yes` redireciona HTTPS com erro de certificado
  (o padrão), `no` só recusa; a API RFC 8908 e a opção DHCP só com `dns-name` e certificado válido.
  O HotSpot é para Wi-Fi com login; o **bloqueio de inadimplente** em provedor MikroTik é feito à
  mão: address-list `bloqueados`, regras para liberar DNS e o site do provedor, `dst-nat` da porta
  80 para um servidor externo (MK-Auth, IXC, SGP), `drop` do resto. A dor: HTTPS não é
  redirecionável sem erro, então o cliente não vê nada (o `drop` ainda faz o app ficar girando) e
  liga para o suporte.
- **pfSense / OPNsense** ([pfSense](https://docs.netgate.com/pfsense/en/latest/captiveportal/index.html),
  [OPNsense](https://docs.opnsense.org/manual/captiveportal.html)): zonas por interface,
  redirecionamento HTTP para o servidor web local, "Allowed Hostnames" resolvidos pelo DNS e
  re-resolvidos de tempos em tempos, login HTTPS com certificado próprio. O OPNsense anuncia a
  opção RFC 8910 desde a 23.x. Não é bloqueio de provedor (é login de convidado).
- **VyOS**: não tem portal; usa-se um servidor externo com regras de NAT.
- **Juniper/Cisco BNG** (Junos subscriber management, IOS-XE ISG): *HTTP redirect service* por
  assinante ativado por RADIUS/CoA, *walled garden* por ACL, liberação por CoA sem derrubar a
  sessão. É o desenho mais próximo do nosso, e o motivo de tudo aqui ser por lista e por CoA.

## O que adotamos e o que fica melhor que o MikroTik

- **Detecção de portal do sistema** como mecanismo principal (no MikroTik é acidente do HotSpot;
  no bloqueio de provedor não existe).
- **Recusa rápida** (RST/ICMP), não `drop`: o app mostra "sem conexão" na hora.
- **Página servida pelo próprio roteador**, com variáveis `{login}` `{plano}` `{valor}`
  `{vencimento}` `{link_pix}` preenchidas pela API (`ip.subscriber-notice.vars.set`) ou pelos
  atributos de resposta do RADIUS — sem servidor externo para cair.
- **Walled garden por domínio** resolvido pelo DNS do roteador (lista reservada `sn-garden`), com
  padrão restritivo (vazio).
- **Liberação automática** ao sair da lista, sem derrubar a sessão; **aba Active** (quem está
  bloqueado ou avisado, desde quando, se viu a página); **Log** de cada visualização (prova de
  aviso); **Testar como cliente** (`ip.subscriber-notice.test`: o que um endereço recebe, sonda
  por sistema, e por que não funcionaria); **webhook** quando alguém entra numa lista (WhatsApp,
  SMS, e-mail pelo sistema do provedor — cobre TV e IoT que não mostram portal).
- **Nunca**: desviar todo o DNS, interceptar HTTPS (MITM) ou pedir certificado no aparelho.

## Extras e riscos

- **Firewall de entrada do operador**: o redirect leva a conexão para a porta 8880 do roteador;
  uma regra `input` do operador que descarte o tráfego dos assinantes derruba o portal. O
  `ip.subscriber-notice.test` avisa (avalia o `input` contra um SYN do assinante para a porta).
- **Conexões já abertas no fast path** (XDP, flowtable): ao entrar em `block`, as conexões do
  assinante são encerradas (`connections_kill`), senão um download em andamento continuaria pelo
  caminho rápido (G4.10b).
- **Limite de entradas dinâmicas** (`MAX_DYNAMIC` = 65 536): o RADIUS e o PPP usam listas
  dinâmicas; acima disso, o sistema do provedor deve usar entradas estáticas (sem limite próprio;
  100 mil medidos na G4.10b).
- **TV e IoT** não mostram portal: por isso o webhook.
- **Falso positivo de sonda**: intercepta só a porta 80 dos IPs das sondas; HTTPS para os mesmos
  IPs (Google, Apple) segue intocado no modo `notice`.

## Desempenho e paralelismo

- **Trabalho por pacote**: uma consulta de conjunto (hash/intervalo do nftables) por cadeia, nada
  por assinante; 100 mil assinantes listados = um conjunto de 100 mil elementos, sem regra por
  assinante (medido na G4.10b).
- **Trabalho por assinante**: a entrada ou saída de uma lista é um elemento de conjunto
  (`address_list_dynamic`), O(1).
- **Portal**: servidor com número de conexões e de bytes por requisição limitados, threads
  nomeadas, lendo um retrato (perfis, páginas, membros) atualizado pelo tick, sem o lock da
  `Session` na E/S; marcar "visto" põe numa fila limitada aplicada no tick (G4.10c).
