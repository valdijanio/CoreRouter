# LLDP e MNDP (G5.2)

O CoreRouter descobre vizinhos por três protocolos. O CRDP, protocolo próprio, é do G5.1 e está
em `docs/discovery.md`. Este documento cobre os outros dois:

| Protocolo | Envia? | Recebe? | Por quê |
|---|---|---|---|
| **LLDP** (IEEE 802.1AB) | sim | sim | Padrão aberto, falado por switches gerenciáveis, MikroTik, Cisco, Juniper, Linux (`lldpd`). Interoperar com ele é o que um operador espera. |
| **MNDP** (MikroTik) | **nunca** | sim, só leitura | Proprietário e sem especificação. Ler os anúncios mostra os MikroTiks de uma rede mista. Anunciar MNDP seria fingir ser um MikroTik. |

## O que é enviado (LLDP)

Um LLDPDU a cada `interval_secs` da descoberta (padrão **30 s**, o msgTxInterval do 802.1AB)
por interface habilitada na descoberta, com **TTL = 4 × intervalo** (padrão **120 s**, msgTxHold
4), e logo quando o conteúdo muda (identity, endereços, comentário). Só com `--backend linux`: o
laboratório virtual não tem enlace real. Quadro Ethernet para o endereço de
grupo `01:80:C2:00:00:0E` ("nearest bridge": bridges 802.1D não o encaminham, então o anúncio
nunca sai do enlace), EtherType `0x88CC`, MAC de origem = MAC da porta, zeros de preenchimento
até 60 bytes depois do TLV End.

TLVs que o daemon monta (`apps/corerouter-daemon/src/link_discovery.rs`):

| TLV | Conteúdo |
|---|---|
| Chassis ID | subtipo 7 (local), o node id do CRDP em hex (`<config-dir>/node-id`). Estável entre reinícios e mudanças de interface, e o vizinho que fala os dois protocolos vê o mesmo `node_id` na linha LLDP e na CRDP |
| Port ID | subtipo 5, nome da interface (`ether1`) |
| Time To Live | 4 × intervalo (120); 0 num LLDPDU de desligamento quando a interface sai da descoberta, a descoberta é desligada ou o daemon para |
| Port Description | comentário da interface, se houver (omitido sem comentário) |
| System Name | identity do roteador |
| System Description | `CoreRouter <versão>` |
| System Capabilities | sistema: router + bridge; habilitado: router (+ bridge quando a interface é bridge ou porta de bridge) |
| Management Address | endereços IP configurados na interface (até 8), com ifIndex do kernel |

Nada é enviado em interface fora da lista de descoberta. A lista e o liga/desliga são a
configuração de descoberta do G5.1 (`ip.neighbor.discovery.set`), a mesma para CRDP e LLDP. A
WAN fica fora por padrão.

## O que só é lido

- **LLDP de qualquer vizinho.** Todos os TLVs obrigatórios e os opcionais básicos são
  decodificados. TLVs desconhecidos (tipos 9–126) e os específicos de organização (127, por
  exemplo 802.1/802.3/LLDP-MED) são guardados crus e nunca dão erro.
- **MNDP**, UDP 5678, IPv4 (broadcast) e IPv6 (o socket escuta em `[::]`, só IPv6). Campos
  decodificados: MAC, identity, version, platform, uptime, software-id, board, unpack, IPv4,
  IPv6 e nome da interface de saída do remetente. Fontes públicas usadas, registradas no topo de
  `crates/proto-mndp/src/lib.rs`: o dissector do Wireshark (`packet-mndp.c`; só fatos de formato,
  nenhum código copiado) e o manual "Neighbor discovery" da MikroTik. O formato não tem
  especificação, então o decodificador é tolerante: campo de tamanho fixo com tamanho errado é
  descartado, TLV desconhecido é ignorado, e só a falta do MAC rejeita o pacote.

### Por que o MNDP é só leitura

1. Não há especificação. Um emissor feito por engenharia reversa poderia quebrar em qualquer
   versão do RouterOS e mostrar dados errados no WinBox/The Dude de terceiros.
2. Anunciar MNDP faz o CoreRouter aparecer como dispositivo MikroTik nas ferramentas de outro
   operador. É enganoso, e as marcas são da MikroTik.
3. O que interopera de verdade com MikroTik já está coberto: o RouterOS fala LLDP (ligado por
   padrão), então um MikroTik vê o CoreRouter pelo LLDP.

O crate `proto-mndp` não tem função de codificação; os testes montam os pacotes à mão.

## Implementação

| Peça | Camada | O que faz |
|---|---|---|
| `crates/proto-lldp` | L2 | Codec puro de LLDPDU (`decode`/`encode`), sem I/O, compila para wasm |
| `crates/proto-mndp` | L2 | Só `decode` de anúncio MNDP, sem I/O, compila para wasm |
| `crates/hal-linux/src/l2.rs` | L1 (plataforma) | `LldpIo`: socket `AF_PACKET` por porta, envio periódico (`due`/`send`), recepção não bloqueante; `MndpListener`: UDP 5678 com `IP_PKTINFO` (interface de chegada) |
| `apps/corerouter-daemon/src/link_discovery.rs` | L6 | Junta os dois numa thread (`lldp-mndp`): a cada segundo lê a running, abre/fecha portas LLDP conforme a descoberta, envia o que venceu ou mudou e o desligamento (TTL 0); a cada 200 ms lê quadros e datagramas, decodifica e chama `Session::record_neighbor` |

O `hal-linux` só move bytes porque está abaixo (L1) dos codecs (L2).

**Sem `unsafe`.** O socket vem do `socket2`. O `sockaddr_ll` exigido pelo `bind` de um socket
`AF_PACKET` não é montado à mão: é o que o próprio kernel devolve para a interface em
`getifaddrs` (`nix`). Pelo mesmo motivo, `PACKET_ADD_MEMBERSHIP` (sem API segura) não é usado:
para o grupo `01:80:C2:00:00:0E` passar no filtro de multicast da placa, a porta liga
`allmulticast` via rtnetlink ao abrir, só se estava desligado, e desliga ao fechar.

**Entrada hostil.** LLDPDU limitado a 9216 bytes, datagrama MNDP a 2048. Todo comprimento é
conferido antes da leitura. Texto é decodificado com perdas e cortado em 255 bytes (na fronteira
de caractere). No máximo 64 quadros/datagramas por socket a cada `recv`, para uma enxurrada não
travar o loop do daemon. Cópias dos nossos próprios quadros (`PACKET_OUTGOING`) e quadros para
outros destinos são descartados. Validação de recepção do 802.1AB (9.2.7.7): Chassis ID, Port
ID e TTL obrigatórios e nessa ordem; duplicata deles rejeita o LLDPDU; duplicata de TLV opcional
de instância única fica com o primeiro; End é opcional (802.1AB-2009+).

## Testes

- `proto-lldp`: vetor de um switch montado byte a byte a partir do padrão, ida e volta,
  bytes exatos dos TLVs obrigatórios, erros de ordem/duplicata/truncamento/tamanho; proptest
  (1024 casos cada): decode nunca dá panic (ruído e "sopa" de TLVs válidos), encode→decode
  devolve o mesmo valor, re-codificar o que foi decodificado é ponto fixo, textos respeitam o
  limite.
- `proto-mndp`: anúncio no formato do RouterOS, TLVs desconhecidos, campos de tamanho errado,
  pedido de 4 bytes, truncamentos, limites; proptest com ruído, sopa de TLVs e cortes
  arbitrários.
- `hal-linux/tests/netns_l2.rs`, num network namespace descartável sem root (`cargo xtask
  netns`): LLDP entre as duas pontas de um par veth nos dois sentidos (MAC de origem, payload
  intacto, preenchimento, quem envia não ouve o próprio quadro, intervalo de 30 s); `allmulticast`
  ligado e restaurado; interface inexistente reportada; datagrama UDP 5678 recebido com a
  interface de chegada certa.

### Mapeamento para a tabela de vizinhos

| `NeighborEntry` | LLDP | MNDP |
|---|---|---|
| `interface` | porta de chegada | interface de chegada (`IP_PKTINFO`); sem ela o datagrama é descartado |
| `mac` | MAC de origem do quadro | TLV MAC |
| `addresses` | Management Address (só IP) | IPv4, IPv6 e a origem do datagrama |
| `identity` | System Name | identity |
| `version` / `platform` | System Description; `CoreRouter <v>` vira platform `CoreRouter` + version `<v>`, o resto fica inteiro em version | version / platform |
| `board` | capacidades habilitadas (`router,bridge`) | board |
| `uptime_secs` | — | uptime |
| `node_id` | Chassis ID como texto | — (a linha é chaveada pelo MAC, então as cópias IPv4 e IPv6 do mesmo anúncio são uma linha só) |
| `remote_interface` | Port ID como texto | nome da interface do remetente |
| `hold_secs` | TTL (0 apaga na hora) | 120 s fixos: o MNDP não tem TTL, e o RouterOS anuncia a cada 30 s (**estimado** a partir do manual) |

Texto recebido: caracteres de controle viram `?` e o campo é cortado em 128 bytes. Frames que não
decodificam são descartados (log em `debug`). A sessão já descarta o que chega por interface sem
descoberta ativa.

### Sem permissão (CAP_NET_RAW)

O socket `AF_PACKET` exige `CAP_NET_RAW` (e ligar `allmulticast`, `CAP_NET_ADMIN`). Sem eles o
daemon **não cai**: loga uma vez por interface "LLDP is off on etherN: no permission for a raw
socket … needs CAP_NET_RAW and CAP_NET_ADMIN (run as root, or `setcap
cap_net_raw,cap_net_admin+ep`)" e tenta de novo a cada 10 s. CRDP e MNDP (UDP 5678, porta sem
privilégio) seguem funcionando. Conferido num namespace com `setpriv --bounding-set=-net_raw`.

## Estado

- **Parte 1 (feita):** codecs, I/O no `hal-linux` e testes.
- **Parte 2 (feita, `stream/G5.2-integration`):** o daemon envia e recebe LLDP e escuta MNDP nas
  interfaces da descoberta e grava `lldp`/`mndp` em `ip.neighbor.list`.
  `apps/corerouter-daemon/tests/netns_l2.rs` (`cargo xtask netns`): dois daemons `--backend
  linux` em namespaces sem root, ligados por dois pares veth, se veem como `crdp` **e** `lldp`
  (mesmo `node_id`), o filtro `protocol` funciona, um MNDP sintético para a porta 5678 aparece
  como `mndp` com todos os campos, nada é gravado na interface sem descoberta, e o LLDPDU de
  desligamento apaga a linha antes do TTL (~14 s **medido**).

## Histórico de revisão

- 2026-10-21 — versão inicial (G5.2, Parte 1).
- 2026-10-22 — Parte 2: integração no daemon, mapeamento, Chassis ID = node id, sem permissão.
