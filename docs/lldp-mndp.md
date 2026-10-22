# LLDP e MNDP (G5.2)

O CoreRouter descobre vizinhos por três protocolos. O CRDP, protocolo próprio, é do G5.1 e está
em `docs/discovery.md`. Este documento cobre os outros dois:

| Protocolo | Envia? | Recebe? | Por quê |
|---|---|---|---|
| **LLDP** (IEEE 802.1AB) | sim | sim | Padrão aberto, falado por switches gerenciáveis, MikroTik, Cisco, Juniper, Linux (`lldpd`). Interoperar com ele é o que um operador espera. |
| **MNDP** (MikroTik) | **nunca** | sim, só leitura | Proprietário e sem especificação. Ler os anúncios mostra os MikroTiks de uma rede mista. Anunciar MNDP seria fingir ser um MikroTik. |

## O que é enviado (LLDP)

Um LLDPDU a cada **30 s** (msgTxInterval padrão do 802.1AB) por interface habilitada na
descoberta, com **TTL 120 s** (4 × 30, msgTxHold padrão). Quadro Ethernet para o endereço de
grupo `01:80:C2:00:00:0E` ("nearest bridge": bridges 802.1D não o encaminham, então o anúncio
nunca sai do enlace), EtherType `0x88CC`, MAC de origem = MAC da porta, zeros de preenchimento
até 60 bytes depois do TLV End.

TLVs que o daemon vai montar (integração, segundo PR; veja "Estado"):

| TLV | Conteúdo |
|---|---|
| Chassis ID | subtipo 4, MAC (da primeira interface, fixo enquanto o roteador roda) |
| Port ID | subtipo 5, nome da interface (`ether1`) |
| Time To Live | 120 (0 num LLDPDU de desligamento quando a interface sai da descoberta) |
| Port Description | comentário da interface, se houver |
| System Name | identity do roteador |
| System Description | `CoreRouter <versão>` |
| System Capabilities | router (+ bridge quando a interface é porta de bridge) |
| Management Address | endereços IP da interface, com ifIndex |

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
| daemon | L6 | Junta os dois: monta o LLDPDU, decodifica o que chega, injeta na tabela de vizinhos do G5.1 (segundo PR) |

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

## Estado

- **Parte 1 (feita):** codecs, I/O no `hal-linux` e testes.
- **Parte 2 (segundo PR, depois do G5.1):** o daemon liga `LldpIo`/`MndpListener` à
  configuração de descoberta e injeta vizinhos `lldp`/`mndp` na tabela de `ip.neighbor.list`
  pelo ponto de entrada do G5.1 (mapeando MAC, identity/System Name, versão, platform/board,
  uptime, endereços e interface); LLDPDU de desligamento (TTL 0) quando uma interface sai da
  descoberta; expiração pelo TTL recebido.

## Histórico de revisão

- 2026-10-21 — versão inicial (G5.2, Parte 1).
