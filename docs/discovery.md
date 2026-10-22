# CRDP — CoreRouter Discovery Protocol (v1)

Status: implementado no G5.1 (Fase A). Codec em `crates/proto-discovery` (L2, puro), runtime em
`crates/discovery` (L4, sockets + threads std), tabela de vizinhos no engine
(`Session::record_neighbor`), comandos `ip.neighbor.*`, janela IP › Neighbors e tela de conexão
da GUI.

## 1. Por que um protocolo próprio

O WinBox acha roteadores pelo MNDP (UDP 5678) e gerencia sem IP pelo RoMON. Os dois são
proprietários e sem especificação pública: não os clonamos. O CRDP é nosso, documentado aqui e
versionado. Para redes mistas, o G5.2 acrescenta LLDP (IEEE 802.1AB, aberto) e só a **escuta**
do MNDP — o CoreRouter nunca anuncia MNDP. Todos alimentam a mesma tabela de vizinhos.

## 2. Transporte

| Item | Valor |
|---|---|
| Porta | **UDP 7979** — o número da porta TCP do canal de controle, para que um par de regras de firewall cubra a gerência. Não é a 5678 do MNDP. |
| IPv6 | `ff02::1` (all-nodes, escopo de enlace) com o índice da interface de saída; hop limit 1 (padrão de multicast) |
| IPv4 | broadcast dirigido de cada endereço IPv4 da interface (`10.0.0.255` para `10.0.0.1/24`), saindo de um socket ligado a esse endereço; prefixos /31 e /32 não têm broadcast e não anunciam por IPv4 |
| Interfaces | só as da lista `ip.neighbor.discovery.set {interfaces}` com `enabled = true`, e nunca uma interface desabilitada |
| Respostas | **nenhuma**. O CRDP só anuncia e escuta; um datagrama recebido nunca gera tráfego |

Vários processos CRDP no mesmo host (daemons, GUI) compartilham a porta (`SO_REUSEADDR` +
`SO_REUSEPORT`); cada um recebe a sua cópia de cada broadcast/multicast.

## 3. Tempo

- Anúncio a cada `interval_secs` (padrão **30 s**, aceito 1..=3600) e logo depois de qualquer
  mudança nas configurações de descoberta.
- `hold` anunciado = 4 × intervalo (**120 s** no padrão), limitado a 65535. O receptor esquece o
  vizinho `hold` segundos depois do último anúncio.
- **Despedida:** quando a descoberta para numa interface (saiu da lista, `enabled = false`), o
  roteador manda um último anúncio com `hold = 0`; quem recebe apaga o vizinho na hora.
- O daemon expira a tabela uma vez por segundo.

## 4. Formato

Todos os inteiros em big endian. Um anúncio = um datagrama de no máximo **1232 bytes** (MTU
mínima do IPv6, 1280, menos os cabeçalhos IPv6 e UDP), para nunca fragmentar.

### Cabeçalho (8 bytes)

| Bytes | Campo | Valor |
|---|---|---|
| 0..4 | magic | `"CRDP"` (`43 52 44 50`) |
| 4 | versão | `1`. Outra versão → datagrama descartado |
| 5 | reservado | enviado `0`, ignorado na recepção |
| 6..8 | tamanho | bytes de TLV que seguem; tem de ser exatamente o resto do datagrama |

### TLVs

Cada TLV: tipo (u16), tamanho (u16), valor. Tipo `0` é inválido.

| Tipo | Nome | Valor | Obrigatório | Repete |
|---|---|---|---|---|
| 1 | node id | 16 bytes, aleatório, nunca todo zero | sim | não |
| 2 | hold | u16, segundos (0 = despedida) | sim | não |
| 3 | identity | texto (`system.identity`) | sim | não |
| 4 | version | texto (versão do software) | não | não |
| 5 | platform | texto (`CoreRouter`) | não | não |
| 6 | board | texto (arquitetura e backend, ex. `x86_64 linux`) | não | não |
| 7 | uptime | u64, segundos desde que o daemon subiu | não | não |
| 8 | interface | texto, nome da interface de saída no remetente | não | não |
| 9 | MAC | 6 bytes, MAC da interface de saída | não | não |
| 10 | IPv4 | 4 bytes de endereço + 1 byte de prefixo (≤ 32) | não | até 16 |
| 11 | IPv6 | 16 bytes de endereço + 1 byte de prefixo (≤ 128) | não | até 16 |
| 12 | porta de controle | u16 ≠ 0, TCP do canal de controle (`--control`) | não | não |
| 13 | porta WebSocket | u16 ≠ 0, GUI web (`--ws`) | não | não |

Texto: UTF-8 válido, no máximo **128 bytes**, sem caracteres de controle. O remetente corta a
identity no limite (num limite de caractere); o receptor recusa o que passar dele.

### Regras de recepção (entrada hostil)

Qualquer um no enlace manda qualquer coisa. O decodificador (`proto_discovery::decode`) nunca dá
panic (proptest com bytes arbitrários, cabeçalho válido + lixo, e bytes trocados de anúncios
válidos) e descarta o datagrama inteiro quando:

- é maior que 1232 bytes ou menor que o cabeçalho; magic ou versão errados;
- o tamanho do cabeçalho difere do resto do datagrama; um TLV passa do fim;
- um TLV conhecido tem tamanho ou valor inválido (porta 0, prefixo > 32/128, node id zero,
  texto inválido); um TLV não repetível aparece duas vezes; IPv4/IPv6 passam de 16;
- falta node id, hold ou identity.

**TLVs de tipo desconhecido são pulados**: versões futuras acrescentam TLVs sem quebrar quem
lê v1. Mudança incompatível = nova versão no cabeçalho.

Depois de decodificar, o receptor:

1. ignora o próprio node id (cópias de loopback);
2. descobre a interface de chegada: o *scope id* do endereço link-local de origem (IPv6), ou a
   sub-rede configurada que contém a origem (IPv4);
3. só guarda o vizinho se a descoberta estiver ativa nessa interface (config **running**);
4. a tabela tem no máximo 4096 entradas; cheia, a que expira primeiro sai.

## 5. Configuração e estado

| O quê | Onde | Persistido |
|---|---|---|
| `enabled`, `interfaces`, `interval_secs` | `Config.ip.neighbor_discovery` (`ip.neighbor.discovery.set` / `.get`) | sim, como qualquer config (revisão, rollback) |
| Vizinhos | `Session::neighbors()` (`ip.neighbor.list`) | **não** — estado operacional |
| Node id | `<config-dir>/node-id` (32 dígitos hex) | sim; sem `--config-dir`, vale só enquanto o processo vive |

**Padrão: `enabled = true` com nenhuma interface.** O CoreRouter ainda não tem listas de
interfaces LAN/WAN, então não sabe qual porta é WAN; anunciar numa WAN contaria à internet a
identity, a versão e as portas de gerência. O operador liga a descoberta nomeando as
interfaces do lado LAN: `ip.neighbor.discovery.set {"interfaces": ["ether2", "bridge1"]}`.
Remover uma interface (`interface.remove`) também a tira da lista.

## 6. Ponto de integração para outros protocolos (G5.2)

LLDP e MNDP entram na mesma tabela sem comando novo:

```rust
let entry = NeighborEntry {
    interface,                       // nossa interface de chegada
    protocol: NeighborProtocol::Lldp,
    mac, addresses, identity, version, platform, board,
    uptime_secs, node_id,            // LLDP: chassis id como texto
    remote_interface,                // LLDP: port id
    mgmt: None,
    last_seen: unix_now(),           // o mesmo relógio do expire_neighbors
    hold_secs: ttl,                  // LLDP TTL; 0 = shutdown, apaga
};
corerouter_engine::lock(&shared).record_neighbor(entry); // false: interface sem descoberta
```

Implementado assim em `apps/corerouter-daemon/src/link_discovery.rs` (G5.2).

A chave da linha é `(interface, protocolo, node_id | MAC | primeiro endereço | identity)`. Quem
chama `record_neighbor` não precisa filtrar por interface: a sessão já descarta o que chega por
interface sem descoberta ativa. `expire_neighbors(now)` roda no daemon a cada segundo
(`corerouter_discovery::Agent`).

### LLDP e MNDP (G5.2)

Com `--backend linux`, o daemon usa as **mesmas** configurações (`enabled`, `interfaces`,
`interval_secs`) para o LLDP, e escuta MNDP nelas. Detalhes em `docs/lldp-mndp.md`.

| | Enviado | Só lido | Por quê |
|---|---|---|---|
| **CRDP** | sim | sim | Nosso, documentado acima |
| **LLDP** (802.1AB) | sim: a cada `interval_secs`, TTL 4 ×, System Name = identity, System Description = `CoreRouter <versão>`, Port ID = nome da interface, Chassis ID = node id, Management Address = endereços da interface; TTL 0 quando a interface sai | sim | Padrão aberto que switches, MikroTik, Cisco e `lldpd` falam |
| **MNDP** (MikroTik) | **nunca** | sim, UDP 5678 | Proprietário e sem especificação; anunciar seria fingir ser um MikroTik. Um RouterOS já vê o CoreRouter pelo LLDP |

No laboratório virtual (`--backend virtual`) só roda o CRDP: não há enlace de camada 2.
`--no-discovery` desliga os três.

## 7. GUI

- **IP › Neighbors** (`crates/ui/src/neighbors.rs`): tabela reutilizável (Interface, Protocol,
  Address, MAC Address, Identity, Version, Board, Uptime) e as configurações de descoberta.
- **Tela de conexão** (`crates/ui/src/connect.rs`, estilo login do WinBox 4): abre quando a GUI
  nativa inicia sem `--connect`. Esquerda: Connect to, Login, Password, Remember password, Group,
  Comment, Save to list, Connect e "Virtual lab". Direita: abas Neighbors e Saved com Find.
  Clique num vizinho preenche Connect to; duplo clique preenche e conecta.
  - Nativo: escuta CRDP direto nas interfaces da máquina (`corerouter_discovery::Listener`,
    nunca envia). Um vizinho que roda na própria máquina vira `127.0.0.1:<porta>`.
  - Web: o navegador não escuta UDP; a aba Neighbors mostra o `ip.neighbor.list` do daemon que
    serviu a página, e Connect to usa a porta WebSocket anunciada.
  - Login e senha ficam **desabilitados** até a autenticação (G0.3). Saved guarda só endereço,
    grupo e comentário (arquivo `saved-routers.json` no diretório de config do usuário, ou
    `localStorage` na web); senha nunca é gravada em texto puro.

## 8. Segurança

- Sem autenticação nem assinatura na v1: um anúncio pode ser forjado por quem está no enlace. O
  efeito é limitado a uma linha falsa na tabela (que nunca é usada para rotear) e um
  "Connect to" enganoso — e conectar ainda exige alcançar o canal de controle, que hoje só
  aceita loopback (G0.3).
- O CRDP nunca responde, então não serve para amplificação.
- Assinatura dos anúncios com o segredo da malha e transporte entre vizinhos sem IP vêm no G5.3.

## Histórico de revisão

- 2026-10-22 — v1 (G5.1).
- 2026-10-22 — LLDP e MNDP no §6 (G5.2 Parte 2).
