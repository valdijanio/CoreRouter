# OSPF (G3.4)

OSPFv2 (IPv4) e OSPFv3 (IPv6) no modelo do RouterOS v7. O FRR (`ospfd`, `ospf6d`) roda o
protocolo e o SPF; o CoreRouter é dono do modelo de configuração, da validação, do render para o
FRR (só a diferença, com rollback: `hal-frr`), das checagens antes do commit e da leitura do
estado (vizinhos, LSDB, rotas, topologia: G3.4b).

## Comandos

| Menu RouterOS | Comandos | O que é |
|---|---|---|
| `/routing ospf instance` | `routing.ospf.instance.{add,set,remove,list}` | Uma por versão e VRF: `router-id`, `redistribute` (connected, static, bgp, kernel), `out_filter_chain` (a chain do `/routing filter`, G3.2b), `originate_default`, `subscriber_pools` |
| `/routing ospf area` | `routing.ospf.area.{add,set,remove,list}` | `area_id`, `type` (default, stub, nssa), `no_summaries`, `default_cost`, `nssa_translate` |
| `/routing ospf area range` | `routing.ospf.area.range.{add,set,remove,list}` | Sumarização num ABR (RFC 2328 §12.4.3): `advertise`, `cost` |
| `/routing ospf interface-template` | `routing.ospf.interface-template.{add,set,remove,move,list,check}` | Casa interfaces por nome, por interface list ou por rede; o primeiro template que casa ganha |
| `/routing ospf static-neighbor` | `routing.ospf.static-neighbor.{add,remove,list}` | Vizinhos de link NBMA (RFC 2328 §9.5.1) |
| (nosso) | `routing.ospf.keychain.{add,set,remove,list}`, `routing.ospf.keychain.key.{add,set,remove}` | Várias chaves com janela de envio e de aceite (RFC 8177) |
| (nosso) | `routing.ospf.impact` | O que o commit faz às adjacências ("estes vizinhos vão cair") |

Exemplo (dois roteadores no backbone, uplink /30 com sha256):

```sh
corerouter-cli run routing.ospf.instance.add '{"name":"v2","router_id":"10.255.0.1","redistribute":"connected"}'
corerouter-cli run routing.ospf.area.add '{"name":"backbone","instance":"v2","area_id":"0.0.0.0"}'
corerouter-cli run routing.ospf.interface-template.add '{"area":"backbone","networks":"10.0.0.0/16","type":"ptp","auth_key":"segredo"}'
corerouter-cli run routing.ospf.interface-template.check '{"area":"backbone","networks":"192.168.0.0/16"}'
```

## Como funciona

- **Templates → interfaces** (`proto_ospf::bind`): para cada interface habilitada, o primeiro
  template (na ordem da lista) de cada instância que a nomeia, nomeia uma interface list dela ou
  tem uma rede com um endereço dela. Cada casamento vira o contexto `interface X` do FRR com os
  valores do template (`ip ospf area`, `ip ospf cost`, …). O FRR não mistura `network … area` com
  `ip ospf area`; ficamos com o por interface, que serve às duas versões.
- **Chaves**: toda chave cripto vai numa key chain do FRR `CR-…` (o `ospfd` do FRR 10 autentica
  HMAC-SHA por key chain, RFC 5709; o `ospf6d` faz o trailer da RFC 7166 do mesmo jeito). A chave
  própria de um template é a chain `CR-T<id>`; a `/routing ospf keychain K` é `CR-K-K`. As
  janelas viram `send-lifetime`/`accept-lifetime` no horário local da caixa: o CoreRouter roda em
  UTC. `simple` usa `ip ospf authentication-key` (8 bytes, RFC 2328 §D.3).
- **Selagem**: `auth_key` e `key_string` chegam em claro e são selados na hora (AES-256-GCM, a
  mesma das senhas PPPoE e da chave TCP MD5 do BGP). Config, histórico, journal, MCP e respostas
  mostram a caixa ou `key_set: true`; só o render abre. O `hal-frr` mascara `key-string`,
  `authentication-key`, `md5 …` e `key …` em erro e log; as duas chaves estão em
  `auth::SECRET_KEYS`.
- **Redistribuição**: um route-map por instância e tipo (`CR-O2-<inst>-connected`): primeiro os
  pools de assinantes, depois a `out_filter_chain` compilada pelo compilador da G3.2b com as
  listas renomeadas `CR-O2-…`/`CR-O3-…` (o BGP continua com as dele no `bgpd`). Uma chain que testa
  ou muda algo que rota OSPF não tem (AS path, communities, local-pref) é recusada no commit.
- **Pools de assinantes (G4.3ce, parte OSPF)**: com `subscriber_pools`, os `/ip pool` dos perfis
  PPPoE (`remote-address`) e dos servidores DHCP IPoE são cobertos pelo menor prefixo de cada
  faixa e agregados; as rotas dos assinantes (PPP: conectada /32; IPoE: kernel) entram pelo
  prefix-list e o `summary-address` do `ospfd` as junta num LSA tipo 5 por prefixo. O núcleo vê
  uma rota por pool, e ela sai sozinha quando o último assinante do pool cai.
- **Contextos no FRR** (`hal_frr::render::OWNED`): `router ospf`, `router ospf6`, `interface`
  (só as linhas `ip ospf …` no `ospfd` e `ipv6 ospf6 …` no `ospf6d`, `render::CHILDREN`: a
  `description` do zebra que o `ospfd` imprime não é nossa), `key chain CR-`, `ip prefix-list
  CR-O2-`, `ipv6 prefix-list CR-O3-`, `route-map CR-O2-`/`CR-O3-`.
- **Forma canônica**: o render escreve como o FRR 10.7.1 imprime de volta (lido dos
  `config_write_*` do `ospfd/ospf_vty.c`, `ospf6d/ospf6_interface.c`, `lib/keychain_cli.c`): área
  pontuada, `%e` com espaço nas datas, valores do `ospf6d` iguais ao padrão omitidos (ele não os
  imprime). Linha que o FRR imprime diferente aparece no log como "leftover".

## Estado (G3.4b)

| Comando | O que é |
|---|---|
| `routing.ospf.neighbor.list` | `/routing ospf neighbor`: estado (RFC 2328 §10.1), papel, selo "Full · DR", tempo no estado, BFD |
| `routing.ospf.interface.list` | As interfaces como o daemon as roda (tipo, estado, MTU, hello/dead, DR/BDR), com o template |
| `routing.ospf.lsa.list` | `/routing ospf lsa`, paginado, por tipo, área e originador |
| `routing.ospf.route.list` | As rotas que o `ospfd` calculou (intra, inter-área, E1/E2) |
| `routing.ospf.topology` | Roteadores e redes de trânsito da LSDB com posição (layout por forças) e custo de cada ponta |
| `routing.ospf.path` | "Por que esse caminho?": o caminho mais curto até um endereço ou router id, custo somado salto a salto, conferido com a rota do daemon (`agrees`) |
| `routing.ospf.neighbor.diagnose` | Por que um vizinho não chega a Full, com a seção da RFC |

- **Vizinhos e interfaces** vêm em toda leitura do serviço `frr` (a cada 2 s, fora do lock).
- **A LSDB e as rotas** são lidas sob demanda, fora do lock: o comando pede (`crate::ospf_state`),
  a thread do FRR lê em fluxo direto do socket (`show ip ospf database <tipo> json`) para a tabela
  compacta `Lsdb` (uma linha fixa por LSA, links num vetor só) e devolve; a primeira resposta pode
  vir `pending`. O resultado vale 10 s e é compartilhado (`Arc`) por páginas, topologia e caminho;
  o layout fica guardado enquanto a mesma cópia da LSDB estiver em uso.
- **Diagnose** (`proto_ospf::diagnose`): com o estado do daemon, explica ExStart/Exchange parado
  (MTU, §10.6), Init (os Hellos chegam mas não nos listam: autenticação, área, timers, máscara,
  §10.5), 2-Way normal em link multiacesso (§10.4), interface passiva ou caída. Com pacotes
  capturados (`proto_ospf::packet`, parser do cabeçalho, Hello e DD de v2 e v3, RFC 2328 §A.3 e
  RFC 5340 §A.3, com proptest) compara campo a campo: área, hello/dead, máscara, bits E/N do tipo
  de área (RFC 3101 §2.3), tipo e key id de autenticação (§D.3), MTU do DD, router id duplicado
  (§C.1) e tipo de rede diferente.
- **Laboratório virtual**: sem FRR, vizinhos, LSDB e rotas são uma amostra feita a partir da
  config (`proto_ospf::sample`: um vizinho por interface ativa, um anel de roteadores e uma LAN de
  trânsito atrás de cada um, a segunda interface parada em ExStart), com `source: "virtual lab
  sample"`.
- **Teste com FRR real**: `cargo xtask vm-lab run -- scripts/frr-ospf-live.sh` (dois FRRs em
  namespaces: Full com HMAC-SHA-256, rotação da chave sem queda, MTU diferente parado antes de
  Full e explicado pelo Diagnose, LSDB e topologia lidas).
- **Limites**: VRF diferente de `main` e a LSDB do OSPFv3 ainda não são lidas (G3.4h).

## Janela Routing › OSPF (G3.4c)

Abas **Neighbors** (estado em selo "Full · DR", área em selo colorido pelo id, uptime, BFD; a linha
selecionada mostra o detalhe e o botão **Diagnose**), **Instances**, **Areas**, **Interface
Templates** e **Key Chains** (o padrão de lista G0.24: barra + − ✓ ✗ 💬, modal com a prévia do
engine: interfaces que entram, tipo e `passive` sugeridos, autenticação ausente, adjacências que
caem com Safe Mode), **LSDB** (paginada por tipo), **Routes** (selecionar uma rota mostra "Por que
esse caminho?") e **Topology** (o mapa desenhado da LSDB; clique num roteador para o caminho; arraste
e role para mover e aproximar). A resposta da topologia vira vetores planos ao chegar: 500
roteadores pintam e tesselam em 3,2 ms por quadro em debug (**medido**).

## Seguro por padrão

- `routing.ospf.interface-template.check` (o modal) mostra antes de aplicar: **quais interfaces
  entram** e por quê (nome, lista, rede), o **tipo sugerido** por interface (/30, /31 ou PPP →
  `ptp`, como o RouterOS 7 faz sozinho em link PtP: sem eleição de DR, adjacência até 40 s mais
  cedo), **`passive` sugerido** em interface com servidor DHCP ou PPPoE (cliente não forma
  adjacência nem injeta rota), **OSPF sem autenticação** em interface ativa e **md5/simple
  inseguros**, o template que **fica escondido** por outro anterior, e o **risco**: as interfaces
  cujas adjacências caem (área, autenticação, tipo de rede, hello/dead, `passive`, tipo da área,
  router-id), com o Safe Mode oferecido.
- `routing.ospf.impact` dá a mesma lista para o candidate inteiro (modo transacional).
- `routing.ospf.keychain.list` diz, no relógio do roteador, qual chave é enviada agora e onde
  uma rotação derrubaria vizinho: um momento sem chave de envio, chave enviada antes de ser
  aceita, ou chave antiga que deixa de ser aceita quando a nova começa a ser enviada (o vizinho
  com o relógio atrasado cai; RFC 8177).
- Validação (recusa o commit): backbone stub/NSSA (RFC 2328 §3.6, RFC 3101 §2.1), dead ≤ hello
  (§C.3), uma instância por versão e VRF, área/instância/key chain inexistentes, OSPFv3 com
  `simple`/`md5` (RFC 7166 só HMAC-SHA), key id > 255 em v2 (§D.3), virtual link fora do backbone
  ou por área stub (§15), janela de chave fora de 1993–2035 (limite do FRR), chain com teste BGP.

## Desempenho e paralelismo

Medido em 2026-10-27, 32 núcleos, build de bench (release), `cargo bench -p
corerouter-proto-ospf --bench ospf_config`: 4 000 interfaces, 4 000 endereços, 1 000 templates
(900 por nome, 100 por rede).

| Medida | Antes | Depois |
|---|---|---|
| templates → interfaces (`bindings`) | 145,7 ms | 10,9 ms |
| render FRR completo | 148,1 ms | 12,7 ms |
| impacto do commit (uma mudança) | 284,8 ms | 32,8 ms |
| validação | 0,30 ms | 0,31 ms |

- **Onde está o trabalho por item:** cada interface tentava todos os templates (O(interfaces ×
  templates × nomes)). Agora os templates são indexados uma vez pelos nomes que listam (listas
  expandidas) e cada interface só tenta os que a nomeiam e os que casam por rede. A listagem e o
  `check` montam o índice uma vez por chamada (antes, um `bindings` por template: O(templates²)).
  Os pools são calculados uma vez por render.
- **Threads:** não ajudam aqui. O render roda uma vez por commit e leva ~13 ms com 4 000
  interfaces; o tempo do commit é do FRR digitando os contextos (G3.1: um thread por daemon, o
  `ospfd` e o `ospf6d` em paralelo, já feito). Dividir o casamento por faixa de interfaces
  ganharia ≤ 10 ms e não roda no WASM.

### Estado: LSDB e layout (G3.4b)

Medido em 2026-10-27, 32 núcleos (carga ~10 de outras sessões), build de bench.

| Medida | Resultado |
|---|---|
| LSDB de 10 000 LSAs (2 000 router com 4 links, 500 network, 7 500 externas; 4,0 MiB de JSON): leitura em fluxo para a tabela compacta | 9,1 ms, 612 KiB |
| a mesma como árvore `serde_json::Value` | 17,0 ms, +34 MiB de RSS |
| layout de 500 roteadores (570 links, 300 rodadas): 1 thread | 66,8 ms |
| idem, 4 threads | 27,1 ms |
| idem, 16 threads | 29,1 ms (a barreira entre rodadas custa o que a divisão ganha) |

- **Por item:** a LSDB vai direto do socket para linhas fixas (um LSA = 40 bytes, um link = 12),
  sem árvore JSON; uma página de LSAs é um filtro sobre o vetor.
- **Threads no layout:** a repulsão é O(n²) por rodada e cada nó só depende das posições da
  rodada anterior, então os nós se dividem em pedaços, um thread por pedaço, criados uma vez, com
  uma barreira entre as rodadas (criar threads a cada rodada custava mais do que ganhava: 16
  threads em 69 ms contra 72 ms em um, **medido**). O mesmo resultado em 1 ou N threads (teste).
  Limite de 8 threads; no WASM, um. O layout roda uma vez por LSDB nova e fica guardado, não a
  cada quadro.

## Pesquisa

- **MikroTik RouterOS v7** ([OSPF](https://help.mikrotik.com/docs/spaces/ROS/pages/9863229/OSPF),
  [interface-template 7.25](https://manual.mikrotik.com/docs/7.25/cli-reference/routing/ospf/interface-template)):
  `instance` (version 2/3, vrf, router-id, redistribute, originate-default, out-filter-chain),
  `area` (type default/stub/nssa, no-summaries), `area range` (advertise, cost),
  `interface-template` (interfaces/networks como casadores, type broadcast/nbma/ptp/ptmp/…, cost,
  priority 128, hello 10 s, dead 40 s, passive, auth simple/md5/sha1/sha256/sha384/sha512,
  auth-id, auth-key, use-bfd), `static-neighbor`; `neighbor` e `lsa` só leitura. O tipo padrão é
  `ptp` em interface PtP. Relato de interoperabilidade
  ([bird-users, 2023](https://bird.network.cz/pipermail/bird-users/2023-January/016526.html)):
  `auth-id` padrão 0 no RouterOS 7.7 quebrava com o BIRD — o `check` avisa que usamos 1 sem
  `auth_id`.
- **FRR 10.7.1** (código-fonte, tag `frr-10.7.1`, commit `f8c0b08`): HMAC-SHA no `ospfd` só por
  key chain (`ospf_auth.c`), `ospf6d` com `authentication keychain` (RFC 7166), key chain é
  northbound (`ietf-key-chain`) e cada daemon tem a sua cópia, `summary-address` para agregar
  externas, `ip ospf passive` por interface.
- **Cisco IOS-XE**: `ip ospf authentication key-chain` com `cryptographic-algorithm
  hmac-sha-256` e `send-lifetime`/`accept-lifetime`; `area range`, `summary-address`, `passive-
  interface default`; `ip ospf network point-to-point` recomendado em /30–/31.
- **Juniper Junos**: `authentication keychain` com `tolerance` (folga entre envio e aceite, o que
  inspirou o aviso de rotação), `interface-type p2p`, `passive`, `area-range`.
- **Nokia SR OS**: `authentication-keychain` com `tolerance`, `interface-type point-to-point`,
  `passive`, `area-range`, `loopfree-alternates`.
- **RFCs (cadeia)**: RFC 2328 (OSPFv2; atualizada pelas 5709, 6549, 6845, 6860, 7474, 8042, 9355 e
  9454, [rfc-editor](https://www.rfc-editor.org/info/rfc2328), e errata em
  [rfc-editor.org/errata](https://www.rfc-editor.org/errata/rfc2328)), RFC 5709 (HMAC-SHA; atualizada pela 7474, que adiciona
  proteção de replay), RFC 7474 (contador de sequência que não recua), RFC 3101 (NSSA), RFC 5250
  (LSA opaco), RFC 3623 (graceful restart), RFC 6860 (esconder prefixos de trânsito), RFC 5340
  (OSPFv3; atualizada pelas 6845, 6860, 7503, 8362 e 9454,
  [rfc-editor](https://www.rfc-editor.org/info/rfc5340)), RFC 7166 (trailer de autenticação do v3,
  substitui a 6506), RFC 8362 (OSPFv3 estendido), RFC 5882 (BFD genérico), RFC 8177 (modelo
  YANG de key chain). Seções citadas no código e nos testes (§3.6, §10.5, §10.6, §12.4.3, §15,
  §C.3, §D.3; RFC 3101 §2.1, §3.1; RFC 7166 §4.3).
- **O que adotamos além do RouterOS:** key chains com janelas e análise de rotação, chaves
  seladas, `sha256` por padrão quando só a chave é dada, prévia das interfaces que entram, tipo e
  `passive` sugeridos, aviso de autenticação ausente/fraca, prévia "estes vizinhos vão cair" com
  Safe Mode, pools de assinantes sumarizados, recusa de chain BGP-only no OSPF.
- **Ficou para depois:** LFA/TI-LFA (RFC 5286, G3.4d), graceful restart com a atualização A/B
  (RFC 3623, G3.4e), Segment Routing (RFC 8665, G3.4f), pools IPv6 no OSPFv3 (G3.4g).
