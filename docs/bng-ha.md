# BNG em alta disponibilidade: par ativo/espera (G4.3h)

Dois CoreRouters atendem os mesmos assinantes PPPoE/IPoE como um par: um **ativo** responde, o
outro fica de **espera** com uma cópia das sessões. Se o ativo cai, o de espera assume com o mesmo
MAC virtual, os mesmos SESSION_IDs e os mesmos números mágicos do LCP: o CPE não percebe (sem
PADT, sem novo login) e a contabilização continua com o mesmo Acct-Session-Id.

Aprovado pelo usuário em 2026-10-26, com as duas fases e todos os extras. Entra em PRs
empilhados:

| PR | Parte | Estado |
|---|---|---|
| a | crate `proto-ha` (sans-IO): codec do sync, registro da sessão, máquina de papéis com cerca, hello de acesso, laboratório de dois nós, fuzz, benchmark; este documento | #241 |
| b | modelo `ppp.redundancy` e comandos `ppp.redundancy.{set,get,monitor,switchover,simulate-failure}` | #242 |
| c | serviço `ppp-ha` no daemon: link de sync TLS com autenticação mútua, hello de acesso (AF_PACKET), testemunha (ICMP), track, monitor; `proto_ha::node` (o mesmo código no daemon e no laboratório) | #248 |
| d+e2 | fases 1 e 2 no serviço `pppoe`: só o ativo responde (nem PADT), MAC virtual e portas promíscuas, AC-Cookie do par; hot standby: cada worker publica as suas sessões, a tomada as adota em Opened, contabilização contínua (o mesmo Acct-Session-Id, um Interim, nenhum Stop) | #263 |
| e1 | `proto-pppoe`: `Server::export`/`import` (a sessão em Opened no outro servidor, sem renegociar) | #253 |
| e2a | registro da sessão completo para a tomada | #255 |
| f | aba PPP › Redundancy na GUI | #251 |
| g | laboratório com dois daemons e BNG Blaster (`cargo xtask bng-lab --only ha`) | este PR (empilhado sobre o #263) |

## 1. Pesquisa

Fontes (veja também `docs/research-sources.md`):

- **MikroTik RouterOS v7:** não tem redundância de PPPoE server. O que existe é VRRP
  (`/interface vrrp`) para o gateway; uma sessão PPPoE morre com o roteador e o CPE refaz o login.
  Nada a copiar de comportamento; os nomes seguem o estilo do RouterOS (`priority`, `preemption-mode`
  do VRRP viram `priority`, `preempt`).
- **Cisco ASR 9000 (IOS XR) — BNG Geo Redundancy** ([artigo da Cisco
  Community](https://community.cisco.com/t5/service-providers-knowledge-base/asr9000-xr-using-and-understanding-bng-geo-redundancy/ta-p/3158636)):
  *Subscriber Redundancy Group* (SRG) por grupo de acesso; o mestre sincroniza o estado de cada
  sessão para o escravo por TCP (sobre o ICCP do MC-LAG); a sessão fica "sombra" e totalmente
  programada no escravo; papéis por grupo (ativo/ativo entre grupos); MAC virtual; rastreamento de
  objetos com temporizadores, sem VRRP; a configuração **não** é sincronizada (cada nó tem a sua, e
  divergência é erro do operador). Regra explícita: os dois lados nunca podem estar ativos ao mesmo
  tempo.
- **Nokia 7750 SR — PPPoE multi-chassis** ([PPPoE MC
  redundancy](https://infocenter.nokia.com/public/7750SR225R1A/topic/com.nokia.Triple_Play_Service_Delivery_Architecture_Guide/pppoe_mc_redund-d1060e15371.html),
  [modelo de sincronização](https://infocenter.nokia.com/public/7750SR227R1A/topic/com.nokia.Triple_Play_Service_Delivery_Architecture_Guide/pppoe_multi-cha-d1060e15527.html),
  [stateless](https://infocenter.nokia.com/public/7750SR227R1A/topic/com.nokia.Triple_Play_Service_Delivery_Architecture_Guide/stateless_multi-ai9jxkmbg9.html),
  [SRRP](https://documentation.nokia.com/html/0_add-h-f/93-0267-HTML/7X50_Advanced_Configuration_Guide/SRRP.html)):
  MC-Sync (MCS) copia o estado das sessões; SRRP escolhe ativo/espera por grupo, com temporizadores
  abaixo de um segundo; depois da troca o nó novo manda um MAC update gratuito; modo **stateless**:
  sem sincronizar sessões, o CPE refaz o login depois do timeout do echo; um temporizador
  *delayed-enable* dá tempo ao sync depois de um boot.
- **Juniper (MX, M:N subscriber redundancy):** cobre DHCP/IPoE; PPPoE não é suportado.
- **accel-ppp (VyOS), pfSense/OPNsense:** nada para o servidor. O que se vê na prática é CARP/VRRP
  com o CPE refazendo a sessão (segundos de queda) — o que a nossa fase 1 já melhora.
- **Normas:**
  - RFC 2516 §4: a sessão é identificada pelo SESSION_ID e pelo par de MACs (o MAC do AC tem de ser
    o mesmo no outro nó: MAC virtual).
  - RFC 1661 §6.4: o Magic-Number é único por ponta e o par descarta Echo com o número errado; o
    nó que assume reusa os **dois** números da sessão.
  - RFC 2866 §5.5 (Acct-Session-Id único e o mesmo do Start ao Stop) e RFC 2865 §5.25 (Class
    ecoado na contabilização): o nó que assume mantém os dois e não manda Stop nem Start novo.
  - RFC 5798 §7.2 (VRRP): o mestre novo anuncia o MAC virtual para os switches aprenderem a porta
    — o nosso hello de acesso faz o mesmo papel.
  - IEEE Std 802 §9.2.4: EtherType 0x88b5 (Local Experimental) para um protocolo dentro de uma
    rede, como o hello.

### O que adotamos

- Ativo/espera com **MAC virtual** e sessões sincronizadas (Cisco SRG, Nokia MCS); modo
  **stateless** também (Nokia), para quem não quer o custo do sync.
- **Configuração não sincronizada** (Cisco): cada nó tem a sua, e o par **detecta divergência**
  (o Hello leva o hash de cada seção que importa).
- **Temporizadores** de hello e de morte abaixo de um segundo e meio, *init hold* depois do boot
  (Nokia *delayed-enable*), *recover hold* e preempção com atraso (VRRP).
- Nunca dois ativos (Cisco): a regra de maioria de três com testemunha (abaixo).

### Melhorias propostas

Entram agora:

- **Cerca por maioria de três** (este nó, o par e uma testemunha, como o gateway): ninguém
  documenta isso nos BNGs pesquisados. Um nó só fica ativo se ouve o par, ou, com o par em silêncio,
  se alcança a testemunha. O ativo que perde os dois se cerca sozinho.
- **Dois caminhos para ouvir o par:** o stream de sync e um **hello autenticado na rede de
  acesso**, o mesmo L2 dos assinantes. Cortar só o link de sync não faz troca; dois nós que não se
  ouvem no acesso também não atendem os mesmos assinantes.
- **Eleição à prova de visões cruzadas:** cada hello diz qual encarnação do par ele ouve e o
  último número de visão do par que viu; o vencedor só assume quando o perdedor confirma (veja
  §2.3). O teste com 2000 sementes de falhas aleatórias achou duas corridas antes disso.
- **Troca manual (switchover)** sem dois ativos nem perda de sessão, e **"Simular falha"**: o nó
  fica mudo e cego por N segundos (para de responder e de mandar hello), o par assume de verdade, e
  ele volta como espera.
- **Detecção de divergência** de configuração e **visão de saúde do sync** (sessões N/N, atraso,
  log, snapshots, buracos).
- **Contabilização contínua:** Acct-Session-Id e Class preservados, sem Stop duplicado, um Interim
  logo depois da tomada (fase 2).

Viram gap depois: ativo/ativo por grupo de portas (Cisco SRG por grupo), mais de dois nós (M:N),
sincronização da configuração com confirmação.

### O que ficou de fora e por quê

- **Sincronizar a configuração:** a Cisco também não sincroniza; uma config errada copiada para o
  outro nó derruba os dois. A divergência é mostrada, não corrigida sozinha.
- **Testemunha com protocolo próprio (lease):** exigiria software na testemunha. O ping/ARP no
  gateway mais o hello de acesso cobrem os casos de falha simples; o caso que sobra está em §5.
- **ICCP/MC-LAG:** o nosso sync vai pelo canal de controle com TLS que já existe.

## 2. Desenho (`crates/proto-ha`, sans-IO)

### 2.1 Papéis

`Init` (escuta o par por `init_hold`, 5 s, antes de reivindicar), `Standby`, `Active`, `Fenced`
(não prova que não está isolado, porta rastreada caída, ou falha simulada: não responde nada) e
`Yielding` (switchover em andamento: já parou de responder, espera o par assumir).

| Situação | Decisão |
|---|---|
| Par ouvido e ativo | espera (se os dois ativos: fica a época maior, depois prioridade, depois id) |
| Par ouvido, ninguém ativo | eleição: réplica completa, depois prioridade, depois id; o vencedor espera a confirmação do perdedor |
| Par em silêncio nos dois caminhos por `dead` (1,2 s) | assume se alcança a testemunha (ou, sem testemunha, se o hello de acesso está ligado); senão cerca |
| Ativo com par em silêncio e sem testemunha | cerca (isolado) |
| Ativo com par ouvido e sem testemunha | continua (a testemunha morta sozinha não derruba o acesso) |
| Porta rastreada caída | cerca |
| Cercado volta | só depois de `recover_hold` (3 s) estável |

**Com BFD (G3.6h, §2.13).** O BFD é um terceiro sinal de vida em cada caminho; ele só antecipa a
detecção, e a regra de maioria com a testemunha não muda:

| Situação | Decisão |
|---|---|
| BFD expira (diagnóstico 1: os pacotes do par pararam) em **todos** os caminhos em uso, antes do `dead` | o espera sonda a testemunha na hora; assume só com uma resposta **posterior** à detecção. Sem resposta, espera: quando o `dead` dos hellos vence, vale a tabela de cima |
| BFD expira num caminho só | nada: o outro caminho ainda ouve o par |
| BFD num caminho só configurado (com `fencing` usando o acesso) | nada antecipa: o hello do outro caminho ainda precisa do `dead` |
| O par anuncia Down (AdminDown, diagnóstico 3) ou a sessão nunca subiu | não conta: o par está vivo e falando; só os hellos decidem |
| Hello chega até `dead` depois de uma perda de BFD | alarme falso: o caminho revive e leva uma segunda penalidade |
| Penalidade do caminho ≥ `suppress` (3 perdas em ~15 s, ou uma perda falsa e mais uma) | o BFD desse caminho é ignorado (amortecido) até a penalidade cair abaixo de `reuse`; só os hellos decidem |
| Ativo com o par mudo pelo BFD e sem testemunha | como antes: cerca pelo estado da testemunha com debounce (3 faltas); o BFD não cerca mais cedo |
| Falha simulada / Testar tomada (método falha) | este nó para também as sessões BFD do par (somem sem AdminDown): o par vê uma queda de verdade |

Toda tomada aumenta a **época**; ela desempata um split-brain visto depois de uma partição (fica a
tomada mais recente, que tem as sessões novas).

### 2.2 Sync (hot standby)

- **Stream** = uma história da tabela (id aleatório escolhido quando um nó vira ativo); cada mudança
  tem o próximo **número de sequência**. Operações idempotentes: registro inteiro (upsert), remoção,
  contadores absolutos.
- Réplica que conecta com o mesmo stream e uma posição que o **log** do ativo ainda tem continua de
  lá; qualquer outra recebe um **snapshot** (a tabela em pedaços na sequência `base`) e depois os
  deltas.
- **Ack** em lote (1024 operações ou 20 ms); **buraco** na sequência pede **resync** a partir do
  primeiro número que falta (ou snapshot, se o log já não tem).
- Memória limitada: log por bytes (32 MiB), saída pelo orçamento de bytes que o socket aceita.

### 2.3 Eleição sem visões cruzadas

Uma decisão tomada com a visão velha do par pode cruzar com a decisão dele em voo (os dois se
acham vencedores). Três campos em todo hello evitam isso:

- `incarnation`: aleatório por início do processo;
- `hears`: a encarnação do par que o remetente ouve agora;
- `view_seq` / `acked`: o número da visão do remetente (muda quando o papel ou a elegibilidade
  muda) e o último número da visão do par que ele viu.

O vencedor de uma eleição só assume quando o par diz "espera (ou não posso atender), ouço *você*,
e vi a sua visão atual". O perdedor anuncia a espera na hora. Assim a tomada demora no máximo uma
ida e volta a mais, e nunca há dois vencedores.

### 2.4 Formatos

**Stream de sync** (sobre TLS no canal de controle): `"CRHA" | versão | tipo | reservado | tamanho
(LE) | conteúdo`, até 1 MiB por quadro. Mensagens: Hello (versão, nó, época, papel, prioridade,
modo, stream, posição, hashes das seções), Heartbeat, SnapshotBegin/Chunk/End, Delta, Ack, Resync,
Handover, HandoverRequest. Versão ou tipo desconhecido fecha o stream.

**Registro da sessão** (TLV, tipo u8 + tamanho u16): núcleo (porta, tags, TPID, SID, MAC do
cliente, MAC do AC, início), LCP (os dois Magic-Numbers, MRU dos dois lados), autenticação,
usuário, Service-Name, IPv4 e DNS, identificadores IPv6CP, /64 e prefixo delegado, rate-limit,
timeouts, circuit-id/remote-id (RFC 4679), Acct-Session-Id, Class, intervalo de Interim, perfil,
servidor, pool, address-list, contadores. Tipos desconhecidos são guardados e reescritos (versão
nova sincroniza com antiga); tipo repetido é erro.

**Hello de acesso** (Ethernet, EtherType 0x88b5, destino `03:43:52:48:41:00`): nó, encarnação,
sequência, `hears`, `view_seq`, `acked`, época, papel, prioridade, flags (testemunha, em sync,
elegível) e HMAC-SHA-256/128 com chave derivada do segredo do par. O ativo manda do **MAC
virtual**: todo hello é também o MAC update gratuito. Repetição recusada por encarnação e
sequência.

## 2.5 O serviço `ppp-ha` do daemon (PR c)

- **Link de sync:** TLS na `listen_port` (o certificado do próprio roteador, o mesmo do canal de
  controle) e um discador para `peer`. Fica só a conexão discada pelo nó de **id menor** (o id é
  um hash do certificado de cada roteador, que o discador vê no handshake), então o par tem um
  link só. O certificado do par é fixado no primeiro uso (`ppp-ha-peer.fingerprint` na pasta de
  config). Sobre o TLS, o `Node` autentica as duas pontas com o segredo (desafio e prova HMAC).
- **Hello de acesso:** um socket `AF_PACKET` (0x88b5) por porta de acesso, com allmulticast como o
  LLDP; do MAC virtual enquanto ativo.
- **Testemunha:** um eco ICMP por endereço por segundo; cai depois de 3 faltas seguidas, volta na
  primeira resposta. **Track:** as portas da lista precisam estar com portadora.
- **Locks:** o `Node` fica atrás de um mutex que cada thread pega rápido e nunca durante E/S (o
  laço principal a cada 10 ms, a thread da conexão, os comandos). O serviço `pppoe` lê só
  atômicos (`ppp_ha::shared`: responder ou não, MAC virtual, chave do cookie).
- **Teste em namespace** (`tests/netns_ha.rs`, dois daemons, sem root), **medido** em debug:
  - par formado em 762 ms;
  - switchover em 53 ms;
  - failover depois de matar o ativo em 1,16 s (morte 1,2 s);
  - o nó isolado (os dois links e a testemunha perdidos) se cerca e o outro assume.

## 2.6 A aba PPP › Redundancy (PR f)

À esquerda, a configuração (`ppp.redundancy.get/set`): par (TLS), modo, segredo (só de escrita:
o campo vazio não muda nada), prioridade, preempção, MAC virtual, grupo, portas de acesso, cerca,
testemunha, track e temporizadores; Apply manda só o que mudou. À direita, o par agora
(`ppp.redundancy.monitor`):

- o papel deste nó em selo colorido (active verde, standby azul, fenced vermelho, init/yielding
  âmbar) e a época;
- o par: papel, TLS, e os caminhos em que é ouvido (link de sync, acesso);
- a testemunha;
- o sync: sessões N/N, pendentes, atraso e o snapshot em andamento;
- a divergência de config, uma seção por selo;
- as últimas trocas de papel, com o motivo e "sessions kept".

**Switchover** e **Simulate Failure** pedem confirmação. Todo rótulo tem ⓘ com a explicação em
português. Conferido com dois daemons reais num namespace (switchover, falha simulada de 30 s e
volta como standby), nos temas escuro e claro.
## 2.7 A sessão PPPoE de um servidor para outro (PR e1)

`proto_pppoe::server::ha`: `Server::export_all(now)` dá o `SessionState` de cada sessão
estabelecida, e `Server::import(now, states)` as recria no outro servidor já em **Opened** no LCP,
no IPCP e no IPv6CP, sem mandar nada. Ficam o SID, o par de MACs, os dois Magic-Numbers, o MRU dos
dois lados, o protocolo de autenticação, o endereço, o DNS, os identificadores IPv6CP, o
rate-limit e o que falta do Session-Timeout. O keepalive recomeça da tomada; uma renegociação
pedida pelo CPE segue normal. A lista de SIDs livres é refeita uma vez por lote (O(n)).

- **Teste** (`tests/ha.rs`):
  - 1000 assinantes (MS-CHAPv2, PAP e CHAP, IPv4 e IPv6, dois shards) passam para servidores novos
    e ficam 2 minutos de keepalive de pé, sem relogar e sem queda;
  - o export do servidor novo é idêntico ao do antigo (a mutação de um magic reprova);
  - com 5 % de perda depois da tomada, as sessões aguentam;
  - SID ocupado ou de outra lane é recusado.
- **Medido** (release): export de 74 ns e import de 242 ns por sessão (20 mil em 1,5 ms e 4,8
  ms): 100 mil num núcleo ≈ 25 ms; por worker, em paralelo.

## 2.8 Fase 1 no serviço `pppoe` (stateless)

- **Só o ativo fala.** Fora do papel ativo, o worker não entrega quadro nenhum ao BNG e descarta o
  que ele quisesse mandar. Isso inclui o PADT que o `proto-pppoe` manda a quadro de sessão
  desconhecida: no standby, esse PADT derrubaria o CPE que está no ativo. Um nó que acaba de ligar
  fica mudo até o par decidir (`HA_ACTIVE` começa falso).
- **MAC virtual.** Com a redundância ligada, o AC MAC de todos os servidores é o MAC virtual
  (PADO, PADS e sessões). O `ppp-ha` põe as portas de acesso em modo promíscuo enquanto as tem
  abertas, para receber os quadros endereçados a ele. O hello do ativo, mandado do MAC virtual,
  ensina a porta aos switches.
- **AC-Cookie do par.** A chave vem do segredo do par, e o cookie deixa de amarrar o índice da
  porta, que muda entre as máquinas. Assim, um PADR em voo numa troca entra no novo ativo
  (`ServerConfig::cookie_secret`).
- **Ao perder o papel**, o nó encerra as sessões sem mandar nada ao CPE. No modo stateless manda
  Acct-Stop; no hot standby, não (abaixo).
- **Medido** (debug, `tests/netns_ha_pppoe.rs`, dois daemons reais e 200 CPEs `proto-pppoe` com
  keepalive de 1 s × 3): o standby não atende ninguém e não derruba ninguém em regime; morto o
  ativo, as 200 voltam no outro nó em 4,9 s (morte em 1,2 s, mais o keepalive do CPE de 3 s, mais o
  login).

## 2.9 Fase 2 no serviço `pppoe` (hot standby)

- **Publicar.** Cada worker marca a sessão que mudou: subida, CoA de rate-limit, IPv6, rotas. A
  cada volta do laço ele monta o `SessionRecord` (proto-pppoe `export` mais o estado do BNG) e o
  entrega ao publicador do `ppp-ha`. A remoção vai no fim da sessão; os contadores, a cada 10 s.
  O custo é O(1) por mudança, e nada se refaz por sessão a cada tick.
- **Tomar.** Ao virar ativo com a réplica completa, o `ppp-ha` entrega os registros aos workers
  **antes** de liberar o "responder". Um quadro de sessão ainda não adotada levaria PADT, por isso
  cada worker só responde depois de adotar a sua parte (`ha_pending`). A adoção, por worker e em
  paralelo, faz:
  - `Server::import` (Opened, sem quadro);
  - o endereço reservado no pool;
  - a entrada no XDP ou a rota do caminho lento;
  - as rotas da G4.3cd;
  - a tabela ativa, com os contadores herdados como base;
  - a address-list;
  - uma linha `up`/`takeover` no histórico;
  - um **Interim-Update** com o mesmo Acct-Session-Id e os contadores.
  
  O serviço RADIUS agenda os Interims seguintes a partir desse (antes, só a partir do Start).
  Os ganchos `on_up` não rodam de novo.
- **Entregar.** O nó que perde o papel em hot standby encerra as suas cópias sem Acct-Stop e sem
  `on_down`: a sessão continua no par.
- **Mesmo número de workers nos dois nós.** Os quadros de um CPE chegam ao worker do hash do MAC, e
  o SESSION_ID dele é desse worker. Por isso o número de workers entra na divergência
  (`pppoe.workers`), e uma sessão que não cabe é contada e registrada no log.
- **Medido** (debug, `tests/netns_ha_pppoe.rs`): morto o ativo, as 200 sessões estavam no outro nó
  em 1,22 s, e **nenhum** CPE caiu em 10 s de keepalive. Unidade (`pppoe_ha_tests.rs`): 200
  sessões adotadas por outro `Bng`, 2 minutos de keepalive dele, 0 PADT, os mesmos logins,
  endereços, SIDs e Acct-Session-Id.

### Achado: Acct-Session-Id repetido entre workers

O laboratório achou um defeito anterior à G4.3h. O Acct-Session-Id era `hora + contador`, e
cada worker do `pppoe` (G4.3g) tem o seu contador: dois workers davam o mesmo id no mesmo
segundo. Em 1000 logins houve 213 ids distintos. Isso viola a RFC 2866 §5.5, que pede o id único,
e quebra também o CoA por Acct-Session-Id. Agora o id leva a lane do worker; o laboratório
confere que todos os Starts têm ids distintos.

## 2.10 Laboratório (`cargo xtask bng-lab --only ha`, PR g)

Três namespaces: o nó A, o nó C e o BNG Blaster (com `--root`, nomeados por `ip netns`: o
carregador XDP lê o `/sys` do namespace). Duas bridges (acesso e uplink), o link de sync, a
testemunha e um servidor RADIUS de teste num link que continua de pé. Com todas as sessões em A e a
réplica de C completa, **A perde a energia**: todas as portas caem ao mesmo tempo. Sem root, na VM
(caminho lento; o tráfego de 1 pps vai em todas as sessões até 2000, e acima disso numa amostra de
500).

**Medido** (VM `corerouter-lab`, 8 vCPUs, kernel 7.0, release, BNG Blaster 1.0.1, 2026-10-26,
`cargo xtask vm-lab run -- cargo xtask bng-lab --only ha --scales 1000,10000,100000`; CHAP pelo
RADIUS de teste, keepalive do BNG Blaster de 5 s × 3):

| Sessões | Tomada | Tráfego de subida de volta | Sessões perdidas | No nó novo | Starts (ids únicos) | Stops na tomada | Com Interim do nó novo |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 000 | 1,13 s | 1,14 s | 0 | 1 000 | 1 000 (1 000) | 0 | 1 000 |
| 10 000 | 1,12 s | 1,14 s | 0 | 10 000 | 10 000 (10 000) | 0 | 10 000 |
| 100 000 | 1,15 s | 1,29 s | 0 | 100 000 | 100 000 (100 000) | 0 | 100 000 |

Com root (`--root`: XDP genérico nas portas dos dois nós, e as sessões adotadas programadas nos
mapas do nó novo), **medido** na mesma VM:

| Sessões | Plano | Tomada | Tráfego de subida de volta | Sessões perdidas | Starts (ids únicos) | Stops | Com Interim do nó novo |
|---:|---|---:|---:|---:|---:|---:|---:|
| 1 000 | XDP | 1,23 s | 1,25 s | 0 | 1 000 (1 000) | 0 | 1 000 |
| 10 000 | XDP | 1,24 s | 1,27 s | 0 | 10 000 (10 000) | 0 | 10 000 |
| 100 000 | XDP | 0,99 s | 1,12 s | 0 | 100 000 (100 000) | 0 | 100 000 |

A tomada é quase toda a espera pela morte do par (1,2 s, 4 hellos de 300 ms). Adotar 100 mil
sessões quase não aparece no tempo: 1,15 s contra 1,13 s com mil. O import do `proto-pppoe` custa
242 ns por sessão (#253), dividido entre os workers. Nenhum assinante percebeu a troca (0 flaps no BNG
Blaster), e a contabilização seguiu com os mesmos ids, sem Stop. No A/B da mesma VM, um nó sozinho
sobe as mesmas 100 mil em 33 s.

O tráfego de descida depende do protocolo de roteamento que anuncia o pool pelo nó ativo, fora do
laboratório (gap G4.3hf).

## 2.11 CoA e Disconnect pelo par (G4.3hb)

O servidor RADIUS manda o CoA/DM ao NAS que conhece. Depois de uma tomada, esse NAS pode ser o
nó que já não tem a sessão. Agora:

- O `/radius incoming` de cada nó aplica o pedido nas sessões dele, como antes.
- Se nenhuma sessão é dele, e este nó não é o que atende os assinantes (espera, cercado, cedendo),
  o pedido decodificado vai ao par pelo link de sync (`Msg::Forward`, JSON do `CoaRequest`, até
  64 KiB). Os donos de sessão do par o aplicam, e nunca o encaminham de novo. A resposta volta
  (`Msg::ForwardReply`), e este nó responde ao servidor com o que o par disse (ACK, ou NAK com o
  Error-Cause do par). A RFC 5176 §3.3 pede a resposta do endereço para onde o servidor mandou: por
  isso quem responde é o nó antigo, e não o par.
- O par também não tem a sessão: NAK 503 (Session Context Not Found), como sem par. O par não
  responde em 2 s: NAK 505 (Other Proxy Processing Error, §3.5). Sem link de sync: NAK 503 na
  hora.
- Uma retransmissão do servidor enquanto o par responde não é encaminhada de novo: vai a resposta
  do primeiro, e as seguintes saem do cache, como sempre.
- Até 1024 pedidos encaminhados em voo; acima disso, NAK 503 na hora.
- Compatível com a versão anterior do par: o Hello leva os recursos (`features`) nos bytes
  reservados do cabeçalho, que a versão antiga ignora. O `Forward` só vai a um par que anunciou
  o recurso.
- O ativo não encaminha: ele tem todas as sessões, e perguntar ao standby só atrasaria o NAK.
- `radius.incoming.get` mostra `forwarded` e `forward_answered`.

**Medido** (debug, `tests/netns_ha_pppoe.rs`, dois daemons reais, 200 CPEs):

- CoA de taxa por Framed-IP-Address no ativo: 0,19 ms.
- Depois de um switchover, o mesmo CoA mandado ao nó antigo: mediana de 40 ms e máximo de 50 ms
  em 20 pedidos. O nó novo aplica a taxa, e um Disconnect pelo nó antigo encerra a sessão no novo.

Os 40 ms são as esperas dos laços, não trabalho:
- até 20 ms do read da conexão de sync antes de escrever o que saiu;
- até 10 ms do laço principal, em cada ponta.

O trabalho em si custa 0,25 ms ponta a ponta, medido com o par em memória
(`radius_aaa_tests`). Os pedidos andam em paralelo: uma rajada não espera um pelo outro (veja o
laboratório).

## 2.12 IPoE no par (G4.3hd)

As sessões IPoE (G4.3f) entram no hot standby como as PPPoE:

- **Publicar.** O ativo publica cada sessão IPoE com a concessão DHCP dela: um `SessionRecord` de
  `Kind::Ipoe`, com os TLVs novos `LEASE*` (fim, duração, última mensagem, client id da opção 61,
  opção 82, `hw`, nome). Ele vai quando a sessão sobe e a cada renovação; os contadores vão a cada
  10 s. A versão anterior guarda esses TLVs como desconhecidos. Um registro tem ≈ 123 B.
- **Calar o standby.** O servidor DHCP do standby fica mudo nas portas dos servidores com sessões
  (`IpoeBackend::answering`): descarta o que ouve, não pergunta ao RADIUS e não oferece nada. Um
  nó que acaba de ligar começa mudo até a configuração dizer se há par. As portas IPoE do
  standby ganham `arp_ignore=8`: os dois nós têm o endereço do gateway, e só o ativo responde ARP.
  Um roteador sem par não tem o `arp_ignore` tocado.
- **Tomar.** Ao virar ativo, o serviço `ipoe` adota as sessões da tomada **antes** de liberar o
  DHCP:
  - a sessão volta com o mesmo Acct-Session-Id, o mesmo Class, a taxa e as rotas;
  - a entrada no XDP;
  - uma linha `up`/`takeover` no histórico;
  - um Interim-Update com os contadores herdados, sem Start.
  
  As concessões entram no servidor DHCP (`Server::adopt`, no journal também). As concessões
  ligadas deste nó que o par não conhece terminam: a tabela do par é a mais nova. Assim a renovação
  do cliente (RFC 2131 §4.3.2) encontra a concessão como no nó que a deu.
- **Apontar o ARP do CPE.** O nó novo manda um ARP ping a cada assinante adotado, com o endereço do
  gateway como remetente. Pela RFC 826, quem já tem o remetente na tabela atualiza o MAC dele.
- **Entregar.** O nó que perde o papel encerra as cópias sem Acct-Stop. No modo stateless manda
  o Stop: o cliente refaz o DHCP no outro.

### Pesquisa

- **DHCP failover** ([draft-ietf-dhc-failover-12](https://datatracker.ietf.org/doc/html/draft-ietf-dhc-failover-12),
  ISC Kea HA [hot-standby](https://kb.isc.org/docs/kea-ha-quickstart-guide)):
  - o par copia cada concessão (o *binding update*) antes ou logo depois do ACK;
  - o standby não responde ao cliente enquanto o primário vive;
  - na tomada, o parceiro atende as renovações das concessões que recebeu;
  - o MCLT limita quanto um servidor estende uma concessão que o outro ainda não sabe.
  
  Aqui o par copia a concessão a cada renovação. O que se perde numa queda são só as mudanças sem
  ack (milissegundos): um cliente que renovou nesse intervalo tem, no nó novo, a concessão com o
  fim de antes da renovação, ainda válida por pelo menos meio lease (T1). Por isso não precisamos
  do MCLT.
- **Cisco ASR 9000, IPoE L2 com geo redundancy**
  ([artigo](https://community.cisco.com/t5/service-providers-knowledge-base/bng-geo-redundancy-for-l2-connected-ipoe-subscriber-sessions/ta-p/3686641)):
  a sessão IPoE e a concessão vão ao escravo pelo SRG, o gateway é um endereço e um MAC virtuais do
  grupo, e o escravo não responde DHCP nem ARP. Juniper M:N cobre DHCP/IPoE do mesmo jeito.
- **MikroTik RouterOS v7:** sem redundância de servidor DHCP nem de sessão IPoE (VRRP para o
  gateway e o cliente refaz o DHCP).

**Medido:**
- Release, `cargo bench -p corerouter-daemon --bench ipoe_bng -- ipoe_ha`, Ryzen AI Max+ 395,
  2026-10-27, máquina com outras sessões:

  | | 10 000 | 100 000 |
  |---|---:|---:|
  | adoção no serviço `ipoe` (sessões, XDP, Interims) | 29,7 ms (3,0 µs/sessão) | 623 ms (6,2 µs/sessão) |
  | concessões no servidor DHCP (`Server::adopt`) | 2,6 ms | 74 ms |
  | publicar (renovar todas e montar os registros) | 20 ms | 300 ms |

- O lock do núcleo IPoE é pego em lotes de 1024 (≈ 8 ms cada), não pelos 0,6 s inteiros. A
  primeira versão segurava o lock 774 ms com 100 mil.
- Laboratório (VM `corerouter-lab`, release, sem root, BNG Blaster 1.0.1, 2026-10-27,
  `env BNG_LAB_HA_IPOE=1 cargo xtask bng-lab --only ha`), A perde a energia:

  | Sessões IPoE | Tomada | Todas no nó novo | Perdidas | Starts | Stops | Com Interim do novo | Renovaram no novo |
  |---:|---:|---:|---:|---:|---:|---:|---:|
  | 1 000 | 1,03 s | 1,14 s | 0 | 1 000 | 0 | 1 000 | todas (lease de 2 min, 75 s depois) |
  | 3 000 | 1,23 s | 1,35 s | 0 | 3 000 | 0 | 3 000 | todas |

  Acima de ≈ 5 mil, o BNG Blaster não completa a subida do IPoE nem num nó sozinho, sem par. Ele
  repete cada DHCP a cada 5 s, ≈ 19 mensagens por cliente, enquanto o servidor responde até 3100
  ACKs/s. Por isso a adoção de 10 mil e 100 mil vem do benchmark (gap G4.3fb).

## 2.13 BFD no par (G3.6h)

Aprovado pelo usuário em 2026-10-28 (mockup da janela PPP › Redundancy). O BFD (RFC 5880/5881,
o nosso motor em Rust da G3.6, o mesmo do `/routing bfd`) entra como **terceiro sinal de vida**
nos dois caminhos do par. A detecção cai de 1,2 s (4 hellos) para o tempo de detecção do perfil
(`fast`: 50 ms × 3 = 150 ms); a decisão de assumir continua a mesma (tabela em §2.1).

### Pesquisa

- **Cisco ASR 9000 (BNG Geo Redundancy, SRG):** o par se acompanha por uma sessão TCP/sync e pela
  rota de controle de estado; o BFD protege essa rota e o peering. Um caso no fórum da Cisco: com
  a energia cortada, a troca levou 2–3 min porque a sessão BFD foi a *AdminDown* em vez de expirar,
  e o BGP só caiu no timeout do TCP
  ([community.cisco.com](https://community.cisco.com/t5/xr-os-and-platforms/bng-geo-redundancy-no-sub-second-failover-after-power-failure/m-p/3696820)).
  Lição adotada: só a **expiração** (diagnóstico 1) conta como morte; AdminDown não, e o hello
  continua como rede de segurança.
- **Juniper MX (M:N subscriber redundancy):** o primário passa as ligações ao backup por TCP, e a
  troca vai pela redundância de pseudowire; o BFD aparece como verificação de sessão, sem
  descrição de como acelera a troca
  ([juniper.net](https://juniper.net/documentation/us/en/software/junos/subscriber-mgmt-sessions/topics/topic-map/m-to-n-subscriber-redundancy.html)).
- **Nokia 7750 (MC-LAG + SRRP, MCS):** o par fala por UDP 1025 entre os system addresses; o SRRP
  segue o MC-LAG. O BFD é documentado para VRRP e para LAG, não para o peering MC
  ([MC-LAG and SRRP](https://infocenter.nokia.com/public/7750SR222R1A/topic/com.nokia.Interface_Configuration_Guide/mc-lag_and_subs-d10e14929.html)).
- **VRRP com BFD** (draft-ietf-rtgwg-vrrp-bfd-p2p, atualiza a RFC 9568, trabalho em andamento):
  BFD ponto a ponto só entre o ativo e o backup crítico, detecção na faixa de 150 ms, e *o BFD
  sempre volta à falha normal do VRRP*
  ([datatracker](https://datatracker.ietf.org/doc/draft-ietf-rtgwg-vrrp-bfd-p2p/)). É o mesmo
  desenho daqui: o BFD antecipa, o hello continua sendo o piso.
- **RFC 5880 §6.8.4 e errata:** a errata 6926 (verificada) manda manter o diagnóstico em
  *Control Detection Time Expired* quando os pacotes param, mesmo que o par tenha anunciado
  AdminDown antes; a 5205 está retida para revisão
  ([errata](https://www.rfc-editor.org/errata/rfc5880)). A RFC 5881 (salto único, TTL 255) já é
  seguida pelo motor. RFC 5882 §3.2 pede amortecer os clientes de uma sessão que oscila.
- **MikroTik RouterOS v7:** não tem redundância de PPPoE server; o BFD existe para BGP/OSPF.

**O que adotamos:** sessões BFD do nosso motor (sem processo externo) ao endereço de sync do par e
ao endereço do par no acesso; só a expiração conta; confirmação **fresca** da testemunha antes de
assumir; amortecimento por caminho com o perfil do BFD; linha do tempo de cada tomada; o
"Testar tomada" e o alerta preventivo de jitter.

**Melhorias além dos outros:** a resposta da testemunha *depois* da detecção (nenhum dos BNGs
pesquisados documenta isso; fecha a janela em que um espera isolado assume com o estado velho da
testemunha); o alarme falso (BFD perdido com o hello passando) custa penalidade dobrada; o teste
de tomada lê o resultado do par pelo link de sync; a linha do tempo medida em cada nó.

**Fora, e por quê:** BFD echo (o motor não tem; o assíncrono a 50 ms já dá 150 ms); BFD sobre
IPv6 link-local no acesso (a chave da sessão não tem interface: use um endereço global ou um /30
numa VLAN de gerência); acelerar a cerca do ativo isolado pelo BFD (uma resposta perdida da
testemunha derrubaria o acesso de todos: fica o debounce de 3 s, como antes).

### Como funciona

- **Config:** `ppp.redundancy.set bfd=fast access_bfd=fast access_peer=<ip>`. O `peer` precisa
  ser um endereço para o BFD do sync. `get` mostra `detection_ms`: o BFD quando todos os caminhos
  em uso têm BFD, senão o `dead`. Mudar o BFD não recria a máquina de papéis (um nó recriado
  volta a `init` e para de responder).
- **Sessões:** o serviço `bfd` acrescenta as do par ao que já roda (peers, rotas com
  `check_gateway=bfd`), também no modo data plane do `bfdd`.
- **Sem lock do `Session` no caminho da decisão:** a thread do motor BFD chama um *tap* (um
  ponteiro de função nas `Options` do motor) na mudança de estado; ele só põe numa fila de 256 e
  acorda o laço do `ppp-ha`. O laço entrega à máquina de papéis, que pede uma sonda à thread da
  testemunha (acordada na hora, espera de 200 ms); a resposta acorda o laço de novo. Nada disso
  passa pelo lock do engine nem pelo laço do serviço `bfd`.
- **Linha do tempo** (`ppp.redundancy.monitor` → `takeovers`), em ms desde o último sinal de vida
  do par (o último pacote BFD, ou o último hello): detectado, testemunha, ativo, anunciado (o
  primeiro hello do MAC virtual), adotadas (o último worker que adotou a sua parte), 1º quadro de
  assinante; sessões entregues, adotadas, que não couberam, e perdidas (as que o par tinha e a
  réplica não, mais as que não couberam).
- **Testar tomada** (`ppp.redundancy.test-takeover`): sem `confirm` só roda as verificações (este
  nó ativo, o par de espera, em sync e alcançando a testemunha, os dois caminhos ouvidos, o BFD de
  pé e não amortecido, a config igual). Com `confirm=takeover`, o método `failure` deixa este nó
  mudo por N segundos (sem respostas, sem hellos, sem BFD); o par detecta como uma queda. A cada
  2 s este nó pergunta ao par a última tomada dele (`Msg::Forward` com `{"ha":"last-takeover"}`:
  um par sem a G3.6h responde 404, porque o pedido não é um CoA válido) e dá o veredito: `passed`
  com 0 perdidas.
- **Alerta preventivo:** p99 do intervalo entre os pacotes do par ≥ 2/3 do tempo de detecção (dois
  dos três pacotes da janela faltando: mais uma perda seguida derruba a sessão), este nó mandando
  BFD atrasado (p99 ≥ 1/3 da detecção: CPU) e caminho amortecido. Cada alerta vai uma vez ao log.
- **Janela PPP › Redundancy:** BFD (sync), BFD (acesso) com o endereço do par, Detecção; à
  direita, o BFD por caminho (estado, perfil, detecção, p99, amortecido), a idade da resposta da
  testemunha, os alertas, o resultado do teste, a linha do tempo em selos encadeados e a última
  tomada do par; **Testar tomada** mostra as verificações e só roda depois de digitar `takeover`.
  Conferida com dois daemons reais num namespace, temas claro e escuro.

### Medido

- **Laboratório em memória** (`tests/sim_bfd.rs`, release): morto o ativo com 20 mil sessões, o
  espera assume em **155 ms** simulados (BFD 150 ms + a sonda da testemunha), 0 perdidas; 300
  sementes de falhas aleatórias com BFD e perdas de BFD com o hello passando: **nunca** dois ativos
  que se ouvem.
- **Dois daemons reais** (`tests/netns_ha_bfd.rs`, debug, namespace, sem assinantes): detectado
  em 150 ms, testemunha em 150–154 ms, ativo em **150–154 ms** depois do último sinal de vida
  (antes do laço acordar pelo evento: 160 ms); o teste de tomada passa e o nó de origem lê o
  resultado do par.
- **Motor BFD:** o tap ouve a perda 117 ms depois de o par parar (detecção de 150 ms contada do
  último pacote recebido), na thread do motor.
- **VM com BNG Blaster:** tabela abaixo.

## 3. Testes

- Unidade (27): cada regra da máquina de papéis, codec, registro, hello, sync.
- `tests/sim.rs`, dois nós em memória com o codec de verdade, latência, cortes, perdas:

| Simulação | Confere |
|---|---|
| 100 mil sessões sincronizam e o ativo morre | snapshot em 145 ms simulados, troca em 1175 ms (morte 1200 ms), **0 de 99 373 perdidas**; o nó volta como espera com cópia completa |
| morte no meio da carga | só diferem as mudanças em voo (20 de 184 não confirmadas) |
| só o sync ou só o acesso cortado | nenhuma troca |
| partição total com os dois na testemunha | cada um atende a sua metade; na cura, um sai em ≤ 400 ms (fica a época maior) |
| ativo isolado (sem par e sem testemunha) | cerca-se; o par assume com 0 perdidas; volta como espera |
| espera sem testemunha | não assume; assume depois do `recover_hold` quando volta |
| 20 quedas do link de sync com carga | todas retomam pelo log, 0 snapshot, 0 buraco |
| switchover ida e volta (50 mil) | troca em ≤ 20 ms, 0 perdidas, nunca dois ativos |
| simular falha | o par assume; o nó volta como espera |
| preempção | a prioridade maior retoma depois do atraso, em sync |
| BFD 50 ms × 3 nos dois caminhos, o ativo morre (G3.6h, `tests/sim_bfd.rs`) | troca em 155 ms simulados, 0 de 20 000 perdidas, a detecção marcada como BFD e a testemunha respondendo depois dela |
| BFD só no sync, ou espera isolado sem testemunha | espera o `dead` dos hellos / não assume |
| BFD perdido com o hello passando, 6 vezes | no máximo uma troca; os dois caminhos amortecidos; 60 s depois o BFD volta a valer |
| falhas aleatórias com BFD e perdas de BFD (300 sementes) | **nunca** dois ativos que se ouvem |
| falhas aleatórias (2000 sementes × 120 eventos: morte, reinício, cortes, testemunha, porta, switchover, simular falha, 2 % de perda no acesso) | **nunca** dois ativos que se ouvem; tudo converge para um ativo com a espera em sync |

  O vigia do laboratório foi conferido por mutação: com o ativo nunca cedendo num split-brain, dois
  testes reprovam.
- `tests/fuzz.rs`: bytes aleatórios e quadros reais com bits trocados e cortes no deframer, no
  decodificador de cada tipo, no registro e no hello; ida e volta de registros e mensagens gerados,
  com o stream partido em qualquer ponto. `HA_FUZZ_CASES=N`. libFuzzer: `cd crates/proto-ha/fuzz
  && cargo +nightly fuzz run -s none stream` (alvos `stream`, `record`, `hello`).

## 4. Desempenho e paralelismo

**Medido** (`cargo bench -p corerouter-proto-ha --bench ha`, Ryzen AI Max+ 395, release,
2026-10-26):

| Caminho | Número |
|---|---|
| codificar um registro de sessão | 48 ns (161 B) |
| decodificar um registro | 99 ns |
| 2048 mudanças publicadas, codificadas, decodificadas e aplicadas na réplica | 2,06 ms (≈ 1 µs por mudança, montagem do registro incluída: ≈ 1 milhão por segundo num núcleo) |
| snapshot de 100 mil sessões, ponta a ponta | 55 ms (0,55 µs por sessão), 21 MiB no fio (216 B por sessão) |
| hello de acesso (HMAC, codificar + conferir) | 372 ns |
| memória da réplica | 400 B por sessão (40 MiB para 100 mil) |
| memória do publicador (tabela + log) | 389 B por sessão |

- **Trabalho por item:** O(1) por mudança (mapa com chave inline de 32 B, sem alocação por chave;
  o valor é um `Arc` compartilhado entre a tabela e o log). Nenhum custo cresce com o total, exceto
  o snapshot (O(n) por definição, só no início ou depois de uma queda longa) e a lista de chaves que
  ele copia (33 B por sessão).
- **Banda:** uma mudança custa ≈ 182 B (upsert) ou 50 B (contadores). Um BNG de 100 mil assinantes
  com 2000 logins/logouts por segundo e contadores a cada 10 s gasta ≈ 0,4 MB/s + 0,5 MB/s: menos de
  1 % de 1 Gbit/s (**estimado**). O snapshot inteiro passa em 0,2 s a 1 Gbit/s.
- **Threads:** a sincronização cabe num núcleo com folga: 1 milhão de mudanças/s, contra
  ≈ 94 mil sessões/s que o BNG monta (G4.3d). Um stream por worker evitaria o lock do par, mas
  não precisou: o worker não espera por ele (abaixo).
- **A tomada** importa em paralelo: cada worker adota as sessões da sua lane.
- **A máquina de papéis** é uma só por nó: decisão global, custo desprezível.

### BFD no par (G3.6h)

- **Trabalho por item:** nenhum por sessão de assinante. O custo é por mudança de estado do BFD
  (um mutex de uma lista de até 2 endereços, uma fila de 256) e por tomada (O(1) para a linha do
  tempo; a adoção continua dividida entre os workers). O worker do `pppoe` faz uma leitura atômica
  relaxada por quadro (o "1º quadro" da linha do tempo): ≈ 1 ns (**estimado**; a linha de cache é
  só lida fora de uma tomada).
- **Threads:** a detecção roda na thread do motor BFD (a roda de temporizadores dele, G3.6), a
  decisão no laço do `ppp-ha` (acordado pelo evento), a sonda na thread da testemunha. Nenhuma
  espera o lock do `Session` nem o laço do serviço `bfd` (que pega o lock para o histórico). O
  par tem 2 sessões BFD: mais threads não ajudam; o motor já é multithread para os milhares de
  sessões de BGP/OSPF.
- **Filas:** eventos do BFD (256), respostas ao par (1024), logs (256): todas limitadas.
- **Medido:** detecção → ativo em 0–4 ms (laço acordado pelo evento), contra 10 ms com o tique de
  10 ms (`tests/netns_ha_bfd.rs`, debug).

### No serviço `pppoe` (fase 2)

**Medido** com `cargo bench -p corerouter-daemon --bench pppoe_bng` (release, Ryzen AI Max+ 395,
2026-10-26, com outras sessões na máquina: load 14–19, mediana de 3 execuções):

- **Cada worker publica as suas mudanças a cada rodada.** Por sessão, um registro de ≈ 200 B.
  Montar 1000 sessões custa 15–18 ms com e sem hot standby: a diferença fica dentro do ruído.
- **O lock do par pode ficar ocupado por milissegundos**: a thread do sync codifica até 4 MiB por
  volta num snapshot. O worker que esperasse por ele pararia de atender os assinantes. Por isso o
  `publish` usa `try_lock`. Lock ocupado: as mudanças voltam para a fila do worker
  (`ha_requeue`) e saem na rodada seguinte, na mesma ordem. O worker só espera passadas 65 536
  mudanças na fila, o limite de memória. 40 mil logins em rodadas de 256, com o lock preso 8 ms a
  cada 10 ms (o pior caso):

  | | 1 worker | 8 workers |
  |---|---:|---:|
  | sem HA | 67 570/s | 331 743/s |
  | hot standby, worker espera o lock | 23 854/s | 179 141/s |
  | hot standby, `try_lock` + fila (este PR) | 63 469/s | 302 470/s |

- **Os contadores para o standby** (a cada 10 s) saem na mesma passada do `tick` de 1 s, que já
  percorre a tabela ativa. A primeira versão fazia uma varredura própria, debaixo do lock
  compartilhado: 22 ms para 50 mil sessões num worker, 442 ns por sessão. Agora o `tick` de 50 mil
  sessões leva 21,7 ms sem os contadores e 22,7 ms com eles: ≈ 1 ms a mais a cada 10 s.
- **O `tick` de 1 s em si** (G4.3g, anterior a este PR) custa ≈ 440 ns por sessão debaixo do lock
  compartilhado. Reusar um buffer para o id da sessão, no lugar do `format!`, não mudou nada
  (21,6 contra 22,2 ms). O custo é a busca no mapa de 50 mil chaves, não a alocação. Dividido
  entre 8 workers, dá ≈ 3 ms por worker a cada segundo.

## 5. Riscos e como evitamos

- **BFD perdido nos dois caminhos com o par vivo (G3.6h):** com o hello ainda passando, o espera
  pode assumir antes do próximo hello. O par ativo ouve a tomada no hello seguinte e cede
  (época maior), em ≤ 1 hello; numa réplica completa, as sessões seguem no novo ativo. O
  amortecimento torna isso raro (a perda falsa vale duas penalidades: a próxima já é ignorada) e
  o alerta de jitter avisa antes. Por isso o BFD tem de ir nos **dois** caminhos, que passam por
  redes diferentes.

- **Uma porta de acesso por L2:** o ativo põe o mesmo MAC virtual em todas as portas de acesso.
  Duas portas no mesmo L2 fazem o switch mover o MAC de uma para a outra, e os quadros chegam pela
  porta errada (o laboratório achou isso com duas portas numa bridge só). Num ISP cada porta vai a
  uma OLT ou a um switch; MAC virtual por porta fica para uma gap, se alguém precisar.
- **CoA/DM depois da tomada (G4.3hb):** o servidor de cobrança continua mandando o CoA ao nó
  antigo. Se ele está vivo (switchover, falha simulada, volta como espera), encaminha o pedido ao
  par (§2.11). Se morreu, o pedido não chega a ninguém. O servidor precisa mandá-lo ao nó que manda
  a contabilização da sessão: depois da tomada, o Interim sai do nó novo, do endereço dele. Um
  endereço de CoA flutuante, que segue o papel, fica para a gap G4.3hg.
- **Class (RFC 2865 §5.25, G4.3ha):** o PPPoE e o IPoE ecoam o Class do Accept, byte a byte, em
  todo Accounting-Request; o registro o carrega (um TLV: 3 B + o tamanho), e o nó que assume
  manda o Interim e o Stop com o mesmo Class. O laboratório `ha` dá a cada usuário um Class
  binário próprio e conta os registros sem ele (coluna "Registros sem o Class do usuário").
- **DHCPv6-PD:** o prefixo delegado é reservado e anunciado no nó novo, e o Renew do CPE é
  atendido a partir da concessão refeita. O estado fino do DHCPv6 (T1/T2 em curso) não é copiado.


- **Dois ativos (o pior):** maioria de três, dois caminhos, eleição confirmada, época. O caso que
  sobra: o link de sync **e** o hello de acesso cortados com os dois nós alcançando a testemunha —
  cada um atende a metade do acesso que ainda alcança. Para o mesmo assinante ver os dois, o L2 de
  acesso tem de ligá-los, e aí o hello passa; um filtro que bloqueie só o EtherType 0x88b5 quebraria
  isso, e o monitor avisa quando o caminho de acesso está mudo com o par vivo no sync.
- **Troca falsa por carga:** morte em 1,2 s (4 hellos de 300 ms); a GUI mostra o atraso do sync e
  os hellos perdidos.
- **Testemunha caída:** sozinha não muda nada (o ativo ouve o par); só impede a tomada.
- **Sessões que não chegaram ao par:** perdem-se só as mudanças sem ack (milissegundos); o CPE
  dessas refaz o login. Um endereço emprestado nesse intervalo não volta duplicado: a sessão velha
  morreu com o nó.
- **Divergência de configuração** (pool, perfil, servidor diferentes): o Hello leva os hashes; o
  monitor mostra quais seções diferem, e a tomada avisa.
- **Versões diferentes no par (atualização em etapas):** o registro é TLV com campos desconhecidos
  preservados; a versão do stream vai no Hello.
- **Segredo do par:** só de escrita, como as senhas; autentica o hello e deriva a chave do
  AC-Cookie comum aos dois nós.
