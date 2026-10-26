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
| d | fase 1 no serviço `pppoe`: só o ativo responde, MAC virtual, segredo do AC-Cookie compartilhado | depois da sessão B (G4.3k+l) entrar |
| e1 | `proto-pppoe`: `Server::export`/`import` (a sessão em Opened no outro servidor, sem renegociar) | este PR |
| e2 | fase 2 no serviço: exportar/importar sessão por worker, mapas XDP na tomada, contabilização contínua | depois do d |
| f | aba PPP › Redundancy na GUI | #251 |
| g | laboratório com dois daemons, MAC virtual e BNG Blaster (`cargo xtask bng-lab` estágio `ha`) | depois do e |

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
- **Threads:** a sincronização cabe num núcleo com folga (1 milhão de mudanças/s contra ≈ 94 mil
  sessões/s que o BNG monta, G4.3d). Dividir por worker do `pppoe` (cada worker já tem a sua faixa
  de SESSION_ID) daria um stream por worker sem lock compartilhado — é o plano da fase 2 (PR d):
  cada worker publica as suas mudanças numa fila limitada para a thread do sync, e a tomada
  importa as sessões em paralelo, uma thread por worker. A máquina de papéis é uma só por nó
  (decisão global, custo desprezível).

## 5. Riscos e como evitamos

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
