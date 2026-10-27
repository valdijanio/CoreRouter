# RPKI, rotas por conexão e "Por que essa rota?" (G3.2c)

Terceira parte do BGP (`docs/bgp.md`), mais o que faltava do G3.3 (estado BGP):

| O quê | Comandos | Janela |
|---|---|---|
| Validadores RPKI (RTR) e a política de inválidas | `routing.rpki.{add,set,remove,list,preview}`, `routing.rpki.session.list`, `routing.rpki.invalid.set` | Routing › RPKI |
| `rpki-check` de um prefixo | `routing.rpki.check` | Routing › RPKI |
| Rotas recebidas e anunciadas por conexão | `routing.bgp.route.list`, `routing.bgp.route.summary` | Routing › BGP Routes |
| "Por que essa rota?" | `routing.bgp.route.explain` | modal; botões em BGP Routes, no detalhe da sessão (Routing › BGP) e em IP › Routes |
| Histórico de quedas | `routing.bgp.session.history` | Routing › BGP Routes › History |

## Como usar

```sh
corerouter-cli run routing.rpki.add '{"name":"routinator1","address":"192.0.2.10","port":3323}'
corerouter-cli run routing.rpki.session.list            # estado RTR, versão, serial, VRPs, política
corerouter-cli run routing.rpki.check '{"prefix":"192.0.2.0/24","origin_as":64500}'
corerouter-cli run routing.rpki.invalid.set '{"connection":"rr1","invalid":"accept"}'
corerouter-cli run routing.bgp.route.list '{"connection":"upstream1","rpki":"invalid"}'
corerouter-cli run routing.bgp.route.list '{"connection":"upstream1","direction":"advertised","as_path":"^64500"}'
corerouter-cli run routing.bgp.route.explain '{"prefix":"203.0.113.7"}'
corerouter-cli run routing.bgp.session.history '{"connection":"upstream1"}'
```

`route.list` e `route.explain` leem o FRR num job fora do lock da sessão: a primeira resposta é
`{"state":"loading"}` e a seguinte (um instante depois) traz os dados. As páginas seguintes, as
buscas e os filtros saem da memória.

Para testar sem internet, o exemplo `rtr_server` do `hal-frr` é um validador RTR com VRPs fixos:

```sh
cargo run -p corerouter-hal-frr --example rtr_server -- 127.0.0.1:3323 vrps.txt   # "prefixo maxlen asn" por linha
```

## Como funciona

- **Quem descarta é o FRR.** O render (`proto_bgp::rpki::render_frr`) põe o nó `rpki` com os
  validadores ativos e o route-map `CR-RPKI-IN` (`deny 1` com `match rpki invalid`,
  `permit 65535`). Cada vizinho que descarta inválidas recebe `route-map CR-RPKI-IN in` e
  `soft-reconfiguration inbound`: sem a Adj-RIB-In o `bgpd_rpki` não revalida quando as ROAs
  mudam (documentação do FRR, "Prefix Origin Validation Using RPKI"), e uma rota descartada como
  inválida que fica válida só voltaria com um reset da sessão. A mesma Adj-RIB-In mostra, na lista
  recebida, o que foi recusado (`filtered`).
- **O FRR precisa do módulo `rpki`:** pacote `frr-rpki-rtrlib` e `-M rpki` em `bgpd_options`
  (`/etc/frr/daemons`). Sem validador ativo nada de RPKI é renderizado, então um FRR sem o módulo
  continua aceitando os commits.
- **O CoreRouter tem o seu próprio cliente RTR** (`proto_bgp::rtr`, sans-IO; serviço `rpki` do
  daemon, uma thread nomeada por validador): RFC 8210 versão 1 com volta para a 0 (RFC 6810; negociação da RFC 8210 §7),
  Reset Query, Serial Query incremental, Serial Notify, Cache Reset, troca de Session ID, timers
  do End of Data (com os limites da §6) e expiração. Os dados entram todos de uma vez no End of
  Data (§5.8). As VRPs viram uma árvore de prefixos (`VrpTable`, Patricia por família) construída
  na thread do serviço; só o `Arc` é trocado sob o lock. Ela dá os selos das listas, a porcentagem
  por sessão, o `rpki-check` e funciona no laboratório virtual.
- **eBGP e RFC 8212.** Qualquer route-map satisfaz o `ebgp-requires-policy` do FRR. Um
  `CR-RPKI-IN` num vizinho eBGP sem política abriria a sessão para tudo que não é inválido. Então,
  até a G3.2b entregar as políticas, o RPKI só é aplicado em iBGP; o eBGP continua não aceitando
  nada. A G3.2b põe as entradas `route_map_prelude` (sequências 1..=9) no começo do route-map de
  entrada de cada conexão (contrato combinado com ela).
- **Listas de 1 M de rotas.** O `hal-frr` lê `show bgp … neighbors X received-routes json`
  (`advertised-routes`, ou `routes` quando não há Adj-RIB-In) em streaming direto do socket vty
  para a tabela compacta (`BgpRib`: 24 bytes por rota, atributos internados), sem montar o texto
  nem um `serde_json::Value`. O engine guarda até 4 tabelas (LRU, 10 min sem uso), ordenadas por
  prefixo e já validadas (`proto_bgp::rib::Indexed`). Busca por prefixo é busca binária; AS path e
  community olham os atributos internados uma vez.
- **"Por que essa rota?"** lê `show bgp … <prefixo> json` (todos os caminhos) e compara o melhor
  com cada outro na ordem do `bgp_path_info_cmp` do FRR 10.x (`proto_bgp::decision`): weight,
  local-pref, rota local, tamanho do AS path, origin, MED (mesmo AS vizinho), eBGP × iBGP, custo
  IGP, confederação, caminho mais antigo (eBGP), router-id/originator-id, cluster list, rota
  obsoleta, endereço do vizinho. A resposta traz o passo e os dois valores comparados. Se a nossa
  comparação não reproduz a escolha do daemon (deterministic-med, multipath), ela diz isso.
- **Histórico de quedas.** Comparando as amostras de 2 s do serviço `frr`: `down` (saiu de
  Established), `up`, e `flap` quando o contador de quedas andou entre duas amostras. Até 64
  eventos por sessão, na memória.

## Pesquisa

### MikroTik RouterOS v7

- [`/routing/rpki`](https://manual.mikrotik.com/docs/7.25/cli-reference/routing/rpki/),
  [`/routing/rpki/session`](https://manual.mikrotik.com/docs/7.24/cli-reference/routing/rpki/session/)
  e o [guia de RPKI](https://manual.mikrotik.com/docs/7.25/user-guides/routing-and-networking-protocols/unicast/rpki/).
- Uma entrada por validador: `group`, `address`, `port`, `refresh-interval`, `retry-interval`,
  `expire-interval`, `preference` (maior vence; sem ela, o menor IP), `vrf`, `disabled`.
  `session` mostra `state` (idle, connecting, prepare, loading, sync, error), `version`,
  `session`, `serial`, `expires`. `rpki-check group=… prfx=… origin-as=…`.
- Estados: `valid`, `invalid`, `unknown` e `unverified` (nenhuma sessão do grupo sincronizou).
- **O RouterOS não descarta nada sozinho:** é preciso `rpki-verify <grupo>` e
  `if (rpki invalid) { reject }` no filtro de entrada. Também não há "por que essa rota".
- `/routing route print detail` mostra os atributos e a flag de ativa, sem dizer o motivo.

### Outros

- **Junos**: `routing-options validation group … session …`, `show validation session /
  database / statistics`; o descarte vem de uma política com `validation-state invalid` →
  `reject` (o exemplo da própria Juniper). `show route <prefixo> detail` traz em cada caminho
  inativo o `Inactive reason` (Local Preference, AS path, Not Best in its group - Router ID…):
  é a referência do nosso "Por que essa rota?".
- **Cisco IOS XR**: com `rpki server` configurado, a validação de origem liga e caminhos inválidos
  ficam fora do bestpath por padrão (`bgp bestpath origin-as allow invalid` volta atrás).
  `show bgp <prefixo> bestpath-compare` mostra, para cada caminho, por que não é o melhor.
- **Nokia SR Linux / SR OS**: `rpki-validation` por grupo de vizinhos; `show router bgp routes
  <prefixo> hunt` lista RIB-In, RIB e RIB-Out com o motivo de cada um.
- **BIRD**: protocolo `rpki` alimenta tabelas `roa4/roa6`; o filtro chama `roa_check()`. Não
  descarta por padrão. `show route for X all` mostra os atributos.
- **FRR**: `rpki` (rtrlib) com `match rpki invalid|valid|notfound` em route-map; revalidação
  precisa de `soft-reconfiguration inbound`; `show bgp … json` traz `selectionReason` só do
  melhor caminho; 10.x também traz ASPA (rascunho).
- Validadores: Routinator (porta 3323), rpki-client + StayRTR (8282), FORT, OctoRPKI.

### RFCs (base, atualizações e errata)

- [RFC 6811](https://www.rfc-editor.org/info/rfc6811) (validação de origem), atualizada pela
  [RFC 8481](https://www.rfc-editor.org/info/rfc8481) (esclarecimentos) e pela
  [RFC 8893](https://www.rfc-editor.org/info/rfc8893) (validação na exportação). Sem errata
  (rfc-editor.org, 2026-10-27). Aplicado: §2 (VRP cobre se o prefixo dele contém a rota; casa se
  o tamanho ≤ max length e o AS é o de origem; origem = último AS de um AS_SEQUENCE final, nenhuma
  com AS_SET), RFC 6483 §4 e RFC 7607 (VRP de AS 0 não casa com nada), RFC 8481 §4 (rota local tem
  o nosso AS como origem; validar rotas de toda fonte, iBGP também).
- **RFC 8481 §5:** "Absent specific operator configuration, policy MUST NOT be applied". O pedido
  é descarte por padrão. Conciliação: a política só existe depois que o operador configura um
  validador (essa é a configuração), a resposta do `routing.rpki.add`, a prévia do modal e a
  janela dizem o que acontece, e há interruptor por conexão (`routing.rpki.invalid.set`). Sem
  validador, nada é descartado; com o validador fora do ar, as rotas ficam `unverified` e passam.
- [RFC 8210](https://www.rfc-editor.org/info/rfc8210) (RTR versão 1; atualiza a
  [RFC 6810](https://www.rfc-editor.org/info/rfc6810)), sem atualizações nem errata.
  Aplicado: formatos da §5 (com os exemplos de PDU virados teste), timers e limites da §6,
  negociação de versão da §7, sequências da §8, códigos de erro da §12; MAX_PDU de 64 KiB, como o
  draft-ietf-sidrops-8210bis (versão 2, com ASPA, ainda rascunho: `-27` de 2026-08-13), que não
  implementamos.
- [RFC 4271 §9.1](https://www.rfc-editor.org/rfc/rfc4271#section-9.1) (decisão) e
  [RFC 4456 §9](https://www.rfc-editor.org/rfc/rfc4456#section-9) (ORIGINATOR_ID e CLUSTER_LIST),
  citadas passo a passo em `proto_bgp::decision` e nos ⓘ.

### O que adotamos e o que melhoramos

- Modelo e nomes do RouterOS (`/routing rpki`, estados `valid/invalid/unknown/unverified`,
  `rpki-check`) e o comportamento do IOS XR: com validador, inválidas são descartadas sem
  precisar escrever filtro.
- Cliente RTR próprio, em Rust: estado detalhado (versão, Session ID, serial, VRPs por família,
  expiração) e selos sem consultar o FRR rota a rota.
- "Por que essa rota?" com o passo e os dois valores, para todo caminho (o Junos dá o motivo, o
  XR compara, o RouterOS e o BIRD não têm), e o aviso quando o daemon decidiu por algo que a
  comparação passo a passo não cobre.
- Listas de rotas paginadas no roteador, com busca por prefixo, AS path, community e estado
  RPKI, e o histórico de quedas.

### Ficou para depois

- RPKI em eBGP e na exportação (RFC 8893): entra com as políticas da G3.2b (as funções
  `route_map_prelude` já existem).
- Grupos de validadores por conexão: o FRR tem uma tabela RPKI por VRF; hoje todo validador ativo
  alimenta a mesma.
- ASPA (rascunho do SIDROPS; o FRR 10.7 já tem) e BGPsec (router keys são só contadas).
- RTR sobre SSH/TLS (o FRR suporta SSH): hoje só TCP, com o validador em rede confiável.
