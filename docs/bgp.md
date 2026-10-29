# BGP (G3.2)

O BGP do CoreRouter roda no FRR (decisão do G3.1, `docs/architecture.md` 1.3). O engine guarda a
config no modelo do RouterOS v7, valida, rende para o `bgpd` e aplica só a diferença pelo
socket vty (`crates/hal-frr`). O G3.2 foi dividido em três partes:

| Parte | O quê |
|---|---|
| **G3.2a** (esta) | templates, conexões, sessões ao vivo, validação, janela Routing › BGP |
| G3.2b | políticas: prefix-list, community normal e large, AS-path, `routing.filter.rule` com prévia (`docs/bgp-policy.md`) |
| G3.2c | RPKI (RFC 6811/8210) por padrão, "Por que essa rota?" e rotas por conexão (`docs/rpki.md`) |

## Como usar

```sh
corerouter-cli run routing.bgp.instance.set '{"asn":65000,"router_id":"10.255.0.1"}'
corerouter-cli run routing.bgp.template.add '{"name":"transit","local_role":"ebgp-customer","hold_time":90,"afi":"ip,ipv6","max_prefix_ipv4":1200000}'
corerouter-cli run routing.bgp.connection.add '{"name":"upstream1","remote_address":"198.51.100.2","remote_as":65100,"templates":"transit","tcp_md5_key":"…"}'
corerouter-cli run routing.bgp.session.list
corerouter-cli run routing.bgp.session.refresh '{"connection":"upstream1"}'
```

| Comando | RouterOS v7 |
|---|---|
| `routing.bgp.template.{add,set,remove,list,check}` | `/routing bgp template` |
| `routing.bgp.connection.{add,set,remove,list,check}` | `/routing bgp connection` |
| `routing.bgp.session.list` | `/routing bgp session print` |
| `routing.bgp.session.refresh` / `resend` / `clear` | `/routing bgp session refresh` / `resend` / `clear` |
| `routing.bgp.connection.set {disabled: true}` | `disable` (shutdown) |

Parâmetros de conexão e template (os mesmos nos dois): `remote_as`, `local_role` (`ibgp`,
`ebgp`, `ebgp-provider`, `ebgp-customer`, `ebgp-peer`, `ebgp-rs`, `ebgp-rs-client`),
`multihop`, `hold_time`, `keepalive_time`, `tcp_md5_key`, `afi` (`ip`, `ipv6`),
`max_prefix_ipv4`, `max_prefix_ipv6`, `max_prefix_action` (`shutdown`, `warning`, `restart`),
`max_prefix_restart`, `update_source` (o `local.address` do RouterOS) e `nexthop_choice`
(`default`, `force-self`, `propagate`). Um parâmetro ausente herda do primeiro template que o
define; `null` num `set` volta a herdar.

### Anunciar redes e refletir rotas (G3.9f)

```sh
corerouter-cli run ip.firewall.address-list.add '{"list":"bgp-out","address":"100.64.0.0/22"}'
corerouter-cli run routing.bgp.connection.set '{"id":"upstream1","output_network":"bgp-out"}'
corerouter-cli run routing.bgp.connection.set '{"id":"core2","output_redistribute":"connected,static"}'
corerouter-cli run routing.bgp.connection.add '{"name":"client1","remote_address":"10.0.0.7","remote_as":65000,"local_role":"ibgp-rr"}'
```

- `output_network` (RouterOS `output.network`): a address-list do firewall cujas redes são
  anunciadas, cada uma só enquanto houver rota para ela (o `network` do FRR com
  `bgp network import-check`, o "só com rota IGP correspondente" do RouterOS). Mudar a lista
  chega ao FRR no mesmo commit (~0,1 s até o vizinho, **medido**). Faixas `a-b` ficam de fora.
- `output_redistribute` (RouterOS `output.redistribute`): `connected`, `static`, `ospf`. As
  estáticas do CoreRouter são instaladas pelo backend linux (`proto static`), e o `zebra` as vê
  como rotas *kernel*: `static` vira `redistribute kernel` com um route-map que só deixa passar
  os prefixos das estáticas configuradas (`CR-BGP-STATIC4/6`).
- Por conexão, como no RouterOS (G3.9fb): cada vizinho recebe só o que a conexão dele pede. O
  FRR origina por instância (a união dos pedidos); a conexão que pede menos que a união ganha um
  route-map de saída próprio, `CR-C+<conexão>`: passam as nossas rotas da lista dela
  (`CR-C+<conexão>+4/+6`) e dos protocolos que ela redistribui (`match source-protocol`); são
  recusadas as rotas `network` das outras conexões (o prefixo, `CR-C+<conexão>+not4/6`, com o
  AS_PATH vazio de rota nossa, `CR-C+local`) e os protocolos que só as outras redistribuem; o
  que passa segue para a chain dela (`call CR-<chain>`). Rotas recebidas de outros vizinhos não
  mudam. O `match peer local` do FRR não serve: num route-map de saída o "peer" é o vizinho de
  destino (`bgp_route.c`, `prep_for_rmap_apply`). Um prefixo conectado (ou estático) que outra
  conexão põe no `output_network` vai também para a que redistribui connected (static): no
  `bgpd` é uma rota só, a do `network`. Quando todas pedem o mesmo, nada muda no render. O eBGP
  sem chain continua sem receber nada (RFC 8212). Limite: um prefixo do OSPF que outra conexão
  lista no `output_network` não vai para a que só redistribui `ospf`.
- `local_role=ibgp-rr` (RouterOS `ibgp-rr`): iBGP em que este roteador reflete rotas para o
  vizinho, seu cliente (RFC 4456, `route-reflector-client` no FRR). O cluster-id é o router-id,
  como no RouterOS.

## Pesquisa

### MikroTik RouterOS v7

- [BGP](https://help.mikrotik.com/docs/spaces/ROS/pages/328220/BGP) e a referência da CLI
  [`/routing/bgp/connection`](https://manual.mikrotik.com/docs/7.25/cli-reference/routing/bgp/connection/)
  e [`/routing/bgp/template`](https://manual.mikrotik.com/docs/7.24/cli-reference/routing/bgp/template).
- O v7 separou o v6 (`peer`) em três menus: `template` (parâmetros do protocolo), `connection`
  (o vizinho, que também expõe os parâmetros do template) e `session` (estado em cache, só
  leitura, com `clear`/`refresh`/`resend`).
- Nomes adotados: `remote.address`, `remote.as` (vazio: aprende do OPEN), `local.role`
  (obrigatório no RouterOS; os papéis da RFC 9234), `templates`, `multihop`, `hold-time`
  (3 s..65535 s ou infinity; padrão 3 min), `keepalive-time` (vazio: um terço do hold),
  `tcp-md5-key`, `afi`, `nexthop-choice`, `input.limit-process-routes-ipv4/ipv6`.
- O que o RouterOS faz pior: o `local.role` é obrigatório mesmo quando o AS remoto já diz o
  tipo; o limite de prefixos só para de processar (não fecha a sessão nem avisa); a doc não diz
  como a herança de vários templates se resolve.

### Outros

- **Junos**: `group` → `neighbor`, herança em dois níveis, `family inet unicast prefix-limit
  maximum N teardown <pct> idle-timeout <min>` — ação e reinício por família, que adotamos.
- **Cisco IOS-XE**: `template peer-session` e `peer-policy` com `inherit` (até 7 níveis), mais
  os `peer-group` antigos; `neighbor X maximum-prefix N [threshold] [restart M | warning-only]`.
- **Nokia SR Linux**: `group` com `neighbor`, `afi-safi` por grupo e por vizinho,
  `prefix-limit max-received-routes` com `prevent-teardown`.
- **VyOS / FRR**: `peer-group`; `neighbor X local-role` (RFC 9234), `maximum-prefix … restart |
  warning-only`, `ebgp-multihop`, `update-source`, `password`.
- Comum aos melhores: limite de prefixos com ação, herança em mais de um nível, papel RFC 9234
  para pegar vazamento de rotas.

### RFCs (base, atualizações e errata)

- [RFC 4271](https://www.rfc-editor.org/info/rfc4271) (BGP-4), atualizada por 4724, 6286, 6608,
  6793, 7606, 7607, 7705, 8212, 8654, 9072, 9687 e 9774. Errata verificadas: 9, das quais
  técnicas a 1633 (§6.3), a 2838 (§8.2.2: HoldTimer_Expires em Established apaga as rotas) e a
  4493 (§4.5: subcódigo 0). Aplicado: hold 0 ou ≥ 3 s (§4.2), keepalive menor que o hold e um
  terço por padrão (§10), estados da §8.2.2 na coluna State.
- [RFC 6793](https://www.rfc-editor.org/info/rfc6793) (AS de 4 bytes; obsoleta a 4893, sem
  atualizações): asplain e asdot aceitos; AS_TRANS (23456) recusado como AS local ou remoto.
- [RFC 7607](https://www.rfc-editor.org/info/rfc7607) (AS 0) e
  [RFC 7300](https://www.rfc-editor.org/info/rfc7300) (65535, 4294967295): recusados.
- [RFC 4760](https://www.rfc-editor.org/info/rfc4760) (multiprotocolo, atualizada pela 7606):
  `afi` com IPv4 e IPv6 unicast; uma conexão sem família é recusada.
- [RFC 7606](https://www.rfc-editor.org/info/rfc7606) (tratamento de erro revisado,
  treat-as-withdraw): é do FRR, ligado por padrão; nada a configurar.
- [RFC 8212](https://www.rfc-editor.org/info/rfc8212): eBGP sem política não aceita nem envia
  (o `bgp ebgp-requires-policy` do FRR, mantido ligado); a janela diz isso no detalhe da
  sessão e na prévia, e as políticas chegam no G3.2b.
- [RFC 2385](https://www.rfc-editor.org/info/rfc2385) (TCP MD5): até 80 bytes
  (`TCP_MD5SIG_MAXKEYLEN` do Linux); [RFC 9234](https://www.rfc-editor.org/info/rfc9234)
  (papéis); [RFC 2918](https://www.rfc-editor.org/info/rfc2918) (ROUTE-REFRESH, usado pelo
  `refresh`).

### O que adotamos e o que melhoramos

- Modelo e nomes do RouterOS v7, com herança de vários templates resolvida assim: valor da
  conexão; senão, o primeiro template da lista que o define (cada template já com os pais
  resolvidos). Laço e profundidade acima de 8 são recusados com a cadeia na mensagem.
- `local.role` opcional: vazio, sai do AS remoto (o nosso → iBGP). `remote_as` vazio vira
  `remote-as external`/`internal` no FRR.
- Limite de prefixos por família com ação (`shutdown`, `warning`, `restart` + minutos), como
  Junos e Cisco, em vez do "para de processar" do RouterOS.
- Chave MD5 selada como as senhas PPP: nunca aparece em config, histórico, journal, logs,
  respostas ou MCP; o modal a trata como campo só de escrita.
- Prévia no modal (o mesmo comando `check` serve à CLI e ao MCP): valores em vigor, o que vem
  de template, timers calculados, aviso de hold curto, de eBGP sem política e sem chave, e de
  que mudanças reiniciam a sessão; a prévia de um template recusa a mudança que deixaria uma
  conexão inválida.
- Transação: mudar um vizinho não derruba os outros (teste com FRR real).

### G3.9f: interoperabilidade (RouterOS v7.25, FRR 10.7.1, CoreRouter × CoreRouter)

- [`/routing/bgp/connection` 7.25](https://manual.mikrotik.com/docs/7.25/cli-reference/routing/bgp/connection/):
  `output.network` (address-list, enviada só com rota IGP correspondente), `output.redistribute`,
  `local.role` com `ibgp-rr`, `use-bfd`, `input.limit-process-routes-ipv4/6` (para de processar,
  não fecha a sessão); sem parâmetro de graceful restart (a sessão anuncia a capacidade `gr`).
- Outros: Junos (`export` de política com `from protocol static`), IOS-XE (`network` +
  `redistribute static route-map`), FRR (`network` com `import-check`; `redistribute` por
  address-family, não por vizinho), VyOS (o mesmo do FRR).
- RFCs: 4271 §5.1.3 (next hop mantido no iBGP; o `nexthop-choice=force-self` é o `next-hop-self`),
  4456 §8 (ORIGINATOR_ID e CLUSTER_LIST, conferidos no laboratório), 4760 e 2545 §3 (IPv6 numa
  sessão IPv4: next hop global, mais o link-local num enlace compartilhado), 1997 (no-export
  respeitado), 8092, 4486 (Cease subcódigo 1 no max-prefix, visto do outro lado como `0601`),
  5880/5882 (o BGP cai com o BFD), 2385 (MD5).
- Como testar: `scripts/bgp-crcr-userns.sh` (no host, sem root nem VM: CoreRouter × CoreRouter e
  FRR) e `scripts/routeros-interop-bgp.sh` (na VM, contra o CHR).
- Divergências do RouterOS 7.25 vistas no laboratório (quem está certo):
  - IPv6 numa sessão IPv4 (`afi=ip,ipv6`): o CHR manda o next hop `::ffff:10.39.1.1`
    (IPv4-mapeado). A RFC 2545 §3 pede um endereço IPv6 global; nenhum kernel instala o mapeado,
    e o próprio RouterOS o trata como inalcançável. Errado o RouterOS. O CoreRouter manda global +
    link-local e o CHR instala. Desde a G3.9fh a chain de entrada reescreve o next hop com o
    IPv6 do CHR no enlace, `if (afi ipv6) { set gw fd39:1::1 } accept` (FRR `set ipv6 next-hop
    global`), e as rotas entram no kernel; a prévia da conexão avisa (`mpbgp-nexthop`) e diz o
    que escrever. A outra saída continua valendo: uma segunda conexão ao endereço IPv6 com
    `afi=ipv6`.
  - Refletor: o CHR põe o próprio Router ID no ORIGINATOR_ID; a RFC 4456 §8 pede o do originador
    do anúncio no AS. Errado o RouterOS; o CLUSTER_LIST e o next hop estão certos.
  - `set bgp-path-prepend N`: no eBGP o CHR sai com o próprio AS N vezes no total (N = 1, 2, 3 →
    1, 2, 3 cópias, **medido**); na saída iBGP e na entrada não põe nada. Desde a G3.9fg o
    CoreRouter faz igual; filtros antigos mantêm a contagem anterior (N além do que a sessão põe)
    até `routing.filter.prepend.set` (`docs/bgp-policy.md`).
  - iBGP de rede própria: o CHR anuncia com o endereço da interface (10.39.1.1) quando a sessão
    é entre loopbacks com `local.address`; a RFC 4271 §5.1.3 permite. Sem `local.address` ele
    abre a sessão a partir do loopback.
  - `input.limit-process-routes-ipv4`: para de processar sem mandar Cease; o `max_prefix` do
    CoreRouter fecha com Cease 6/1 (RFC 4486), que o CHR registra.

### Ficou para depois

- Políticas e o "quais rotas passam" (G3.2b); RPKI e "Por que essa rota?" (G3.2c).
- BFD por conexão (`use-bfd`): a coluna BFD já lê o estado do FRR; ligar o BFD é do G3.6.
- Send Hold Timer (RFC 9687) e TTL security (GTSM, RFC 5082) como parâmetros: o FRR suporta,
  sem pedido ainda.
- VRF por instância (hoje uma instância não `default` vira `view` do FRR).
