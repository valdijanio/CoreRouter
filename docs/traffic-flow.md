# Traffic Flow (G4.4b): IPFIX e NetFlow v9

Exportação de fluxos como o `/ip traffic-flow` do RouterOS. Cada conexão que o kernel rastreia
(conntrack) vira registros de fluxo, por sentido, com os endereços e portas **antes e depois do
NAT**. Saem também os eventos de NAT da RFC 8158: a sessão NAT44 criada e encerrada e, no CGNAT em
blocos (G2.3c), o bloco de portas alocado e liberado. Os destinos são até 16 coletores, em IPFIX
(UDP ou TCP) ou NetFlow v9 (UDP). O roteador guarda os fluxos recentes para os top talkers, para o
CSV e para outro exportador ler em lote.

## Como funciona

```text
kernel: conntrack ──(ctnetlink NEW/DESTROY, multicast)──► leitor ──► fila fixa (262 144 eventos)
                └──(dump da tabela, a cada inactive-timeout)──┐            │ descarte contado
                                                              ▼            ▼
                                         medidor (proto-flow): fluxos + eventos NAT
                                                              │
                     log do roteador (ALLOC/RELEASE do PBA) ──┤
                                                              ▼
                      um codificador por destino (IPFIX/v9, templates) ──► UDP / TCP
                                                              │
                                    armazenamento local (24 h, teto) ──► top, CSV, records
```

- **Fonte:** os eventos do conntrack, não amostragem de pacotes. `NEW` diz quando a conexão
  começou e qual tradução o NAT escolheu; `DESTROY` traz os contadores finais. O exportador liga
  `nf_conntrack_acct` (contadores) e `nf_conntrack_timestamp` (início e fim pelo relógio do
  kernel) no namespace do roteador, e a janela mostra se ficaram ligados.
- **Timeouts:** uma conexão longa é reportada em partes. Sai uma parte a cada `active_flow_timeout`
  e outra quando ela fica `inactive_flow_timeout` sem pacotes. Os dois saem da leitura periódica da
  tabela, a cada `inactive_flow_timeout`, no mínimo 10 s. O fim da conexão sai do `DESTROY`.
- **NAT:** o fluxo do iniciador leva `src → dst` e, depois do NAT, `post_src`/`post_src_port` (a
  tupla de resposta invertida). O fluxo de volta leva o destino público e o assinante em
  `post_dst`.
- **Eventos NAT44 (RFC 8158 §4.2):** `natEvent` 4 (create) e 5 (delete), com o tempo em
  `observationTimeMilliseconds`. O delete leva também o início da sessão (`flowStartMilliseconds`,
  campo que a RFC permite acrescentar). Assim ele sozinho é o registro completo, mesmo quando o
  create se perdeu num estouro do kernel. **Sem destino por padrão** (veja "Marco Civil").
- **Blocos de portas (RFC 8158 §4.2.10):** `natEvent` 16 e 17, com
  `portRangeStart`/`End`/`StepSize`/`NumPorts`, lidos das linhas `ALLOC`/`RELEASE` do CGNAT em
  blocos.
- **Amostragem:** com `sampling_interval=N`, uma conexão em N gera fluxos. A escolha é
  determinística, por um hash da tupla. Um registro de opções avisa o coletor
  (`samplingInterval`). Os eventos de NAT nunca são amostrados.
- **Interfaces:** o conntrack não diz por onde a conexão passou. O roteador acha a interface pela
  tabela de rotas da config (conectadas e estáticas da `main`) e exporta o nome de cada ifIndex num
  registro de opções (`interfaceName`). `interfaces` filtra os fluxos pela interface de entrada ou
  de saída.

## Comandos

| Comando | O que faz |
|---|---|
| `ip.traffic-flow.set` / `.get` | liga, interfaces, `cache_entries`, timeouts, amostragem, `nat_events`, `nat_events_destination`, retenção local |
| `ip.traffic-flow.target.add/set/remove/list` | coletores: `dst_address`, `port` (2055), `src_address` (um endereço do roteador), `version` 9/ipfix, `transport` udp/tcp, `template_refresh` (20 pacotes), `template_timeout` (600 s); a lista traz estado, registros/min, templates, fila e perda |
| `ip.traffic-flow.stats` | eventos lidos, estouros do kernel, fila e descartes, cache, contadores |
| `ip.traffic-flow.top` | top talkers dos últimos N minutos (5 por padrão), por bytes, pacotes ou conexões |
| `ip.traffic-flow.records` | API em lote: registros depois de `since`, até 10 mil, com `next` para continuar (o exportador de ClickHouse, G4.4f, usa este) |
| `ip.traffic-flow.export` | CSV dos últimos N minutos (até 100 mil linhas), filtrável por endereço |

```sh
corerouter-cli run ip.traffic-flow.target.add '{"dst_address":"192.0.2.10","version":"ipfix"}'
corerouter-cli run ip.traffic-flow.set '{"enabled":true}'
corerouter-cli run ip.traffic-flow.top '{"minutes":5}'
```

## Pesquisa

Fontes lidas em 2026-10-23; o relatório completo, com as tabelas, está nas notas da sessão.

- **MikroTik RouterOS v7, Traffic Flow**
  ([manual](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/traffic-flow/),
  [CLI `/ip traffic-flow`](http://manual.mikrotik.com/docs/7.24/cli-reference/ip/traffic-flow/)).
  - Valores padrão: `active-flow-timeout` 30m, `inactive-flow-timeout` 15s, porta 2055,
    `v9-template-refresh` 20 pacotes. O `v9-template-timeout` não tem padrão documentado.
  - `version` aceita 1, 5, 9 ou ipfix.
  - Em `/ip traffic-flow ipfix` há 36 chaves, entre elas `nat-events` e
    `nat-src/dst-address/port`.
  - O manual não diz como codifica os eventos de NAT. Um relato no fórum mostra `NAT_EVENT 0`.
- **IPFIX:** [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011) e a
  [errata](https://errata.rfc-editor.org/rfc7011).
  - Cabeçalho §3.1: a sequência conta os registros de dados *anteriores*, por domínio (errata
    4396).
  - Sets e templates §3.3–3.4; padding §3.3.1; retirada §8.1, que não vale no UDP (§8.4).
  - Reenvio no UDP §8.4. Os padrões de 600 s vêm da
    [RFC 6728 §4.4.2](https://www.rfc-editor.org/rfc/rfc6728).
  - Tamanho §10.3.3: até a PMTU, ou 512 bytes se ela não é conhecida.
  - O Apêndice A virou teste.
  - [RFC 7012](https://www.rfc-editor.org/rfc/rfc7012) e o
    [registro IANA](https://www.iana.org/assignments/ipfix/ipfix.xhtml) dão os números e tipos de
    cada IE.
- **NetFlow v9:** [RFC 3954](https://www.rfc-editor.org/rfc/rfc3954) e a
  [errata](https://errata.rfc-editor.org/rfc3954).
  - O `Count` do cabeçalho conta todos os registros, templates inclusive; a sequência conta
    pacotes (§5.1).
  - O options template usa tipos de escopo (§6.1).
  - Padding a 32 bits (errata 2096).
  - O coletor separa os fluxos pela porta de origem (errata 2979).
- **NAT:** [RFC 8158](https://www.rfc-editor.org/rfc/rfc8158).
  - `natEvent` 4/5 (sessão NAT44) e 16/17 (bloco de portas). 1/2 são Historic.
  - Templates mínimos em §4.6; o destino é opcional na sessão NAT44.
- **Outros:**
  - [ipt-netflow](https://github.com/aabc/ipt-netflow), o módulo de kernel: também usa os eventos
    do conntrack para o NAT (`natevents=1`, só conexões com NAT, IPv4, `natEvent` 1/2) e os mesmos
    valores padrão (1800 s, 15 s, 20 pacotes, 30 min).
  - [pmacct/nfacctd](https://raw.githubusercontent.com/pmacct/pmacct/master/CONFIG-KEYS): tem as
    primitivas `nat_event`, `post_nat_*` e `timestamp_start/end`, e guarda os templates em disco
    (`nfacctd_templates_file`).
  - [goflow2](https://github.com/netsampler/goflow2): saída em JSON/protobuf para o Kafka. Os
    campos de NAT pedem um `mapping.yaml` próprio.
  - [nProbe](https://www.ntop.org/guides/nprobe/flow_information_elements.html): conhece os IEs
    225 e 230.
- **Kernel:** `nfnetlink_conntrack.h` e a
  [documentação dos sysctls](https://docs.kernel.org/networking/nf_conntrack-sysctl.html).
  - Grupos NEW=1 e DESTROY=3; `CTA_TIMESTAMP`=20.
  - `nf_conntrack_acct` e `nf_conntrack_timestamp` vêm desligados por padrão.
  - Um leitor lento recebe `ENOBUFS`.
- **Marco Civil:** [Lei 12.965/2014](https://www2.camara.leg.br/legin/fed/lei/2014/lei-12965-23-abril-2014-778630-publicacaooriginal-143980-pl.html).
  - Art. 5º VI define o registro de conexão (início, fim, duração, IP). Pelo art. 13, o provedor
    o guarda por **1 ano**, sob sigilo.
  - Art. 14: o provedor de conexão **não pode** guardar registros de acesso a aplicações.
  - STJ, REsp 1.784.156/SP (2019) e REsp 2.170.872/SP (2025): com IPv4 compartilhado, a porta de
    origem é indispensável e o dever alcança o provedor de conexão.

**O que adotamos:**

- Nomes e valores padrão do RouterOS (`template_refresh`/`template_timeout` sem o `v9_`, porque a
  chave de parâmetro não aceita dígitos).
- Os templates da RFC 8158 com `natEvent` 4/5, não o 1/2 histórico.
- Os fluxos vêm do conntrack, como faz o ipt-netflow para o NAT.

**O que fazemos melhor que o RouterOS:**

- Eventos de NAT especificados, com o início da sessão no delete.
- Destino fora dos eventos de NAT por padrão.
- Perda e fila visíveis por destino.
- Top talkers e CSV sem coletor.
- Uma API em lote para outro exportador.
- Eventos de bloco do PBA.
- `src_address` só aceita um endereço do roteador.

## Extras e riscos

- **Marco Civil.** O registro de conexão (art. 13) é o evento NAT44 com origem antes e depois do
  NAT, porta e tempos. O destino é acesso a aplicação (art. 14) e só entra com
  `nat_events_destination=yes`. Os **fluxos** de tráfego têm destino por natureza: quem os exporta
  e os guarda (inclusive a retenção local de 24 h) decide isso conscientemente. A ⓘ da janela diz
  isso. Guardar um ano é papel do coletor: o roteador guarda horas, não meses.
- **Volume.** O leitor só tira eventos do socket; o resto é em lote, fora do lock da sessão, que é
  tomado uma vez por tick. A fila tem tamanho fixo e o descarte é contado.
- **Estouro do kernel.** Se o leitor não acompanha, o kernel perde eventos (`ENOBUFS`). Eles são
  contados em `kernel_overruns`.
  - Uma conexão cujo `NEW` se perdeu ainda sai inteira no `DESTROY`: o delete traz o início.
  - O que estava sendo seguido e sumiu da tabela sai com `flowEndReason` 5 (falta de recursos).
- **Coletor fora do ar.**
  - UDP: o socket conectado recebe o "port unreachable" e a janela mostra erro e perda.
  - TCP: as mensagens esperam numa fila de 8 MiB e a conexão tenta de novo a cada 2 s, reenviando
    os templates primeiro (RFC 7011 §8.1).
- **Vazamento.** Só os destinos habilitados da config que está rodando têm socket. Um destino
  removido ou desligado perde o socket e a fila no tick seguinte. O teste em netns confere que ele
  não recebe mais nada. Não há nomes DNS, só endereços.
- **Interfaces aproximadas.** A interface vem da rota, não do pacote. Com rota assimétrica ou
  policy routing ela pode divergir; a fonte XDP do G2.5 resolve isso depois.

## Limites e próximos passos

- Um user namespace recusa o `SO_RCVBUFFORCE`, e o buffer fica no `rmem_max` (8 MiB neste
  computador). Na rajada de 100 mil conexões abertas em 0,35 s, o kernel perdeu 18 % dos `NEW`.
  Os deletes e os fluxos chegaram todos. No roteador o daemon é root e pede 32 MiB.
- SCTP e TLS/DTLS para IPFIX ficam para depois, assim como sFlow v5, a escolha de `natEvent` 1/2
  para coletores antigos e a fonte XDP (gaps no arquivo de mudança).

## Desempenho (**medido**)

AMD Ryzen AI MAX+ 395, kernel 7.0, 2026-10-23.

- **Codec** (`cargo bench -p corerouter-proto-flow --bench flow_codec`, build release):
  - medidor: 7,7 M eventos/s;
  - IPFIX: 16 M registros/s;
  - v9: 14 M registros/s.
- **Ponta a ponta** (`netns_traffic_flow`, build de teste do daemon, sem otimização), 20 mil
  conexões UDP com NAT:
  - os 20 mil creates chegaram ao coletor TCP 0,19 s depois da primeira conexão;
  - 20 mil deletes e 20 mil fluxos saíram 0,24 s depois do primeiro `DELETE` do conntrack, cerca
    de 160 mil registros/s (o limite é a velocidade do kernel ao apagar);
  - 4,7 µs de CPU do daemon por registro;
  - RSS de 59 MB;
  - nenhum descarte na fila nem no kernel.
