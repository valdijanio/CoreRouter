# Roteamento por política (`/routing rule`, G1.27e)

Regras escolhem em qual tabela um pacote é procurado, olhando origem, destino, interface de entrada
e marca de roteamento. O modelo e os nomes são os do RouterOS v7. A aplicação é por netlink
(`FRA_*`), sem processo externo.

```sh
corerouter-cli run routing.table.add '{"name":"isp2"}'
corerouter-cli run ip.route.add '{"dst_address":"0.0.0.0/0","gateway":"198.51.100.1","routing_table":"isp2"}'
corerouter-cli run routing.rule.add '{"src_address":"10.91.0.0/24","action":"lookup","table":"isp2"}'
corerouter-cli run ip.route.lookup '{"address":"8.8.8.8","src":"10.91.0.7","interface":"ether3"}'
```

## Comandos

| Comando | O que faz |
|---|---|
| `routing.table.add/set/remove/list` | Tabelas nomeadas (`docs/routes.md`). |
| `routing.rule.add/set/remove/move/list` | As regras, em ordem. `place_before` escolhe a posição. |
| `routing.rule.kernel` | A lista inteira do kernel, com dono de cada linha, as marcas sem tabela e a diferença para a config. |
| `ip.route.lookup {address, src?, interface?, routing_mark?}` | Caminha pelas regras como o kernel. `matched_rule` e `trace` dizem qual decidiu e por quais passou; `kernel` traz a resposta do kernel e as diferenças. |

Parâmetros de regra: `src_address`, `dst_address`, `interface` (de entrada), `routing_mark`, `action`,
`table`, `min_prefix`, `disabled`, `comment`.

| `action` | Efeito | No kernel |
|---|---|---|
| `lookup` | Procura em `table`; sem rota, segue para a próxima regra | `FR_ACT_TO_TBL` |
| `lookup-only-in-table` | Procura só em `table`; sem rota, inalcançável | `FR_ACT_TO_TBL` seguido de `FR_ACT_UNREACHABLE` |
| `drop` | Descarta em silêncio | `FR_ACT_BLACKHOLE` |
| `unreachable` | Descarta e responde ICMP | `FR_ACT_UNREACHABLE` |

`min_prefix` é o `suppress_prefixlength` do Linux: rotas desse tamanho ou menores são ignoradas, e 0
esconde a rota padrão. Regra sem endereço vale para IPv4 e IPv6; com endereço, só para a família dele.

## A ordem no kernel

O kernel percorre a lista por prioridade (`fib_rules_lookup`, `net/core/fib_rules.c`). Sem rota na
tabela, segue para a próxima regra.

| Prioridade | Regra | Etapa no RouterOS v7 | Dono |
|---|---|---|---|
| 0 | tabela `local` | `local` | kernel |
| 100–999 | uma por marca de roteamento do mangle que nomeia uma tabela | `mangle` | CoreRouter |
| 1000 | `l3mdev` | `vrf-lookup` | kernel (driver de VRF) |
| 1001 | `l3mdev unreachable` | `vrf-unreach` | CoreRouter |
| 2000 em diante | `/routing rule`, duas prioridades por regra | `user` | CoreRouter |
| 32766, 32767 | `main`, `default` | `main` | kernel |

Consequências para quem opera:

- **O próprio roteador vem primeiro.** Pacote para um endereço do roteador nunca chega às regras, como
  no Linux. O RouterOS olha o mangle antes de `local`, e uma nota do fórum sobre a 7.22 alerta que um
  pacote marcado para o próprio roteador pode escapar do `input`. Aqui isso não acontece. Fica de fora
  a opção `policy-rules` da 7.22, que reordena as etapas.
- **Marca do mangle vence as regras.** Uma marca com o nome de uma tabela manda o pacote para essa
  tabela, antes de qualquer regra e antes da VRF. Sem rota lá, ele segue adiante, como no RouterOS.
  Uma marca que não nomeia tabela só serve para `routing_mark` numa regra; `routing.rule.kernel` a
  lista em `marks_without_table`.
- **VRF não vaza.** Sem a regra 1001, um pacote de um membro de VRF sem rota na tabela dela cairia nas
  regras seguintes e na `main`. Ela entra com a primeira VRF e fica quando a última sai, como a
  `l3mdev` do kernel, porque não casa com nada sem VRF.
- **Membro de VRF não serve como `interface`.** A tabela da VRF responde antes de qualquer regra, então
  a regra nunca casaria e é recusada. Para escolher a tabela desses pacotes, use uma marca no mangle.
- **`interface: lo` casa com os pacotes do próprio roteador**, porque o kernel usa `iif lo` na saída.

A prioridade sai da posição na lista. Mover ou inserir no meio renumera as de baixo, com as novas
entrando antes de as antigas saírem. Desligar uma regra ou trocar a ação mexe só nela.

## Marcas no firewall

O mangle usa os 16 bits altos da marca do pacote para a marca de roteamento
(`corerouter_firewall::nft::mark_value`, hash do nome), e as regras comparam com a máscara
`0xffff0000`. O validador recusa dois nomes que caiam no mesmo número.

Com `rp_filter` estrito, a resposta por outra interface é descartada; o padrão aqui é 0. O teste de
origem do kernel só considera a marca com `src_valid_mark`.

## Regra de outro programa

As regras do CoreRouter levam `FRA_PROTOCOL = 200`. A leitura e a reconciliação só consideram essas.
Regra de outro programa ou de `ip rule` nunca é apagada nem conta como drift. Ela aparece como
`foreign` em `routing.rule.kernel`, e se mudar uma decisão o `ip.route.lookup` mostra a diferença em
`kernel.differences`.

A aplicação compara com o que o kernel tem, não com a config anterior. Um daemon que reinicia não
duplica regras nem deixa regra velha. Regra nossa apagada à mão vira drift (`rule-missing`), e
`reconcile` a recoloca.

## Trancar-se para fora

O pacote que chega ao roteador usa a tabela `local`, antes de qualquer regra. O que uma regra pode
cortar é a volta. A cada commit com regras, o motor caminha pela lista para a resposta da sessão de
gerência, antes e depois da mudança. Se a resposta para de sair, ou passa a sair por outra interface,
o commit é recusado com a regra responsável, a menos que o comando traga `force: true` ou o Safe Mode
esteja ligado. É o mesmo mecanismo do firewall (G2.1b). Sessão local não tem conexão a perder.

Fica de fora: a ida de uma sessão encaminhada através do roteador, e `min_prefix` nesse cálculo.

## O que o kernel não responde

`RTM_GETROUTE` sempre percorre as regras. `RTM_F_LOOKUP_TABLE` só pede que a resposta diga a tabela
onde a busca terminou (`inet_rtm_getroute`, `net/ipv4/route.c`). Por isso `ip.route.lookup` com `table`
não tem comparação quando as regras levam a outra tabela: `kernel.available` fica `false` e o motivo é
dito. Uma regra `drop` responde `EINVAL` (`fib4_rule_action`), que o `route_get` traduz em `blackhole`.

## Custo

Medido com `crates/hal-linux/benches/netns_rules.rs`, build release, kernel 7.0.0-42 do host,
2026-11-08/09, frames UDP de 64 bytes numa veth, um núcleo, numa máquina com carga média de 30 a 57
porque outras sessões compilavam ao mesmo tempo. O ruído é alto: valem as ordens de grandeza.

| Regras que não casam antes da `main` | Rodada 1 (kpps) | Rodada 2 (kpps) |
|---|---|---|
| 0 | 910 | 381 |
| 1 | 640 | 256 |
| 10 | 567 | 600 |
| 100 | 127 | 377 |
| 1000 | 26 | 80 |
| 4096 | 8,7 | 17 |
| 4096 origens numa address list, 1 marca no mangle, 1 regra | não medido | 1051 |

O kernel percorre a lista inteira por pacote, sem índice (`fib_rules_lookup`), cerca de 15 a 30 ns por
regra. **Muitas origens indo para uma tabela custam muito menos como uma address list e uma regra
`mark-routing`**: o mangle procura num hash e a lista de regras fica com uma linha só. A partir de 100
regras o `routing.rule.add` avisa.

O caminho é por leitura (RCU), sem lock entre núcleos. `sendto` em 1 e 4 threads, em milhares de
lookups por segundo: sem regras 858 e 2196; 100 regras 523 e 763; 1000 regras 96 e 155; 4096 regras 25
e 85. O ganho varia com a carga da máquina. Uma NIC com várias filas divide os pacotes do mesmo jeito.

Escrever regras (`LinuxHal::apply`, uma mensagem por regra, serializadas pelo kernel; mais threads não
ajudam):

| Regras | Escrever | Remover | Inserir uma no topo | Commit sem mudança nelas |
|---|---|---|---|---|
| 100 | 1,7 ms | 2,7 ms | 4,0 ms | 41 µs |
| 1000 | 11 ms | 6,8 ms | 30 ms | 117 µs |
| 4096 | 76 ms | 39 ms | 929 ms | 379 µs |

Inserir no topo renumera todas as de baixo, e o kernel percorre a lista a cada inserção. É o pior caso
de uma operação rara. A primeira regra sobre 200 000 rotas na `main` levou 3,7 ms: o `fib_unmerge`,
que roda uma vez, não pesa.

## Na GUI

Routing › Rules tem três abas. **Rules** lista as regras em ordem, com ação e tabela em selos, Move Up e
Move Down, o modal de adicionar e editar (o motor faz a prévia e pergunta antes de cortar a sessão) e
**Test a Packet**, que mostra a regra que decidiu e por quais passou. **Tables** lista as tabelas,
incluindo `main` e VRFs, que ficam travadas. **Kernel List** mostra a lista do kernel com o dono de cada
linha, o drift e as marcas sem tabela.
