id: audit-net

Auditoria de interfaces, endereços, rotas, VRF, listas de interface e firewall (com a aplicação no
kernel): 12 dos 14 achados corrigidos aqui, 2 já tinham entrado pelo `audit-persist` (#123), 1
parte vira gap. Resolve a gap **G0.14** (validação do firewall O(n²) no commit). Cada teste
abaixo falhou na `main` (63116ed) antes da correção (**medido**: rodados com o código da `main` e
a API adaptada); os de desempenho têm bench antes/depois na seção `## perf`.

Corrigido:

- **Alto — validar o firewall era O(N²) em todo commit** (#1, G0.14). `rule_issues` clonava a
  tabela inteira e remontava o grafo de jumps para cada regra; com 3000 regras qualquer commit
  levava ~0,58 s em release. Agora `validate` monta as arestas uma vez por tabela
  (`graph::edges`) e guarda as raízes de cada chain (`graph::roots_in`); o comando de uma regra
  só monta o grafo uma vez, sem clonar. Bench `engine_scale/validate_all/filter_rules/3000`:
  562 ms → 0,22 ms; `commit/filter_rules/3000`: 584 ms → 49 ms (o resto é gravar o arquivo).
- **Alto — validar rotas era O(R²) em todo commit** (#2). Cada rota era comparada com todas as
  anteriores; agora só com as do mesmo `(routing_table, dst_address)` (`BTreeMap`).
  `validate_all/routes/10000`: 48 ms → 1,2 ms. Teste `duplicate_routes_are_found_across_the_list`
  (guarda: duplicata separada por outras rotas ainda é achada).
- **Médio — expirar entradas dinâmicas rodava um `nft` por entrada, sob o lock** (#3). Agora a
  expiração vai num só `DynamicChange::Expired(&[..])` (variante nova, aditiva, em `hal`); o
  `LinuxHal` não roda nada (o timeout do próprio set já as tirou do kernel), o lab esquece todas
  de uma vez. Teste `dynamic_entries_expiring_together_are_one_data_plane_change` (300 entradas:
  1 chamada, eram 300).
- **Médio — porta sem gaiola SFP era sondada a cada 30 s, sob o lock** (#3). O `scan_modules`
  lembra as portas que respondem "sem EEPROM de módulo" (`Unsupported`) e não pergunta de novo
  (porta que sai da config volta a ser sondada). Teste
  `ports_without_a_cage_are_not_probed_on_every_scan` (4 varreduras de 8 portas: 8 leituras,
  eram 32). Tirar a varredura de dentro do lock vira a gap G1.22.
- **Médio — remover endereços era O(n²) no kernel** (#4). Cada `DelAddress` fazia um dump
  `RTM_GETADDR` de todos os endereços do namespace (filtrado em espaço de usuário); agora manda
  `RTM_DELADDR` com o endereço montado (`AddressMessageBuilder`), e o kernel responde
  EADDRNOTAVAIL se ele já não está. Bench netns novo `hal_linux_apply/addresses_remove/1000`:
  260 ms → 32 ms.
- **Médio — IPv6 com o mesmo endereço e outro prefixo era aceito e não instalado** (#5). O Linux
  identifica o endereço IPv6 só por endereço + interface (EEXIST no segundo), o plano adotava o
  erro como "já existe" e, removido o primeiro, a interface ficava sem endereço. Agora
  `ip.address.add` e `validate_all` recusam ("2001:db8::1 is already on ether1 as
  2001:db8::1/64"); outra interface, outro pool e IPv4 com outra máscara continuam valendo.
  Testes `an_ipv6_address_cannot_be_on_one_interface_twice_with_two_prefixes`,
  `validation_refuses_an_ipv6_address_twice_on_one_interface`.
- **Médio — renomear lista de interfaces quebrava RA e DNS** (#6). `interface.list.set
  new_name` agora leva junto `ipv6.settings accept_router_advertisements_on` e os itens de
  `ip.dns allowed_from` (como o RouterOS); células da matriz de zonas entram no `used_by` (a
  renomeação é recusada, como já era com regras). `interface.list.remove` de uma lista que o DNS
  usa é recusado com o motivo (antes: erro de validação sem relação no commit). Testes
  `renaming_an_interface_list_renames_its_references`,
  `removing_an_interface_list_dns_uses_is_refused`.
- **Médio — checagem de lockout via a interface errada** (#7, parte que faltava). A sonda usava
  como entrada a interface que tem o endereço local: com gerência num loopback /32 (`lo0`)
  alcançado pela WAN, um `drop` na lista WAN passava. Agora a entrada é a interface para onde o
  roteamento aponta o par (rede conectada ou rota mais específica, na tabela do endereço local;
  sem rota, a de antes). E `ip.firewall.address-list.add` com timeout checa sobre a config
  efetiva (endereços/rotas de DHCP), como o commit. Testes
  `lockout_sees_the_wan_ingress_of_a_loopback_management_address`,
  `lockout_uses_the_port_facing_a_connected_peer`.
- **Baixo — `ip.route.list` era O(L²)** (#8): o vencedor de cada grupo (tabela, destino) sai numa
  passada. `ip.route.list/10000`: 64,6 ms → 14,0 ms.
- **Baixo — endereços sem limite e com etapas quadráticas** (#9). `MAX_ADDRESSES` = 65 536 em
  `ip.address.add` e `validate_all` (`corerouter_engine::validate::MAX_ADDRESSES`);
  `route::connected` deduplica com `BTreeMap`; `plan::rebuilt_links` calcula os links com IPv4
  uma vez. Teste `addresses_are_bounded`.
- **Baixo — address-lists: varreduras lineares e render duplo** (#10). `render` agrupa entradas
  por lista e regras por chain uma vez (era O(listas × entradas)); `nft::changed` só renderiza
  quando firewall ou listas de interface mudaram (o `LinuxHal` e o lab renderizavam as duas
  configs em todo commit); entradas dinâmicas têm índice `(lista, endereço)`.
- **Baixo — `address-list.set` duplicava uma entrada dinâmica** (#11). Agora confere as
  dinâmicas como o `add`. Teste `address_list_set_refuses_an_address_a_dynamic_entry_has`.
- **Baixo — `nft` e genl sem prazo total** (#12). `nft::run_bounded` mata o `nft` depois de 30 s
  (stdin, stdout e stderr em threads, para um filho que não lê nem sai também não travar), usado
  por `run` e `list_json`; `Genl::call` tem um prazo de 1 s para a resposta inteira (notificações
  de multicast reiniciavam o timeout de cada `poll`). Testes `nft::tests::*`.
- **Baixo — `LinkWatch::observe` era O(vigiados × vivos) por segundo** (#13): `BTreeSet`.
- **Lab — `VirtualHal::carry`** recalculava o estado esperado inteiro das duas configs em todo
  apply; agora só a parte cujas entradas mudaram (links/endereços só se interfaces ou endereços
  mudaram; com só rotas mudando, só as rotas alteradas). Um commit que não toca rotas não resolve
  nenhuma. `hal_virtual_apply/routes/1000` (todas as rotas novas) continua ~120 µs: é o custo de
  resolver 1000 rotas novas.

Já corrigidos pelo `audit-persist` (#123), conferidos na `main`: #14 (o lockout só olhava o
firewall; agora também endereço e interface) e a parte de #7 sobre a interface do endereço em
cada lado.

Conferido e falso ou parcial: #6 dizia que nenhuma validação conferia
`accept_router_advertisements_on` — o `proto-dhcp` confere; o problema real era o modo
transacional aceitar a renomeação e todo commit seguinte falhar com erro sem relação (corrigido
acima).

Como testar: `cargo test -p corerouter-engine --test net_audit`; `cargo bench -p
corerouter-engine --bench scale`; `COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net
-- cargo bench -p corerouter-hal-linux --bench netns_apply -- addresses_remove`.

Observação (**estimado**, sem perfil: `perf` não é permitido na máquina): com as validações
lineares, o commit com 10 000 rotas ou 20 000 entradas de address-list ainda leva ~0,3 s; o resto
é gravar o arquivo (a running + até 64 revisões inteiras, até 32 MiB, a cada commit). Vira a gap
G1.23.

| G1.22 | Varredura SFP/DOM fora do lock da sessão | engine (`dom_watch`), control (`clock`), hal-linux | O `scan_modules` do `tick` lê até 64 EEPROMs (até 4 chamadas genl de 1 s cada) com o lock da sessão: um driver travado congela comandos por minutos. Ler numa thread própria e entregar as leituras ao engine; teste com HAL cujo `sfp_module` demora 200 ms: um comando durante a varredura responde em < 50 ms | 4 h | aberto |
| G1.23 | Commit não regrava o histórico inteiro | engine (`session.rs`), model (`persist`), storage-fs | Todo commit serializa a running e até 64 revisões completas (até 32 MiB): com 10 000 rotas `engine_scale/commit/routes/10000` leva ~0,36 s (**medido**), quase tudo gravação (**estimado**). Gravar revisões como diferenças, ou só a running a cada commit e o histórico em arquivos à parte; bench `engine_scale/commit/*` < 50 ms com 10 000 rotas | 6 h | aberto |

## perf

### audit-net: validação, listagem e remoção com tabelas grandes (2026-10-23, **medido**)

AMD Ryzen AI MAX+ 395 (32 CPUs), build release (`cargo bench`), criterion. Bench novo
`crates/engine/benches/scale.rs` (config grande já em vigor, restaurada do armazenamento):
`validate_all/<tipo>/N` é a validação do commit; `commit/<tipo>/N` é um `interface.set comment`
(não toca a lista grande); antes = `main` dbbd394, depois = esta branch.

| Bench | Antes | Depois |
|---|---|---|
| `engine_scale/validate_all/filter_rules/1000` | 54,9 ms | 73 µs |
| `engine_scale/validate_all/filter_rules/3000` | 562 ms | 0,22 ms |
| `engine_scale/commit/filter_rules/1000` | 77 ms | 16,9 ms |
| `engine_scale/commit/filter_rules/3000` | 584 ms | 48,9 ms |
| `engine_scale/validate_all/routes/1000` | 499 µs | 103 µs |
| `engine_scale/validate_all/routes/10000` | 48,2 ms | 1,21 ms |
| `engine_scale/ip.route.list/1000` | 1,37 ms | 1,05 ms |
| `engine_scale/ip.route.list/10000` | 64,6 ms | 14,0 ms |
| `engine_scale/commit/routes/10000` | 344 ms | 364 ms (gravação; G1.23) |
| `engine_scale/commit/address_lists/20000` | 355 ms | 328 ms (gravação; G1.23) |

Kernel (netns sem root, `hal-linux/benches/netns_apply.rs`; antes = 63116ed):

| Bench | Antes | Depois |
|---|---|---|
| `hal_linux_apply/addresses_remove/100` (novo: remover N endereços) | 4,85 ms | 2,82 ms |
| `hal_linux_apply/addresses_remove/1000` | 260 ms | 31,6 ms |

`hal_virtual_apply/*` ficou igual (±5%: o `carry` só ganha em commit que não muda rotas nem
endereços; esse bench aplica N itens novos). `engine_execute/*` igual (±1%), exceto
`rejected_param` (1,17 → 1,60 µs) e `virtual_lab_new` (7,0 → 7,5 µs), caminhos que este PR não
toca: o "antes" foi medido em 63116ed, antes do merge do #123.
