id: valida-fw-raw-delta

Delta de revisão do firewall sem serializar a tabela raw. Achado na validação das rodadas 1 e 2 na
VM `corerouter-teste` (imagem `cb5867de`): com 4 000 regras raw, todo commit que mexia no firewall
(uma regra de filter, até só o comentário) serializava a tabela raw inteira duas vezes e a
comparava por `json_delta` para gravar a revisão. O `config_delta::diff_firewall` e o
`apply_firewall` tiravam filter, nat, mangle e address lists da parte "pequena" do delta, mas
não a raw, que veio depois (G2.1c). Agora uma função só, `light_firewall`, serve os dois lados e
desestrutura o `Firewall` inteiro: tabela nova sem tratamento não compila. A raw virou lista
grande como as outras (`{"a": …}` por blocos do `CowList`); uma revisão gravada antes continua
abrindo (o delta antigo da raw é aplicado pela árvore JSON, como qualquer lista).

Como testar: `cargo test -p corerouter-model --lib config_delta` (os testes novos
`one_raw_rule_of_many_is_one_small_delta`, que compara com o diff da árvore e confere que a raw
fica compartilhada quando muda uma regra de filter, e `the_light_firewall_has_no_rule_table`, que
reprova se alguma tabela de `Table::ALL` sobrar na parte pequena). Benchmark novo:
`cargo bench -p corerouter-model --bench config_delta`.

Desempenho e paralelismo: o trabalho por commit de firewall era O(regras raw) no delta do journal,
sob o lock do `Session`; agora é O(blocos mudados), como filter/nat/mangle. Não há o que dividir em
threads: o delta é um por commit e pequeno. O commit de uma regra com 10 000 regras ainda leva
~100 ms de ponta a ponta na VM (2 vCPUs) e 90–110 ms no host carregado: o resto está fora do delta
(validação do firewall inteiro, `fw_delta`, alocação), medido mas não atacado aqui (G0.31j).

Achados da mesma validação que viram gaps (números **medidos** na VM `corerouter-teste`, 2 vCPUs,
2 GiB, e reproduzidos no host num namespace sem root, release, 2026-10-29):

| G0.31h | `ip.route.list` com 60 000 rotas sem estourar a memória | engine, control | Na VM de 2 GiB, uma chamada levou o RSS do daemon de 307 para 847 MiB (34 MB de JSON, ~9 KiB de pico por linha: árvore `serde_json::Value` de 31 chaves por linha, a string inteira e a cópia do TLS), e o alocador não devolve; com outra chamada em seguida o kernel matou o daemon por OOM (1,85 GiB, `notice-w0 invoked oom-killer`) e o `corerouter-init` o reiniciou. No host: 274 → 720 MiB de pico. Critério: pico abaixo de 2× o tamanho da resposta (linhas serializadas direto no buffer, sem árvore `Value`, ou resposta em pedaços) e uma consulta grande por vez (fila com "ocupado"), medido com 60 000 rotas e com duas conexões ao mesmo tempo | 6 h | aberto |
| G0.31i | Commit de `ip.route.set` (distância) sem ler as rotas do kernel inteiras | hal-linux, engine | Mudar a distância de uma rota entre 60 000 leva 105 ms na VM e 85–230 ms no host (`perf`: o dump `RTM_GETROUTE` inteiro em `netlink::static_routes` e um `BTreeSet<KernelRoute>` das 60 000 a cada commit); acrescentar uma rota leva 16–45 ms e mudar só o comentário 6–15 ms. Critério: o `set` só lê o destino tocado, como o `add` da G0.31 parte 5 e o plano da G0.31e, com número antes e depois | 4 h | aberto |
| G0.31j | Firewall: o resto do commit de uma regra com milhares | engine, hal-linux | Com 4 000 filter + 4 000 raw + 2 000 mangle, o commit de uma regra (até só o comentário) ainda leva ~100 ms na VM e no host, contra 6 ms de um commit sem firewall; o `fw_delta` da G0.31f promete ~1,5 ms nosso. Perfilar com `perf` (validação inteira, sombra, `fw_delta`, alocação) e cortar o que for O(regras). Também: `MAX_RULES` é 4 096 por tabela, então a "config de ISP com 10 000 regras de filtro" dos benchmarks da G0.31 não existe no produto (o `ip.firewall.filter.add` recusa a 4 097ª); decidir com o usuário se o limite sobe ou se os benchmarks passam a usar o que o produto aceita | 4 h | aberto |
| G1.5a | Rotas `blackhole`, `unreachable` e `prohibit` | model, engine, hal-linux, ui | O RouterOS tem `/ip route add blackhole dst-address=…` (e `type=unreachable`/`prohibit`), usado por ISP para anular pools, agregados de CGNAT e prefixos anunciados por BGP; aqui o `gateway` só aceita IP ou interface (`interface 'blackhole' does not exist`). Rota do kernel `RTN_BLACKHOLE`/`RTN_UNREACHABLE`/`RTN_PROHIBIT`, coluna e selo na janela Routes, redistribuição no BGP/OSPF como estática | 4 h | aberto |
| G3.9hl | Terminal: `/interface vlan print` e os outros `print` de submenu | shell, engine | No RouterOS `/interface vlan print` lista as VLANs; aqui dá `bad command name 'print'` (só existe `interface.vlan.add`; a lista é `interface.list` com `type`). Mapear o `print` dos submenus de interface (`vlan`, `bridge`, `bonding`, `pppoe-client`) para `interface.list {type}` com as colunas do RouterOS, e o mesmo para o `export` | 2 h | aberto |

## perf

### Delta de revisão de um commit de firewall (valida-fw-raw-delta, **medido**)

2026-10-29, AMD Ryzen AI Max+ 395 (32 threads), release, máquina compartilhada (load 40–60).
`cargo bench -p corerouter-model --bench config_delta`, `--save-baseline antes` com as linhas da
correção revertidas e `--baseline antes` com elas:

| Caso | Antes | Depois |
|---|---|---|
| `config_delta/one_filter_rule_of_10000` (4 000 filter + 4 000 raw + 2 000 mangle, uma regra de filter mudada) | 31,2 ms | 68 µs (−99,7 %) |

De ponta a ponta (daemon release `--backend linux` num namespace sem root, commit de uma regra de
filter, 15 commits por rodada) o ganho ficou dentro do ruído da máquina carregada: 90–110 ms antes
e depois (G0.31j).
