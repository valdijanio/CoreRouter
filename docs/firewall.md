# Firewall (G2.1)

Modelo do `/ip firewall` do MikroTik RouterOS (filter, nat, mangle, address-lists) e do
`/interface list`, aplicado no Linux com nftables. Nomes e semântica seguem a documentação
oficial da MikroTik (Filter, NAT, Mangle, Address-lists, Interface Lists, Connection tracking);
este texto é nosso.

Entregue em três PRs:

| Sub-item | Conteúdo | Status |
|---|---|---|
| G2.1a | Modelo, comandos, listas de interfaces, address-lists, render nftables, aplicação atômica, janelas Firewall e Interface List | este documento |
| G2.1b | Aviso de lockout, regras sombreadas, configuração inicial segura, modelos prontos, modo por zonas, descrição em português e cores; ação `add-src/dst-to-address-list` e matcher `limit` | este documento (§6–§11) |
| G2.1c | Testador de pacotes, contadores ao vivo com "último uso", prévia do diff do nftables | aberto |

## 1. Diferenças em relação ao RouterOS

| RouterOS | CoreRouter | Por quê |
|---|---|---|
| `/ip firewall` e `/ipv6 firewall` separados | uma lista só; cada regra tem `family` (`both`, `ipv4`, `ipv6`) | uma política, um lugar; endereços IPv4/IPv6, `protocol=icmp`/`icmpv6` e `to-addresses` restringem a família sozinhos (conflito = erro) |
| regra comum com comentário como título | regra-cabeçalho de seção (`section`) | agrupa regras na GUI (faixa de título) sem tocar o data plane |
| `log=yes` em qualquer regra | ação `log` (+ `log_prefix`), que continua para a próxima regra | o mesmo efeito; `log=yes` fica para depois |
| ações `redirect`, `netmap`, `tarpit` … | ainda não | G2.3 |
| `fasttrack-connection` | uma opção só, `ip.firewall.fastpath.set` (o flowtable roda depois das regras; `docs/fastpath.md`); exceções por regra no G2.4c | G2.4 |
| `limit=50/5s,2:packet` (qualquer tempo, modo `bit`) | `limit=50/1s,2` — tempo 1s, 1m, 1h ou 1d, só pacotes | são as unidades do `limit` do nftables |
| `address-list-timeout=none-dynamic` / `none-static` | sem `address_list_timeout` = até reiniciar; não existe entrada estática criada por regra | entradas de regra moram no kernel (§3) |
| marcas como nomes | nomes também; no kernel viram números estáveis (§3) | — |
| lista de interfaces com `include`/`exclude` | só membros diretos | primeira versão |

## 2. Comandos

Formato dos parâmetros: o do RouterOS, com `_` no lugar de `-` e `!` para negar
(`src_address=!10.0.0.0/8`, `dst_port=22,80,8000-8080`,
`connection_state=established,related`). `""` em `set` apaga o matcher.

| Comando | Faz |
|---|---|
| `ip.firewall.{filter,nat,mangle}.add` | regra (ou seção, com `section: "título"`); `place_before: *id` como no RouterOS |
| `….set` | muda campos; trocar `action` mantém os matchers e descarta os campos da ação antiga |
| `force: true` (em `add`/`set`/`remove`/`move`, address-list, membros de lista, `config.commit`, `config.rollback`, modelos, zonas) | aplica mesmo que corte a conexão de gerência (§6) |
| `….remove`, `….move {id, destination?}` | `move` põe acima de `destination` (sem ele: no fim) |
| `….list {chain?}` | regras com `position`, `flags` (`X` desativada, `I` inválida + `reason`) e `summary` no formato do `print` do RouterOS |
| `ip.firewall.address-list.add {list, address, timeout?}` | sem `timeout`: entrada estática (config); com: **dinâmica** (§4) |
| `ip.firewall.address-list.{set,remove,list}` | `set` só em estáticas |
| `interface.list.{add,set,remove,list}` | listas; `remove` recusa enquanto uma regra usa a lista e leva os membros junto |
| `interface.list.member.{add,set,remove,list}` | membros; interface que sumiu aparece com flag `I` (o kernel casa pelo nome) |

Configs novas já trazem as listas `LAN` e `WAN`, vazias (como a configuração padrão do
RouterOS). `all`, `none`, `dynamic` e `static` são reservados.

Validação (`corerouter-firewall::validate`, também chamada por regra nos comandos para o erro
apontar o parâmetro):

- ação existe na tabela: filter `accept drop reject jump return log passthrough`; nat
  `accept masquerade src-nat dst-nat jump return log passthrough`; mangle `accept mark-connection
  mark-packet mark-routing jump return log passthrough`; nas três, `add-src-to-address-list` e
  `add-dst-to-address-list` (`address_list`, `address_list_timeout` opcional; o pacote segue para
  a próxima regra, como no RouterOS);
- `masquerade`/`src-nat` só em `srcnat`, `dst-nat` só em `dstnat`, `mark-routing` só em
  `prerouting`/`output` — numa chain própria, toda chain nativa que pula para ela precisa permitir;
- `src_port`/`dst_port`/`to_ports` exigem `protocol` tcp, udp, sctp ou udp-lite (não negado);
  `icmp_options` exige icmp/icmpv6; `reject_with=tcp-reset` exige tcp;
- interface de entrada na `output` e de saída em `input`/`prerouting`/`dstnat` nunca casam: erro;
- `src-nat`/`dst-nat` exigem `to_addresses` (um endereço ou faixa `A-B`, não prefixo);
- `jump` para chain nativa ou para a própria chain, laços de `jump` (`a → b → a`): erro;
- nomes (listas, chains, marcas): letras, dígitos, `-`, `_`, `.`, até 63; `log_prefix` ASCII
  imprimível sem `"`/`\`, até 64; limites contra entrada hostil: 4096 regras por tabela,
  65 536 entradas de address-list, 256 listas, 4096 membros (**estimados**).

## 3. Render nftables

Tabela única **`inet corerouter`** (IPv4 e IPv6 juntos). Nada fora dela é lido ou alterado:
regras do Docker, libvirt ou da distribuição continuam onde estão.

| RouterOS | nftables |
|---|---|
| filter `input`/`forward`/`output` | base chains `filter_<chain>`, hook igual, prioridade `filter` |
| nat `dstnat` / `srcnat` | `nat_dstnat` (prerouting, `dstnat`) / `nat_srcnat` (postrouting, `srcnat`) |
| mangle | `mangle_<chain>`, prioridade `mangle`; `output` é `type route` (marca de roteamento reroteia) |
| chain própria `x` | chain comum `<tabela>_x`, alcançada por `jump` |
| address-list `x` | sets `al4_x` e `al6_x` (`flags interval, timeout`, `auto-merge`) |
| lista `x` preenchida por `add-*-to-address-list` | também `ad4_x`/`ad6_x` (`flags dynamic, timeout`, `size 65536`) |
| `limit=5/1s,10` | `limit rate 5/second burst 10 packets` (depois dos outros matchers) |
| interface list `x` | set `il_x` de `ifname` |
| regra `*N` | uma regra (ou uma por família, se usa address-list e vale para as duas), sempre com `counter` e `comment "cr:*N"` |
| marca de conexão | `ct mark` = FNV-1a do nome (≠ 0) |
| marca de pacote / de roteamento | 16 bits baixos / altos do `meta mark` (roteamento: `ip rule fwmark …/0xffff0000`, futuro) |

O kernel não deixa o caminho dos pacotes inserir num set de intervalos (`interval`), e as listas
estáticas precisam de prefixos e faixas. Por isso uma lista que alguma regra preenche ganha um
segundo set, sem intervalos (`ad*`); uma regra que casa essa lista vira duas regras disjuntas —
`ip saddr @al4_x` e `ip saddr @ad4_x ip saddr != @al4_x` — para uma ação que segue adiante (log,
marca, outro `add`) nunca rodar duas vezes; `!@x` é `!= @al4_x != @ad4_x` numa regra só. Os
elementos dos sets `ad*` (com ou sem prazo) são lidos antes de cada troca de tabela e recolocados;
quando nenhuma regra preenche mais a lista, eles somem com o set. Testado num kernel real
(`netns_nft.rs`: um SYN enche o set, a troca preserva, a regra da lista conta o pacote). Essas
entradas não aparecem em `address-list.list` (o engine não as vê; ler o kernel é do G2.1c).

Política das chains nativas: `accept` (o RouterOS aceita o que nenhuma regra decidiu). Regras
desativadas e seções não vão para o kernel. Duas marcas cujo número colide são recusadas pelo
validador.

Aplicação (`hal-linux`, módulo `nft`): quando o ruleset renderizado muda, o `LinuxHal` roda
`nft -f -` com

```
table inet corerouter
delete table inet corerouter
table inet corerouter { … }
```

O `nft` compila o texto e manda **um** lote netlink, que o kernel aplica inteiro ou recusa inteiro
— troca atômica. Por que o programa `nft` e não netlink direto do Rust: a API do nftables é uma
VM de bytecode; os crates Rust ou embrulham a libnftnl em C (FFI, `unsafe`) ou não cobrem o que
usamos (sets com intervalo e timeout, `ct status`, faixas de NAT). O texto é montado só com
valores validados (nomes com charset restrito, `quoted()` ainda filtra aspas e barras).

Ordem no commit: nftables primeiro (se recusar, nada mudou), depois o plano netlink (links,
endereços, rotas); se o netlink falhar e desfazer, o ruleset anterior é recarregado. Sem
firewall na config a tabela é apagada; sem mudança no firewall o `nft` nem é chamado (um host
sem nftables continua funcionando para o resto). O `VirtualHal` guarda o script que aplicaria
(`VirtualHal::ruleset`).

Golden: `crates/firewall/tests/golden/full.nft` (uma config que usa todo matcher e ação,
`corerouter_firewall::sample`); `UPDATE_GOLDEN=1 cargo test -p corerouter-firewall` regenera.
O mesmo ruleset é carregado num kernel real em `crates/hal-linux/tests/netns_nft.rs` (namespace
descartável, sem root; `cargo xtask netns`): aplica, preserva tabela de outro dono, troca, recusa
um ruleset inválido sem mudar nada (dnat em postrouting) e remove.

## 4. Entradas dinâmicas de address-list

Com `timeout` (`30s`, `5m`, `1h30m`, `1d`, até 35 dias) a entrada é **estado operacional**, como
os vizinhos: não entra na config nem no `running.json`, não gera revisão, some num reinício (o
RouterOS faz igual com as dinâmicas). Ids `*D0000001…` para nunca colidir com as estáticas.

- O engine manda cada uma ao data plane por `Hal::address_list_dynamic` (no Linux,
  `add element … timeout Ns`), e o kernel a expira sozinho.
- Uma troca de tabela (commit) lê antes os elementos com `expires` dos nossos sets
  (`nft -j list table inet corerouter`) e os recoloca com o tempo que falta. Uma entrada que o
  kernel acrescente entre a leitura e a troca (milissegundos) se perde: aceitável para listas de
  bloqueio temporário.
- O engine espelha a tabela para `address-list.list` (`timeout` = segundos restantes) e expira no
  `Session::tick`. Sem relógio (wasm `?lab`) a contagem começa no primeiro tick.

## 5. GUI (G2.1a + G2.1b)

IP › Firewall: abas Filter Rules / NAT / Mangle / Address Lists sobre a tabela do G1.9 (seleção,
menus, Delete/Ctrl+E/D/M/Enter, comentários inline G1.10/G1.17, maximizar G1.12, botões cinza
com o motivo G1.16). Regras: colunas `#`, flags, Chain, Action, Src./Dst. Address (`@lista` para
address-list), Proto., portas, In./Out. Interface (`[LAN]` para lista), Comment; cor por ação
(aceitar verde, bloquear vermelho, NAT azul, marca roxo; inválida na cor de erro); seções como
faixa de título; filtro por chain; ▲/▼ e arrastar a linha mudam a ordem (`move`; com filtro de
chain o arraste fica desligado para não confundir a posição). Duplo clique abre "Filter Rule
<*N>" com as abas General / Advanced / Action do WinBox; "Section" cria um cabeçalho.
Interfaces › Interface List: abas Members e Lists. As listas só são pedidas ao daemon com a janela
aberta.

G2.1b acrescenta: coluna **Descrição** (§11) antes de Comment; regra sombreada (§7) com flag `S`,
linha na cor de aviso e "NUNCA CASA: a regra #N acima já decide estes pacotes." na descrição;
regras da matriz com flag `Z` e Remove/Disable/Comment/▲/▼ cinza com o motivo; botão
**Templates** (Safe Defaults, Port Forward, Block Address, Brute Force Protection, Limit Ping,
Management From LAN Only), cada um uma janela com a explicação em português e os campos do
comando, erro do engine na própria janela; aba **Zones** (§10); e a janela **This change would
lock you out** (§6).

## 6. Aviso de lockout

O canal de controle diz ao engine qual conexão TCP mandou cada comando (`Caller::link`: endereço
do cliente e nosso endereço local; `lo` se for loopback, senão a interface que tem o endereço
local). Em todo commit (modo imediato, `config.commit`, `config.rollback`, batch) que muda o
firewall ou as listas de interfaces, o engine passa os pacotes dessa conexão pelo firewall atual
e pelo candidato (`corerouter_firewall::eval`, o mesmo caminho que o testador do G2.1c usará):

| Pacote | Chain | Corta se |
|---|---|---|
| estabelecido, cliente → roteador | filter `input` | drop/reject |
| resposta, roteador → cliente | filter `output` | drop/reject |
| conexão nova do mesmo endereço à mesma porta (logar de novo) | filter `input` | drop/reject |
| a mesma conexão nova | nat `dstnat` | um `dst-nat`/redirecionamento a pega |

Se o candidato corta e o atual não, o commit é recusado com `lockout: filter rule *5 (chain=input
action=drop in-interface-list=WAN) would drop this connection (tcp 198.51.100.7:50123 ->
203.0.113.1:8729 on ether1). Enter Safe Mode first …, or repeat with force=true`. Não há recusa:

- com `force: true` no comando (vale só para ele; num batch, para o batch inteiro);
- em Safe Mode (G1.4): perder a conexão já desfaz a mudança;
- para quem está dentro do processo (GUI em lab, testes, `corerouter-cli run` sem `--connect`):
  não há conexão a perder; e o desfazer do Safe Mode nunca é checado (restaura uma config que
  estava rodando).

Uma entrada dinâmica de address-list (com `timeout`, que não passa por commit) é checada ao ser
criada. Suposições do avaliador, sempre as mesmas: o pacote não tem marcas, a conexão não foi
NATeada, um `limit` não está estourado, e as listas têm as entradas estáticas e as dinâmicas do
engine (as que regras puseram no kernel são desconhecidas).

Na GUI, uma recusa assim abre **This change would lock you out** com o motivo e três botões:
**Safe Mode, then apply** (`config.safe-mode.enter` e o mesmo comando de novo), **Apply anyway**
(o mesmo comando com `force: true`) e **Cancel** (o erro volta para a janela que mandou). Só para
comandos que declaram `force`.

## 7. Regras sombreadas

`corerouter_firewall::shadow`: a regra B é sombreada pela regra A anterior da mesma chain quando
A está ativa, **decide** (accept, drop, reject, return, NAT, marca sem passthrough) e cobre B:
todo matcher de A existe em B com valor dentro do de A — endereço/prefixo/faixa dentro, portas
dentro, estados entre os de A, protocolo igual (ou `!udp` cobre `tcp`), a interface membro da
lista de A, ICMP do mesmo tipo, mesma família ou A em `both`. Negações são comparadas pelo
conjunto que casam (`!10.0.0.0/8` cobre `192.168.0.0/16`). O que a análise não compara (um
`limit` em A, address-lists diferentes) conta como "não cobre": ela perde alguns casos, mas nunca
acusa uma regra que casa. No `list`: `shadowed_by` (id de A) e flag `S`. Limite contra config
hostil: 2 milhões de comparações por tabela (**estimado**; ~0,1 s).

## 8. Configuração inicial segura

`ip.firewall.defaults.apply {lan?, wan?, replace?, force?}` — a configuração padrão do RouterOS
(SOHO), com IPv6 e loopback, numa seção `defconf:` no topo do filter:

| Chain | Regra |
|---|---|
| input | aceita `established,related,untracked`; descarta `invalid`; aceita ICMP; aceita ICMPv6; aceita `in-interface=lo`; descarta `in-interface-list=!LAN` |
| forward | aceita `established,related,untracked`; descarta `invalid`; aceita ICMPv6; descarta `new` vindo da `WAN` sem `dstnat` |
| srcnat | `masquerade` IPv4 saindo pela `WAN` (no fim do nat) |

`lan`/`wan` põem interfaces nas listas antes. Recusa com a LAN vazia (tudo de fora da LAN seria
descartado, inclusive você). Rodar de novo é recusado se já há regras `defconf…`; `replace: true`
as remove e aplica de novo. Tudo editável depois; cada regra tem o porquê no comentário.

## 9. Modelos prontos

Comandos (um commit cada; os assistentes da GUI só preenchem os parâmetros). As regras vão para o
topo da chain (acima de cabeçalhos de seção logo acima e nunca dentro do bloco das zonas), com
comentário em português:

| Comando | Gera |
|---|---|
| `ip.firewall.template.port-forward {dst_port, to_addresses, to_ports?, protocol?, dst_address?, in_interface_list? (WAN)}` | `dst-nat` em dstnat (fim do nat) + `accept` em forward com `connection-nat-state=dstnat`, acima do primeiro drop/reject da forward |
| `ip.firewall.template.block-address {address, list? (blocked), timeout?}` | entrada na lista (estática ou dinâmica) e, se ainda não existem, `drop src-address-list=<lista>` em input e forward |
| `ip.firewall.template.brute-force {dst_port? (22,8729), attempts? (3), stage_timeout? (1m), block_timeout? (10d), name? (bruteforce)}` | seção; `drop` da lista negra; para cada estágio, do maior ao menor, `add-src-to-address-list` do estágio k para o k+1 (o último para a lista negra); conexão nova → estágio 1. Uma conexão nova sobe um estágio só |
| `ip.firewall.template.ping-limit {limit? (5/1s,5)}` | seção; aceita echo-request ICMP e ICMPv6 até o limite; descarta o excesso |
| `ip.firewall.template.lan-management {dst_port?, list? (LAN)}` | seção; aceita as portas de `lo` e da lista; descarta o resto. Sem portas: 22, 8729 e a porta da conexão atual. Recusa com a lista vazia |

Bloquear o próprio endereço ou fechar a gerência estando fora da LAN cai no aviso de lockout (§6).

## 10. Modo simples por zonas

Zonas = listas de interfaces + `router` (o roteador; uma lista chamada `router` não é zona). A
matriz (`ip.firewall.zones` na config) diz, para conexões novas de uma zona (linha) para outra
(coluna), `allow` ou `block`; célula vazia = as outras regras decidem.

| Comando | Faz |
|---|---|
| `ip.firewall.zone.list` | zonas, células e ids das regras geradas |
| `ip.firewall.zone.set {from, to, action: allow \| block \| none, force?}` | muda uma célula (`none` a apaga) e reescreve o bloco |
| `ip.firewall.zone.clear {force?}` | esvazia a matriz e apaga o bloco |
| `ip.firewall.zone.detach` | as regras geradas viram regras comuns; a matriz fica vazia |

O bloco gerado (flag `Z`, campo `zone`): cabeçalho de seção; por chain usada, aceita
`established,related` e descarta `invalid`; depois uma regra por célula — `L → router` em input
(`in-interface-list=L`), `router → L` em output (`out-interface-list=L`), `L1 → L2` em forward.
Fica no topo do filter na primeira vez e, a cada mudança, é reescrito inteiro **no mesmo lugar**.

Conflito com edição manual, de forma explícita: as regras geradas pertencem à matriz. `set`,
`remove` e `move` de uma regra `zone` são recusados ("generated by the zone matrix: change the
matrix (ip.firewall.zone.set), or ip.firewall.zone.detach…"), assim como pôr uma regra comum
**dentro** do bloco (`place_before`/`destination` numa regra gerada que não é o cabeçalho; acima
do cabeçalho pode). Quem quer assumir à mão usa `detach`: nada muda no data plane, as regras
ficam editáveis e a matriz some. A GUI mostra o mesmo: botões cinza com o motivo, e o texto da
aba Zones explica. Regras comuns acima do bloco valem antes dele (é assim que se abre uma
exceção).

## 11. Descrição em português e cores

`corerouter_firewall::describe` gera uma frase por regra a partir da ação, da chain e dos
matchers ("Descarta pacotes para o roteador, que não entram pela lista LAN."; "Redireciona para
10.0.0.20 porta 80 pacotes TCP que chegam (antes do roteamento), para a porta 8080, que entram
pela ether1."); `description` no `list`, coluna Descrição na GUI. Cores por ação, as mesmas na
tabela e na matriz: aceitar verde, bloquear (drop/reject) vermelho, NAT azul, marca roxo; regra
inválida na cor de erro e sombreada na de aviso do tema. Testado: contraste WCAG ≥ 4,5:1 com o
fundo nos temas claro e escuro.

## 12. Connections (G2.2)

A aba **Connections** da janela IP › Firewall é a tabela do conntrack, como o
`/ip firewall connection` do RouterOS. O `hal-linux` a lê por **ctnetlink** (`crates/hal-linux/src/ctnl.rs`:
dump, estatísticas, delete), sem o programa `conntrack`. O lab mostra uma tabela simulada, feita a partir
dos pools de CGNAT (`crates/hal/src/lab_conntrack.rs`).

| Comando | O que faz |
|---|---|
| `ip.firewall.connection.list` | uma página (≤ 5000 linhas) do que casa com os filtros, mais o uso da tabela |
| `ip.firewall.connection.top` | os assinantes com mais conexões e quanto do bloco de portas do CGNAT cada um usa |
| `ip.firewall.connection.kill` | derruba uma conexão, por `id`, ou todas as que casam com um filtro |
| `ip.firewall.connection.tracking.info` | os timeouts e o tamanho da tabela |
| `ip.firewall.connection.tracking.set` | muda os timeouts e o tamanho da tabela |

`list` filtra por:

- protocolo;
- origem e destino (endereço ou prefixo);
- porta;
- estado;
- assinante;
- IP público;
- Via;
- srcnat ou dstnat.

`list` ordena por timeout, bytes ou pacotes.

`kill` sem nenhum filtro exige `all=true`.

Os nomes de `tracking.info` e `tracking.set` são os do RouterOS.

Detalhes:

- **Timeouts são parâmetros do Tuning.** `tracking.set` grava os mesmos `net.netfilter.nf_conntrack_*` de
  System › Tuning (G1.26), com as mesmas faixas. Os valores ficam num lugar só e são exportados lá. Os
  padrões do Linux diferem dos do RouterOS: `udp-timeout` é 30 s nos dois, mas `tcp-established` é 5 dias
  no Linux e 1 dia no RouterOS. As explicações do ⓘ citam as RFCs: 5382 REQ-5, 4787 REQ-5, 5508 REQ-2,
  7857 §2.1.
- **Uso da tabela.** A barra mostra `count / nf_conntrack_max`, verde, âmbar a partir de 70 % e vermelha a
  partir de 90 %. Um clique abre System › Tuning. Selos vermelhos mostram `insert failed`, `dropped` e
  `early drop` quando passam de zero. Sem tupla livre no NAT, o kernel descarta e só conta
  `insert_failed`.
- **Coluna Via.** `rules` (o caminho normal), `software` (flowtable, o "fasttrack") e `hardware` (offload
  na placa). Vem dos bits `IPS_OFFLOAD` e `IPS_HW_OFFLOAD` do conntrack. As flags seguem o RouterOS:
  - `S` seen-reply;
  - `A` assured;
  - `C` confirmed;
  - `s` srcnat;
  - `d` dstnat;
  - `F` fasttrack;
  - `H` hw-offload.
- **Sem travar.** A janela pede uma página de 500 linhas por vez (`‹ 1–500 de N ›`), nunca a tabela
  inteira. O engine lê o kernel no máximo a cada 2 s e reaproveita a leitura entre as páginas e o top.
  O botão Pause congela a leitura.
- **Top subscribers.** Conta as conexões e as portas públicas distintas de cada assinante, por
  protocolo; vale o protocolo mais cheio. O selo fica âmbar a partir de 70 % do bloco e vermelho a partir
  de 90 %. Um clique filtra a tabela por aquele assinante.

## Histórico de revisão

- 2026-10-22 — versão inicial (G2.1a).
- 2026-10-22 — G2.1b: `add-*-to-address-list` e `limit` (sets `ad*`), §6–§11 (lockout, sombras,
  configuração inicial, modelos, zonas, descrição e cores).
