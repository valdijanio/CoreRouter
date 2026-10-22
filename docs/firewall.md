# Firewall (G2.1)

Modelo do `/ip firewall` do MikroTik RouterOS (filter, nat, mangle, address-lists) e do
`/interface list`, aplicado no Linux com nftables. Nomes e semântica seguem a documentação
oficial da MikroTik (Filter, NAT, Mangle, Address-lists, Interface Lists, Connection tracking);
este texto é nosso.

Entregue em três PRs:

| Sub-item | Conteúdo | Status |
|---|---|---|
| G2.1a | Modelo, comandos, listas de interfaces, address-lists, render nftables, aplicação atômica, janelas Firewall e Interface List | este documento |
| G2.1b | Aviso de lockout, regras sombreadas, configuração inicial segura, modelos prontos, modo por zonas, descrição em português e cores | aberto |
| G2.1c | Testador de pacotes, contadores ao vivo com "último uso", prévia do diff do nftables | aberto |

## 1. Diferenças em relação ao RouterOS

| RouterOS | CoreRouter | Por quê |
|---|---|---|
| `/ip firewall` e `/ipv6 firewall` separados | uma lista só; cada regra tem `family` (`both`, `ipv4`, `ipv6`) | uma política, um lugar; endereços IPv4/IPv6, `protocol=icmp`/`icmpv6` e `to-addresses` restringem a família sozinhos (conflito = erro) |
| regra comum com comentário como título | regra-cabeçalho de seção (`section`) | agrupa regras na GUI (faixa de título) sem tocar o data plane |
| `log=yes` em qualquer regra | ação `log` (+ `log_prefix`), que continua para a próxima regra | o mesmo efeito; `log=yes` fica para depois |
| ações `redirect`, `netmap`, `tarpit`, `fasttrack-connection`, `add-src-to-address-list` … | ainda não | G2.1b/G2.4/G2.3 |
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
  mark-packet mark-routing jump return log passthrough`;
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
| interface list `x` | set `il_x` de `ifname` |
| regra `*N` | uma regra (ou uma por família, se usa address-list e vale para as duas), sempre com `counter` e `comment "cr:*N"` |
| marca de conexão | `ct mark` = FNV-1a do nome (≠ 0) |
| marca de pacote / de roteamento | 16 bits baixos / altos do `meta mark` (roteamento: `ip rule fwmark …/0xffff0000`, futuro) |

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

## 5. GUI

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

## Histórico de revisão

- 2026-10-22 — versão inicial (G2.1a).
