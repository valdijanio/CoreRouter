id: fix-journal-routing-delta

Journal de config sem OSPF, MPLS/LDP, BFD e RPKI: essa config se perdia quando o daemon morria sem
SIGTERM. Encontrado no laboratório do CHR (G3.9c): depois de um `kill -9` o daemon voltou sem
instância OSPF e sem LDP. No `journal-config.log`, todo `routing.ospf.*`, `mpls.*`,
`routing.bfd.*` e `routing.rpki.*` gravava `"delta":{}` (é também o perfil BFD perdido que a R3-E
viu). O `config_delta::diff_routing` listava à mão os mapas do BGP e o filter (G3.2a/G3.2b), e o que
veio depois (`rpki`, `bfd`, `ospf`, `mpls`) ficava fora do diff. Os `rev-N.json` do histórico usam o
mesmo delta, então um `config.rollback` para uma revisão antiga também não desfazia essas áreas.

O que entrou:
- `diff_routing` com a parte pequena por `light_routing`, que desestrutura o `Routing` inteiro (como
  o `light_firewall`, #458): campo novo sem tratamento não compila. As outras seções já limpavam
  só as listas grandes de um clone e pegavam campo novo sozinhas; o buraco era só esse.
- `persist::revision_delta` confere o delta tipado aplicando-o. Se o resultado não for a revisão,
  grava o delta da árvore JSON inteira (mais lento, sempre completo). Uma seção futura que o diff
  tipado não veja vira custo, não perda de dado.
- Teste de varredura `journal_sections::every_section_survives_a_restart_through_the_journal`
  (engine). Os 84 comandos enchem todos os campos de cada seção que o delta trata (`Config`,
  `system`, `ipv6`, `ip`, `ip.firewall`, `ip.dhcp_server`, `ip.dns_static`, `routing`, `ppp`,
  `queue`). Os nomes dos campos vêm do `Deserialize`, então campo novo que nenhum comando enche
  reprova com o nome. Depois, o delta tipado de cada commit tem de reconstruir o commit sozinho,
  sem a rede de segurança, e o reboot pelo journal tem de dar a mesma config. Com o `diff_routing`
  antigo ele reprova em "routing.rpki.add: typed delta {}".
- Teste de ponta a ponta no daemon `shutdown_checkpoint::sigkill_keeps_the_routing_config`: perfil
  BFD, instância/área/template OSPF, LDP e interface LDP, cache RPKI; SIGKILL; o daemon reinicia e
  as listas voltam iguais. Reprova no código da `main`.
- `config_delta::tests::ospf_mpls_bfd_and_rpki_are_in_the_delta`: os mesmos casos no modelo.

Configs gravadas antes da correção, o que se perdeu e como recuperar:
- Daemon da versão antiga ainda rodando: a config em memória está certa. Pare-o com SIGTERM (parada
  normal do serviço) antes de atualizar. O checkpoint da G0.27 grava o slot (`running.json`) com a
  config inteira e nada se perde.
- Daemon que morreu sem SIGTERM (queda de energia, `kill -9`, OOM): perdeu os commits de
  OSPF/MPLS/BFD/RPKI feitos desde o último checkpoint. O checkpoint só acontece no SIGTERM ou quando
  o journal passa de 1024 linhas ou 1 MiB, então em geral perdeu tudo desde a última parada limpa.
  O que sobra no disco: `running.json` e `running.json.prev` (a config inteira dos dois últimos
  checkpoints, com essas áreas como estavam naquele momento) e, no journal, o nome do comando e a
  hora de cada commit perdido (sem os parâmetros), útil para saber o que refazer. Os `rev-N.json`
  não têm o dado.
- Depois de atualizar, os `rev-N.json` antigos continuam dizendo "routing igual ao da revisão mais
  nova": um rollback para uma revisão de antes da correção não desfaz OSPF/MPLS/BFD/RPKI.

Como testar: `cargo test -p corerouter-model --lib config_delta`,
`cargo test -p corerouter-engine --test it journal_sections` e
`cargo test -p corerouter-daemon --test it sigkill`.

Desempenho e paralelismo: o trabalho é por commit e serial (sob o lock do journal, antes do fsync).
Um commit de routing passa a serializar `rpki`, `bfd`, `ospf` e `mpls` na parte pequena (dezenas de
itens; os mapas do BGP continuam diff por chave). A conferência aplica o delta e compara; as seções
que o commit não tocou são o mesmo `CowArc` e a comparação para no ponteiro. Ela dobra o custo do
delta, mas são dezenas de µs contra o ms do fsync do journal. Dividir entre threads não ajuda:
um commit é um passo só, com ordem obrigatória.

## perf

- 2026-10-30, **medido**, build de bench (release), máquina de desenvolvimento, `cargo bench -p
  corerouter-model --bench config_delta`. Antes/depois da conferência no `persist::revision_delta`:
  `revision_delta_one_filter_rule_of_10000` 29,2 µs → 51,6 µs; `revision_delta_one_route_of_60000`
  (novo) 65,2 µs → 130,7 µs. `one_filter_rule_of_10000` (só o `diff`, código igual) 28,4 → 31,2 µs:
  ruído da máquina compartilhada.
