id: fix-flaky-conntrack-remove

Teste instável `netns_conntrack_remove` (lote 594 da fila: `left: 19, right: 20` na linha 89,
passou sozinho na repetição). Causa: o teste abria 20 sockets UDP em sequência com porta 0 e
fechava cada um antes de abrir o próximo. A porta de origem liberada pode ser sorteada de novo
pelo kernel, e dois sockets com a mesma porta de origem são um fluxo só no conntrack. Correção
no teste: os 20 sockets ficam abertos até o último envio, então as portas são distintas por
construção. O comando `ip.firewall.connection.remove` não mudou.

**Medido** (kernel 7.0, faixa padrão de portas efêmeras 32768–60999, 2026-11-11): o teste
antigo falhou em 11 de 1500 rodadas (0,73 %), cada uma num namespace novo; o corrigido, em 0 de
500. Só o sorteio de portas: 198 de 30 000 rodadas de 20 `bind` em sequência repetiram porta
(0,66 %); com os 20 sockets abertos ao mesmo tempo, 0 de 30 000.

Como testar:
`COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-daemon --test netns_conntrack_remove`
(ou `cargo xtask netns`, que roda todos os testes de namespace).
