id: valida-interop-roteiros

Validação T2 dos roteiros de interop sobre a `main` (RouterOS 7.25 CHR na VM do lab e CR × CR no
host). Correções só nos roteiros:

- `rosx` síncrono (`"as-string": true` no `/rest/execute`) nos roteiros OSPF, BGP e PPPoE, como já
  era no L2: sem ele o RouterOS roda o script em segundo plano e dois comandos seguidos disputam
  entre si. Era a causa da falha do `ipv6` do PPPoE (CHR sem SLAAC/PD) e da rota v3 ausente no
  `ospfv3` na rodada completa.
- `maxprefix` (CR × CR e contra o CHR) espera o Cease com a razão de limite de prefixos, em vez de
  "não Established" + `sleep 3`; o modo `warning` espera os 6 prefixos.
- `ospfv3` espera a rota no CHR (até 30 s) em vez de `sleep 4`, com diagnóstico no FAIL.
- `padt` guarda o fio (PADT e LCP Terminate no `crgv1`) e as linhas do `cpe1` antes e depois do
  `remove`, para o diagnóstico.

Números (**medido**, 2026-10-29, com o host carregado por outras sessões; comparação com 28–29/10):
OSPF ptp Full 1,77 s; LDP 1,6 s; BFD 2,15 s; BGP CR × CR ebgp 5,4 s, GR 2 pings perdidos (412 sem
GR), convergência hold 9,03 s / BFD 370 ms; BGP × CHR ebgp4 4,8 s, ebgp6 1,9 s; PPPoE SLAAC 3,82 s,
PD 20 ms; DNS 1,16 M respostas/s com 4 clientes; A/B do `scale` antes/depois do G3.9fb 7,19 s ×
7,04 s (sem regressão). Relatório completo no corpo do PR.
