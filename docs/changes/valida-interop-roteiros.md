id: valida-interop-roteiros

Validação T2 dos roteiros de interop sobre a `main` (RouterOS 7.25 CHR na VM do lab e CR × CR no
host): tudo passa; nenhuma regressão do CoreRouter. As falhas encontradas eram dos roteiros:

- `rosx` síncrono (`"as-string": true` no `/rest/execute`) nos roteiros OSPF, BGP e PPPoE, como já
  era no L2: sem ele o RouterOS roda o script em segundo plano e dois comandos seguidos disputam
  entre si. Era a causa da falha do `ipv6` do PPPoE (CHR sem SLAAC/PD).
- `padt`: o CHR responde ao PADT do BNG e redisca em menos de 1 s, antes de o poll ver
  `running=false`; o caso agora espera o contador `link-downs` do CHR. Guarda também o fio (PADT e
  LCP Terminate) e as linhas do `cpe1` para o diagnóstico.
- `maxprefix` (CR × CR e contra o CHR) espera o Cease com a razão de limite de prefixos, em vez de
  "não Established" + `sleep 3`; o modo `warning` espera os 6 prefixos.
- `ospfv3` espera a rota nos dois lados (até 30 s) em vez de `sleep 4`, com diagnóstico no FAIL.
- `rsc` (L2) importa só as VLANs do próprio caso: o `qinq` deixa `c201` no CHR e no CoreRouter, e o
  import atômico do CoreRouter recusava o arquivo inteiro (comportamento certo).

O `client` do PPPoE contra o CHR só passa com `XDP=0` (como na medição de 29/10): o BNG e o cliente
dividem o `ether1` do laboratório.

Números (**medido**, 2026-10-29/30, host carregado por outras sessões; entre parênteses, 28–29/10):
OSPF ptp Full 1,77 s (1,8–7,6 s), OSPFv3 Full 1,0–1,5 s; LDP 1,6 s (1–2,5 s); BFD 2,15 s; BGP CR × CR
ebgp 5,4 s (5,5 s), GR 2 pings perdidos com GR e 412 sem (2 e 469), hold 9,03 s / BFD 370 ms
(8,98 s / 420 ms); BGP × CHR ebgp4 4,8 s (5,2 s), ebgp6 1,9 s (2,1 s); PPPoE padt 10 ms (121 ms),
SLAAC 3,82 s (4,2 s), PD 20 ms (6 ms), cliente 2,43 s (2,46 s), 32 sessões em 321 ms; L2 ra 4,5 s
(2,3 s), RA final 862 ms (1,1 s); DNS 1,16 M respostas/s com 4 clientes no host (1,12 M). A/B do
`scale` antes/depois do G3.9fb no mesmo momento: 7,19 s × 7,04 s (sem regressão).
