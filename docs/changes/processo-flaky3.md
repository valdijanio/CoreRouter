id: processo

Três testes instáveis da fila (2026-10-26), cada um pela causa real:
- `netns_pppoe_io` (bug de produção): os sockets `ETH_P_ALL` da porta PPPoE (`pppoe_io::bound` e
  o tap do `bng0`) recebem quadros de **todas** as interfaces, sem filtro, entre o `socket()` e o
  `bind`; o BNG lia esses quadros como PPPoE da porta (no CI, um relatório MLD de outra porta).
  Agora a porta descarta o que ficou na fila depois do filtro e do bind, como os sockets do DHCP e
  da captura já faziam. Teste novo `a_port_never_reads_another_interface`: abre a porta 50 vezes
  com outra veth inundada de PPPoE. Sem a correção, 3.500 a 4.900 quadros alheios por rodada;
  com ela, 0 (**medido**). O teste também passou a esperar a veth sair do qdisc `noop` (o caso 0
  não lia nada no CI: o quadro saía antes do carrier).
- `netns` (`two_daemons_see_each_other`): o veth agora é apagado antes de o namespace de B
  acabar. O kernel destrói o namespace depois, numa workqueue, e leva o veth junto; o `ip link
  del` achava "Cannot find device". Com 300 ms entre os dois passos, a ordem antiga falha sempre
  (**medido**).
- `netns_dns_zones`: o serviço DNS copia a config a cada 1 s, e o teste esperava o 3º de 5
  registros, então a AXFR podia ler 4 de 5. Agora ele espera o SOA servido trazer o serial
  confirmado (`ip.dns.zone.print`). Com uma pausa de 1,1 s depois do 3º registro, o teste antigo
  falha (3 de 5) e o novo passa (**medido**).

Carga: 12 a 16 cópias em paralelo, com 32 núcleos ocupados. `netns_pppoe_io` foi de 1 falha em
160 a 0 em 160; `netns` e `netns_dns_zones` deram 0 em 60 cada (**medido**).
