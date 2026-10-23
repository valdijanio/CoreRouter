id: fix

conntrack: matar conexões não para mais numa conexão ICMP. O `delete` por ctnetlink mandava o
tuple ICMP só com o id, e o kernel exige também tipo e código (`CTA_PROTO_ICMP_TYPE`/`CODE`):
devolvia EINVAL, e o laço desistia no primeiro erro, deixando vivas as conexões que vinham
depois. No CGNAT isso deixava assinantes remapeados com a tradução antiga (o "Quem era?" erraria
para elas), e o `ip.firewall.connection.kill` parava no primeiro ping.

- o parser guarda tipo e código do ICMP no `dst_port` (`tipo << 8 | código`) e o pedido de
  delete os devolve;
- o `delete` tenta todas e só depois devolve a primeira recusa;
- o filtro `port` de `ip.firewall.connection.list` ignora ICMP (o campo é tipo/código ali).

Era a causa do teste instável `netns_cgnat::element_changes_go_incremental_and_remaps_kill_connections`
("killed: left 1, right 0"): falhava quando um teste anterior do mesmo binário deixava um ping no
conntrack. **Medido** (Ryzen AI MAX+ 395, 2026-10-23): antes 2 falhas em 4 execuções do binário,
depois 10 de 10 verdes. Teste novo de bytes: `ctnl::an_icmp_tuple_carries_type_and_code`.
