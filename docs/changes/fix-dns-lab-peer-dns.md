id: fix-dns-lab-peer-dns

`scripts/dns-stress-lab.sh` no modo remoto (fase C) não manda mais carga do laboratório para os
servidores DNS que o roteador aprendeu por DHCP.

**O defeito, achado no notebook (2026-11-14, `dev.659`, **medido**):**
- O cliente DHCP da `ether1` (rede de casa) tem `use_peer_dns`, e o roteador de casa
  (192.168.0.1) entrava em `dynamic_servers` junto com as origens do laboratório.
- Numa bateria de 24 min ele recebeu ~33 000 consultas do laboratório pela `ether1` (27 455
  respondidas, 5 771 sem resposta) e respondeu NXDOMAIN para nomes `*.up.lab`.
- Essa resposta negativa ficava no cache. Era ela que fazia o roteiro acusar "the forwarder
  stopped answering" depois da origem de 200 ms, nas duas rodadas do notebook. O coletor de
  estatísticas mostrou o encaminhador respondendo 13 000 a 23 000 consultas/s, todas NOERROR,
  justo no momento da falha.
- Pelo mesmo motivo, a checagem inicial falhou ("does not answer on 10.53.0.1:53"). Com
  `server_selection fastest`, o roteador de casa já tinha RTT medido e as origens novas ainda
  não. O NXDOMAIN de `big.up.lab` e de `many.up.lab` na tabela de entrada hostil também vinha
  dele.

**A correção:**
- No modo remoto, o roteiro desliga o `use_peer_dns` dos clientes DHCP durante o laboratório. O
  `dhcp_update` do engine mantém o lease, e o rollback do fim religa a opção.
- Ele espera o resolvedor tirar os servidores aprendidos (~2 s no notebook, **medido**) e se
  recusa a rodar se sobrar algum, por exemplo de um cliente PPPoE.
- Ele esvazia o cache depois de configurar.
- A recusa agora interrompe a rodada antes da carga.
- O `REVISION` do rollback fica sendo o primeiro, mesmo quando `dut_config` roda de novo.

Conferido no notebook: com a correção, a rodada `origin,ops` passou ("Resultado: OK") e não
houve mais "stopped answering" depois da origem de 200 ms (38 312 NOERROR, máx. 823 ms).

Como testar:
`cargo xtask vm-lab run -- env COREROUTER_PASSWORD= scripts/dns-stress-lab.sh --dut remote --iface enp9s0 --target 100.64.0.1 --mgmt 100.64.0.253/24 --dut-iface ether2 --tests origin,ops`
contra um roteador com cliente DHCP. O log mostra "DHCP client *1 without use_peer_dns during the
lab", e o `ip.dns.get` volta com o `dynamic_servers` de antes.

**O rollback ainda falha depois do teste `ops`.** Ele faz mais de 64 revisões, e a revisão de
antes sai do histórico. A G0.33 (ponto de volta com nome) resolve isso. Até lá, a limpeza é à mão:
- `use_peer_dns` de volta;
- `ip.dns.set` com os valores de antes;
- remover o endereço 10.53.0.1/24.

**Números do notebook na mesma rodada, para as gaps da fase C (**medido**):**
- **G4.1zo:** com `max_queries_per_client=0` e 65 000 mensagens de lixo por segundo, a thread
  `dns-udp` ficou em 49 % e o cliente legítimo teve p99 de 719 µs. Antes eram 98 % e 1,5 s, com
  27 000 mensagens/s.
- **G4.1zn:** com 20 000 consultas/s ao lado, o p99 de `ip.dns.set` caiu para 43 ms. Ainda ficam
  acima do alvo de 50 ms o `static.add` + `remove` (p99 de 479 ms) e o lote atômico (452 ms).
