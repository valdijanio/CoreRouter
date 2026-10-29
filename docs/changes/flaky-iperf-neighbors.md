id: flaky

Dois testes instáveis do `cargo xtask ci` (2026-10-28) corrigidos:

- **`service::iperf::tests::udp_send_gets_the_far_ends_numbers`**: não era o teste, era uma
  corrida no servidor de bandwidth test (iperf3) do daemon. O servidor mandava `CREATE_STREAMS`
  e só depois abria o socket UDP; com vários streams, também abria o socket do próximo depois de
  responder o anterior. O datagrama do cliente que chegasse antes achava a porta fechada (ICMP
  port unreachable → "Connection refused"). Agora o listener é aberto antes do `CREATE_STREAMS`
  e o do próximo stream antes da resposta, como o iperf3 (`iperf_udp_accept`). Teste novo
  `udp_with_several_streams_never_hits_a_closed_port` (4 streams, 5 vezes): com o código antigo
  falhou 1 de 3 rodadas com o mesmo erro, sem carga; com a correção, 10 de 10, metade com as 32
  CPUs ocupadas (**medido**).
- **`neighbors::tests::recording_into_a_full_table_is_cheap`**: trava de tempo de uma medição só
  (10 000 inserções < 500 ms em debug) estourava com a máquina carregada. Agora julga a rodada
  mais rápida de 7 (2000 inserções cada, < 100 ms): carga passageira atrasa algumas rodadas,
  nunca todas, e o caminho O(n) antigo (~120 µs por inserção) dá > 200 ms em todas. Medido em
  debug: 11 ms por rodada.
