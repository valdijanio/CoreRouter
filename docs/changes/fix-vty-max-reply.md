id: fix-vty-max-reply

O limite de tamanho da resposta do vty do FRR (`max_reply`, `hal-frr/src/vty.rs`) não valia
quando a resposta inteira chegava num `read` só: o `read_reply` achava o terminador antes de
olhar o tamanho e devolvia `Ok` com uma resposta acima do limite (até o tamanho do pedaço lido,
256 KiB). Em produção, uma resposta do FRR maior que o limite passava se viesse de uma vez. O
teste `vty::tests::hostile_commands_and_answers_are_refused` falhava sob carga por isso (2 em 300
execuções com 16 em paralelo, **medido**; o CI do #489 caiu nele). Agora a resposta é recusada
pelo tamanho onde quer que o terminador apareça. Teste novo determinístico
(`a_too_long_answer_in_one_read_is_refused`: o servidor escreve a resposta toda antes da
primeira leitura); falha sem a correção. Depois dela, 300 em 300 sob a mesma carga.
