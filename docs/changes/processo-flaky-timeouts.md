id: processo

Dois testes instáveis travavam a fila (o #227 ficou fora seis vezes):

- **`corerouter-control` `deadline_bounds_the_total_not_each_read`.** Era um bug de verdade. No Unix, um `SO_RCVTIMEO` vencido volta como `WouldBlock` (EAGAIN), e não como `TimedOut`. O `Sock::read` do canal de controle devolvia um ou outro, conforme quem vencia antes: o prazo verificado por nós ou o do socket. Agora os dois casos saem como `TimedOut`.
- **`service::dns::tests` (`a_silent_server_is_skipped` e os outros).** O servidor DNS de teste pegava uma porta UDP livre e tentava a mesma porta em TCP, que um teste paralelo podia estar usando (`AddrInUse`). Agora ele tenta de novo até achar uma porta livre nos dois.
