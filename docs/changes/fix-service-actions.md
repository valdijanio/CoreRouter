id: fix

System › Services: Start/Stop agora mostram o que fizeram (relato do usuário: "start e stop não
funcionam nem mostram o resultado no log"). Eles funcionavam no supervisor, mas nada aparecia:

- **Start num serviço desligado pela config** (`disabled`, ex.: dns-server com
  `allow_remote_requests=no`) respondia OK e não mudava nada. Agora recusa dizendo por quê e
  como ligar (`turn it on with ip.dns.set allow_remote_requests=yes`). Stop continua valendo.
- **O resultado de cada comando vai para o log do roteador**, no tópico do serviço (`dns`,
  `system`…): "Serviço dns-server: parando / parado / iniciando / reiniciando / já estava
  parado (… por comando)". Antes só ia para o stderr do daemon.
- **A linha mostra "stopping"/"restarting"** enquanto a parada não termina (antes continuava
  `disabled`), e `stopped` (pelo admin) fica âmbar, separado do cinza de `disabled` (pela config).
- A janela diz "stop sent to dns-server" ao enviar; o erro do comando aparece no lugar.

Como testar: System › Services › dns-server › Start (mensagem explicando), Stop (stopping →
stopped, âmbar; linha no Log · dns), Start de novo.
