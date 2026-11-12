id: fix-nic-no-driver-boot

"Placa sem driver" só depois de duas leituras seguidas. No notebook (dev.616), a cada boot o
daemon olhava as placas 1 s antes de o PID 1 carregar o `r8152`: aviso no log, item de saúde e
linha na saída do `upload --wait`, normalizado 7 s depois (**medido**). Agora o `no-driver` só
entra na segunda leitura (10 s depois); firmware e Safe Mode, que vêm do log do kernel, contam na
hora. Teste: `cargo test -p corerouter-engine --lib nic_problems`.
