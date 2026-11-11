id: fix-upload-wait-starting

`corerouter-cli upload … --wait` (e o `cargo xtask os push`, que o chama) dizia que a atualização
falhou quando ela tinha dado certo: `slot b was not kept (): see system.package.print`, saída 1,
enquanto o roteador seguia no período de teste e confirmava o slot.

Causa: depois do reboot, o daemon responde antes de o serviço de pacotes ler os slots. Nesse
intervalo o `system.package.print` devolve `{supported: false, reason: "the package service has
not reported…"}`, sem `trial` e sem `last`. O `wait` lia isso como "o período de teste acabou e o
resultado não é confirmed".

Agora o `wait` continua esperando enquanto a resposta não tem `supported: true`. Se o roteador
responde assim por mais de 60 s, o comando falha com o motivo que o roteador deu
(`the router answers but has no package status: …`), em vez de esperar os 15 minutos.

**Medido** na VM `corerouter-teste` (QEMU/KVM, 2026-11-11), atualizando para a 0.1.0-dev.579: o
falso erro saiu em 1 de 3 instalações (7,6 s depois do início; o slot foi confirmado aos 18 s);
nas outras duas o comando levou 17,9 s e 18,3 s. Depois da correção não repeti a instalação na
VM: a corrida é coberta pelos três testes novos, que falham sem a correção com a mesma mensagem.

Como testar: `cargo test -p corerouter-cli upload`.
