id: fix-health-root-untrusted

A checagem de saúde "Root verity" mandava reiniciar ("Reinicie uma vez…") num caso em que
reiniciar não resolve: o slot rodando veio de um pacote assinado por uma chave que a imagem
instalada não traz. O status do slot fica `verified: false`, `signed_by: null`, `verity: false`,
e o outro slot (assinado pela chave antiga) aparece como `invalid`.

Agora, quando o slot rodando não tem o cabeçalho conferido, o motivo diz isso (chave em que a
imagem não confia, ou cabeçalho danificado) e a ação é instalar um pacote assinado por uma das
chaves aceitas, com "Reiniciar não resolve". O caso antigo (cabeçalho conferido, raiz pelo
caminho reserva no primeiro boot) continua com o conselho de reiniciar. O texto do ⓘ da checagem
ganhou o segundo motivo.

Visto na VM `corerouter-teste` em 2026-11-11, ao trocar a chave de dev da VM com um pacote-ponte
(mesma imagem, assinada pela chave antiga): o aviso apareceu com o conselho errado. Saiu ao
instalar o pacote assinado pela chave nova nos dois slots. **Não conferido** numa imagem real
depois da correção (seria preciso degradar a VM de novo); o teste usa o status que a VM mostrou.

Como testar: `cargo test -p corerouter-engine --lib root_`.

| G1.6zk | Trocar a chave de assinatura sem passar por slot não verificado: a instalação recusa (ou avisa antes de reiniciar) um pacote cuja imagem não confia na chave que o assinou, e a imagem aceita uma chave extra para a rotação | sysupdate, image, engine | Pacote-ponte de teste: `system.package.upload.start check=true` diz que a imagem nova não confia na chave do próprio pacote; rotação de chave num roteador termina com os dois slots `verified` sem instalação intermediária degradada | 6 h | aberto |
