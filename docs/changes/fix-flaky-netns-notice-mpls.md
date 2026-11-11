id: fix-flaky-netns-notice-mpls

Dois testes de namespace instáveis no lote 599 da fila (run 43007252303; os dois passaram na
repetição). As duas correções são nos testes; o produto não mudou.

**`netns_notice`** (`left: Http(204, "")`, `right: Http(302, …/?via=android)`, linha 204). O
kernel redireciona um membro da lista assim que o `ip.firewall.address-list.add` retorna, mas
o portal responde por uma cópia das listas que a rodada do serviço `notice` refaz a cada 2 s.
O teste bloqueia dois endereços em dois comandos e esperava só o primeiro aparecer no portal.
Uma rodada entre os dois comandos conhece só o primeiro; o cliente atrás do CPE era então
respondido como não membro, que recebe o que o sistema dele espera (204). Agora o teste espera
os dois membros no portal antes de conferir as sondas. **Medido** (2026-11-11): com uma pausa
de 2,1 s forçada entre os dois comandos, o teste antigo falhou em 6 de 6 rodadas, com a mesma
mensagem do CI, e o corrigido passou em 6 de 6; sem a pausa, 4 de 4, ~12 s cada.

**`netns_mpls_too_big`** (`B answers through the LSP`, só no IPv6, linha 454). Os endereços
globais do laboratório usam `nodad`, mas o link-local de cada enlace ficava `tentative` por
cerca de 2 s depois do link subir (RFC 4862 §5.4: atraso aleatório de até 1 s e 1 s da
sonda). O roteador que encaminha um pacote envia o Neighbor Solicitation a partir do
link-local; enquanto ele é tentativo, nada sai. O primeiro eco IPv6 só voltava na terceira
tentativa, e a janela do teste é de cinco tentativas de 700 ms. Com o resto da suíte segurando
o RTNL (o DAD precisa dele), o DAD termina mais tarde e as cinco se perdem (esta última parte
é inferência do comportamento do kernel; o atraso sob carga não foi reproduzido). Agora o
laboratório desliga o DAD (`accept_dad = 0` em `all` e no enlace) antes de subir cada link.
**Medido** na VM do laboratório (kernel 7.0.0-38, 2026-11-11): primeiro eco IPv6 em
2,03–2,08 s, na terceira tentativa, em 12 de 12 rodadas antes; em 2,3–3,3 ms, na primeira, em
6 de 6 depois (IPv4: ~3 ms antes e depois). O binário inteiro passou 4 de 4 vezes, 11,2 s.

O `netns_icmp` tem o mesmo desenho (roteador IPv6 com `nodad` só nos globais), mas espera até
10 s por resposta e repete respostas "unreachable"; não foi alterado.

Como testar: `cargo xtask netns` (o `netns_mpls_too_big` precisa do módulo `mpls_router`: na
VM, `cargo xtask vm-lab run -- env COREROUTER_NETNS_TESTS=1 COREROUTER_REQUIRE_MPLS=1 unshare
--net -- cargo test -p corerouter-hal-linux --test netns_mpls_too_big`).
