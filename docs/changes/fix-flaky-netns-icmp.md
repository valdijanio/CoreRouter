id: fix-flaky-netns-icmp

Teste instável `netns_icmp` no lote 600 da fila (run 43011148844,
`udp_and_tcp_probes_walk_the_path`: `left: Reached("rst")`, `right: Reached("syn-ack")` na
sonda TCP para a porta 8080; passou sozinho na repetição). Correção no teste; o produto não
mudou.

Causa: o teste abre um ouvinte na porta 8080 com um `python3` e esperava 500 ms fixos por ele.
O que dava folga era outra espera, por acaso: o primeiro eco IPv6 pelo roteador levava de 1 a
2 s, porque o link-local dos enlaces ficava `tentative` (DAD, RFC 4862 §5.4) e o roteador não
envia Neighbor Solicitation a partir de endereço tentativo (a mesma causa do
`netns_mpls_too_big`, #600). Numa máquina carregada o `python3` demora mais que 500 ms + esse
aquecimento, o SYN chega antes do `listen` e o kernel responde RST.

Agora o ouvinte avisa quando está ouvindo (escreve `ready`) e o teste espera por isso. O
laboratório também desliga o DAD nos namespaces (`accept_dad = 0` em `all` e `default`, antes
de criar os enlaces), o que tira a espera de 1–2 s.

**Medido** (máquina de desenvolvimento, kernel 7.0, 2026-11-11), com o ouvinte atrasado em 2 s
de propósito: o teste antigo falhou em 2 de 6 rodadas, com a mesma mensagem do CI (nas duas, o
aquecimento IPv6 levou 1,03–1,06 s; nas quatro que passaram, 2,06–2,08 s); o corrigido passou
em 6 de 6. Primeiro eco IPv6 pelo roteador: 1,03–2,08 s antes, ~0,1 ms depois. O binário
inteiro passou 6 de 6 vezes depois da correção; o tempo dele não mudou (3,1–4,2 s antes e
depois: outras esperas dominam).

Como testar:
`COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-hal-linux --test netns_icmp`
(ou `cargo xtask netns`).
