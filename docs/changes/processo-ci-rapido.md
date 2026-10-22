id: processo

CI mais rápido, com números em `docs/perf.md` ("CI e build"). O job `xtask ci (linux)` chegou a
775 s num PR (**medido**): 416 s só para carregar o módulo `vrf` instalando o
`linux-modules-extra` inteiro. Agora o `vrf.ko` sai do `.deb` baixado (cai na instalação
completa se o `insmod` falhar); sem debuginfo no CI (cache de ~2,5 GB, 70 s para restaurar);
`cargo nextest` no passo `test` do `cargo xtask ci` quando instalado (`COREROUTER_NEXTEST=0`
força o `cargo test`), com `cargo test --doc` só se algum comentário de documentação tiver
código Rust. Localmente os testes caíram de 29,7 s para 14,3 s (**medido**). `sccache` medido e
descartado (0% de acerto entre pastas de build; build nova já leva 27 s).
Também corrige um teste instável que derrubou o CI deste PR: no `netns_icmp`, o primeiro ping
IPv6 logo depois de o laboratório subir pode voltar "unreachable" enquanto o roteador resolve o
host; os testes que esperam eco agora tentam de novo (`ask_echo`) antes de reprovar.
