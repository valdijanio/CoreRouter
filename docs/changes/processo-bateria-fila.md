id: processo

Bateria da fila de entrada (pedido do usuário): 10 features sintéticas (`scripts/bench-queue/`)
de ponta a ponta numa base descartável (`bench/queue`), com um conflito de texto, uma quebra
"sozinho passa, junto quebra", uma gap nova e uma mudança de status de propósito. Resultado: a
fila integrou as 10, parou nas duas quebras (conflito em 3 s; CI vermelho em 57 s, antes da
base) e voltou depois da correção da dona (5 s e 10 s). Achados corrigidos aqui: o teste de
latência do canal de controle reprovava PR bom sob carga (agora o pedido mais rápido de 40, 20 ms);
o download do `linux-modules-extra` para o `vrf` chegou a 82 kB/s (10 min) — o `vrf.ko` fica no
cache do Actions por versão do kernel, o download tem teto de 2 min e, se estourar, o CI segue
sem o teste de VRF com aviso. Achados já entregues em outros PRs: perfil de build enxuto (#50) e
`docs/perf.md` pela fila (#51).

## perf

**Bateria da fila de entrada** (**medido**, 2026-10-22; 10 features sintéticas, 32 núcleos aqui,
GitHub Actions conta grátis):

| Fase | Resultado |
|---|---|
| 10 `cargo xtask ci` ao mesmo tempo (como 10 sessões; `CARGO_INCREMENTAL=0`) | 346 s no total (uma sozinha: 135 s); 4,6 GB de build por sessão |
| 10 PRs abertos juntos (30 jobs) | job começou 7–101 s depois de aberto (limite de jobs simultâneos) |
| `xtask ci (linux)` por PR | mediana 138 s (antes das melhorias: 264 s; pior caso 775 s), máx. 433 s |
| `build (windows-latest)` / `(macos-latest)` | mediana 87 s / 58 s |
| Fila de entrada, por PR (merge da main + fold + CI + squash) | mediana 148 s (137–180 s); 856 s no PR que pegou o espelho lento do `vrf` |
| 10 PRs integrados, de ponta a ponta | 40 min (com as duas paradas e o espelho lento) |
| Conflito de texto / quebra de integração | parados pela fila em 3 s / 57 s; corrigidos pela dona em 5 s / 10 s |
| Falso negativo local sob carga | 1 em 10 (teste de latência; corrigido) |
