id: processo

Runner próprio do CI (`docs/ci-runner.md`): os jobs pesados do lote da fila (`test`,
`bench-check`, `netns`) rodam numa VM descartável desta máquina, `corerouter-ci` (16 vCPUs,
16 GiB, discos em `/srv/build/ci-runner/`), com 3 runners self-hosted, em vez dos runners de
4 vCPU do GitHub; o cache de build fica num disco próprio da VM e sobrevive aos resets.
`cargo xtask ci-runner create|register|status|check-network|run|reset|down|unregister|destroy`
(`xtask/src/ci_runner.rs`, que reaproveita a imagem verificada, o `virsh` e o SSH do `vm_lab`).
Segurança (o repositório é público): o workflow só manda para o runner o `workflow_dispatch` em
`queue/*` com `runner=corerouter` e, se a variável `CI_RUNNER` do repositório pedir, o push na
`main`; PR, inclusive de fork, fica no GitHub. Um hook do runner (root, posto pela unit) reprova
antes do primeiro passo qualquer outro job, mesmo que um workflow alterado peça `self-hosted`.
Os jobs rodam como `runner`, sem sudo; um nwfilter do libvirt no host deixa a VM falar só com a
internet (LAN, endereços do host, faixas privadas e IPv6 bloqueados; conferido por
`ci-runner check-network`). A fila (`scripts/land.sh`) escolhe o runner por lote: o próprio
quando o GitHub o mostra online, senão os do GitHub (a fila nunca espera um runner fora do ar);
lote com PR de fork vai sempre para o GitHub; ociosa, volta a VM ao snapshot a cada 40 jobs.
`xdp-root` e `lint` continuam no GitHub. O registro (token) e as opções do repositório são do
usuário: roteiro em `docs/ci-runner.md`, "Etapa do usuário".

## perf

### Runner próprio do CI: lote da fila antes e depois (processo, 2026-10-29)

**Medido** em 2026-10-29. Antes: os runners do GitHub (4 vCPU por job). Depois: a VM
`corerouter-ci` (16 vCPUs EPYC-Genoa `host-model`, 16 GiB + 16 GiB de swap, 3 runners) no host
de 32 núcleos, com os mesmos jobs (`cargo xtask ci --only test|bench-check|netns`, camada
`full`, partições 1/2 e 2/2) rodando 3 de cada vez por `cargo xtask ci-runner run`, como os 3
runners. Uma amostra por linha.

| Job (lote `33c235c5`) | GitHub (run 40947726887) | VM, cache quente (lote anterior `f0c46dc9` compilado) |
|---|---|---|
| `test (1/2)` | 225 s | 170 s |
| `test (2/2)` | 306 s | 79 s |
| `bench-check` | 428 s | 224 s |
| `netns` | 163 s | 176 s (começa aos 79 s, no runner que rodou o `test (2/2)`, disputando CPU com os outros dois) |
| jobs pesados, ponta a ponta | 428 s (o `bench-check`) | 255 s |
| lote inteiro | 445 s | ~260 s **estimado**: o `xdp-root` (≤ 200 s) e o `lint` (91 s) continuam no GitHub, em paralelo |

A frio (cache vazio, depois de `reset --wipe-cache`), o lote `f0c46dc9` levou 336 s na VM
contra 437 s no GitHub (run 40936449389). Sem swap, o bench `frames` (6,4 GB de RSS) levou OOM
com 3 jobs em 16 GiB; com 16 GiB de swap, nenhum OOM. A VM tem 4 jobs e 3 runners: o `netns`
espera o primeiro terminar. Dois testes saíram FLAKY (falharam e passaram na repetição, sem
reprovar): `service::bandwidth_server::tests::enabled_by_config_serves_and_refuses_outsiders` e
`service::bfd::tests::two_engines_come_up_and_detect_the_loss`, do daemon, sob 3 jobs ao mesmo tempo.
