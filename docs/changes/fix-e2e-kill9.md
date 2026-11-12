id: fix-e2e-kill9

Teste instável: `config_and_history_survive_sigterm_and_kill_9` (daemon, `tests/it/e2e.rs`)
dormia 400 ms e mandava `kill -9` no meio da tempestade de commits. Com o disco disputado por
vários CIs, o primeiro commit (journal com fsync) passava desse tempo, e a asserção "algum commit
confirmado" falhou nas duas tentativas do nextest em duas rodadas seguidas do `cargo xtask ci
--affected` (2026-11-12, carga 35–60). Agora o teste espera 5 confirmações (até 30 s) e corta 100
ms depois. A mensagem diz quantas confirmações houve e em quanto tempo. Sem carga: 10 confirmações
em ~200 ms, com 12 cópias em paralelo (**medido**).
