id: fix-ci-runner-cache

Runner próprio do CI: o disco de cache não enche mais. Em 2026-11-21 os três targets do cargo
(51–53 GB cada) encheram os 196 GB do disco de cache da `corerouter-ci` com 35 jobs desde o
último reset, e todo lote falhou com "No space left on device" (o #706 saiu vermelho por isso,
**medido**). Duas correções em `xtask/src/ci_runner.rs`:

- `reset --if-due` também reseta, e limpa os targets, com o disco de cache a 75 % ou mais, sem
  esperar os 40 jobs. Depois de uma limpeza, uma rodada completa por vaga deixa ~27 GB por target
  (**medido** em 2026-10-29), ~50 % do disco com o swap de 17 GB.
- `reset --wipe-cache` dizia "wiped" e não limpava: o `rm -rf` ficava no cache de páginas e no
  journal do ext4, e o `virsh destroy` logo depois desfazia a remoção (os 186 GB voltaram depois
  do boot, **medido**). A limpeza termina com `sync -f`, e o `reset` roda `sync` na VM antes de
  desligá-la à força, o que também protege o cache que fica.
- Runner órfão: a unidade tem `KillMode=process` e `PrivateTmp=yes`, então um `systemctl stop`
  deixa o `Runner.Listener` vivo numa `/tmp` já apagada. Na limpeza à mão do dia, a vaga 2 ficou
  assim: três lotes falharam com "Cannot create temporary file in /tmp/" (SIGABRT no linker), e
  a unidade religada não conseguia a sessão ("A session for this runner already exists",
  **medido**). O caminho do `reset` que para e religa os serviços ("a job started while
  stopping") agora encerra os órfãos antes; `docs/ci-runner.md` avisa para nunca parar os
  runners com `systemctl` à mão.

Como testar: `cargo test -p xtask ci_runner`; no runner, `cargo xtask ci-runner reset --if-due`
com o disco abaixo e acima de 75 %, e `cargo xtask ci-runner ssh df -h /var/cache/corerouter-ci`.
