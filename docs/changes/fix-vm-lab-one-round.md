id: fix-vm-lab-one-round

O `cargo xtask vm-lab run` sincroniza a worktree para `/srv/lab/<worktree>/src` antes de esperar a
trava da VM. Uma segunda rodada da mesma worktree, posta na fila enquanto a primeira esperava,
sobrescrevia o código dela: a sessão da G3.9da/db viu a rodada da G3.9da compilar o código da
G3.9db (2026-10-30), o que também explicava builds "velhos" de antes. Agora o `run` procura na VM
uma rodada viva cujo comando roda nessa pasta e, se houver, recusa antes do `sync`, com os pids e
o caminho (`--no-sync` continua rodando sobre o código que está lá). Teste:
`same_dir_rounds_check_finds_a_queued_round_of_this_worktree` (acha a rodada da mesma pasta e não
a de outra).
