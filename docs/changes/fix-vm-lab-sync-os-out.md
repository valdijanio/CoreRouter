id: fix-vm-lab-sync-os-out

O `vm-lab run` não manda mais as árvores do Buildroot para a VM. A cópia da worktree (rsync)
deixava de fora `target*`, `.git`, `.claude/` e `plan/`, mas levava `os/dl/` (681 MB) e qualquer
`os/out*/`. Um `os/out.old/` parado no checkout principal (18 GB, **medido**) encheu o disco de
20 GiB da VM no meio da cópia ("rsync error: error in file IO", 2026-11-12), e a rodada falhou
antes de começar. As exclusões viraram a constante `SYNC_EXCLUDES`, agora com `/os/dl/` e
`/os/out*/`. A imagem continua chegando à VM pelo `vm-lab put`. Teste:
`cargo test -p xtask sync_leaves_build_trees_out` roda o rsync de verdade numa pasta temporária;
sem as duas linhas novas, ele mostra `os/dl`, `os/out` e `os/out.old` copiados.
