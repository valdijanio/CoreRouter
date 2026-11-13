id: vm-lab-reset-busy

`cargo xtask vm-lab run` não reinicia mais a VM do laboratório por cima de uma rodada viva. Em
2026-11-13 às 15:16 o health-check de um `run` achou o disco da VM abaixo de 2 GiB (outra rodada
compilava em release) e fez `virsh destroy` + `snapshot-revert` no meio da fase C de DNS contra o
notebook e de uma rodada da G4.1w (as duas com status 255). Agora a decisão é a função pura
`verdict` (`xtask/src/vm_lab.rs`): saúde boa segue; disco curto primeiro apaga os
`/srv/lab/<worktree>/target` das worktrees sem rodada viva, do menos recente para o mais, até 6 GiB
livres (os `src` ficam); sem rodada viva, o que ainda estiver ruim vira `reset` como antes; com
rodada viva (um `ssh … COREROUTER_LAB_ROUND=…` de um `vm-lab run` vivo no `/proc` do host, ou o
`vm/root.lock` do usuário), o `run` espera e confere de novo a cada 30 s dentro do
`--lock-timeout`, com SSH mais paciente (30 s de conexão, 180 s de resposta), e no fim sai com
erro dizendo quem está na VM, sem reiniciar. A conferência, a limpeza e o `reset` rodam sob
`vm/health.lock` no host até o `ssh` da rodada começar: dois `run` não reiniciam juntos.
`snapshot`/`reset` à mão também recusam com rodada viva (antes só olhavam a trava da VM). O
`create` passou a 40 GiB de disco (o `tools` ocupa 7,1 GiB dos 19 GiB, **medido**), e o
`docs/vm-lab.md` ganhou a seção "Saúde da VM: reiniciar ou esperar" e a receita para crescer a VM
existente (`qemu-img resize` + retirar o snapshot `tools`, porque voltar a um snapshot devolve o
tamanho dele, **medido**). Testar: `cargo test -p xtask vm_lab` (tabela da decisão, `classify`,
`round_of_ssh`, a limpeza num `/srv/lab` falso, `live_rounds` com um `ssh` falso).
