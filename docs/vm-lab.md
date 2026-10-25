# Laboratório em VM com root para agentes (G0.26)

Os testes que precisam de root de verdade (carregar XDP, `BPF_PROG_LOAD`, o laboratório do BNG
com BNG Blaster e `pppd`) não rodam no host: os agentes nunca usam `sudo` lá. Em vez de esperar o
usuário rodar no terminal dele ou o runner do CI (~15 min, 4 vCPUs), eles rodam numa VM libvirt
local, `corerouter-lab`, onde o agente é root. O root fica dentro da VM.

## Receita

```sh
cargo xtask vm-lab create          # uma vez: imagem, VM, pacotes, rustup, snapshot `clean`
cargo xtask vm-lab run -- env COREROUTER_REQUIRE_XDP=1 cargo xtask xdp-root
cargo xtask vm-lab run -- cargo test -p corerouter-hal-linux --test xdp_root --no-run
cargo xtask vm-lab ssh             # shell como `lab` (sudo sem senha lá dentro)
cargo xtask vm-lab status          # estado, endereço, snapshots, disco, NICs
cargo xtask vm-lab reset           # volta o disco ao snapshot `clean` e liga
```

| Subcomando | O que faz |
|---|---|
| `create [--cpus N] [--memory MiB] [--disk GiB] [--wires N]` | Baixa a imagem Ubuntu 24.04 cloud uma vez e confere com o `SHA256SUMS` publicado (recusa e apaga se não bate), cria um overlay qcow2 fino, o seed do cloud-init, define e liga a VM, espera o cloud-init, instala o Rust e tira o snapshot `clean`. Padrão: 8 vCPUs, 16384 MiB, 20 GiB, 1 fio. |
| `up` / `down` | Liga e espera o SSH / desliga (ACPI; força depois de 90 s). |
| `ssh [cmd…]` | Shell ou um comando como `lab`. |
| `sync` | `rsync` da worktree para `/srv/lab/<worktree>/src` (sem `target*`, `.git`, `vm/`, `plan/`). |
| `put <arquivo…>` | Copia arquivos do host para `/srv/lab/inbox/` na VM (o `.deb` do BNG Blaster, uma captura). |
| `run [--no-sync] [--shared] -- <cmd…>` | Confere a saúde da VM (root, processos novos, disco > 2 GiB e memória > 1 GiB livres; se falhar duas vezes, `reset` para `clean` sozinho), `sync`, pega a trava `/run/corerouter-lab.lock` (uma rodada por vez; `--shared` pula, só para compilar) e roda o comando **como root** em `/srv/lab/<worktree>/src`, com `CARGO_TARGET_DIR=/srv/lab/<worktree>/target`; saída ao vivo, código de saída repassado, tempo da rodada no fim. Um argumento só é uma linha de shell (`run -- 'a && b'`); vários são citados um a um. |
| `snapshot [nome]` / `reset [nome]` | Snapshot interno do disco (com a VM desligada; sem imagem de RAM) / volta o disco a ele e liga, mantendo a definição atual da VM (CPU, memória). Padrão `clean`. |
| `destroy` | Apaga a VM, o overlay e o seed; a imagem baixada e a chave ficam. |

## Como é montada

- **libvirt `qemu:///system`**, sem `sudo`: o usuário está no grupo `libvirt`. A VM se chama
  sempre `corerouter-lab`; as VMs `nl-node-*` são do usuário e nunca são tocadas.
- **Arquivos em `vm/` do checkout principal** (no `.gitignore`), compartilhado por todas as
  worktrees (`$COREROUTER_VM_DIR` muda): `base/` (imagem e `SHA256SUMS`), `corerouter-lab.qcow2`
  (overlay sobre a imagem), `seed.iso`, `id_ed25519` (chave do laboratório, só para ele),
  `ssh_host_ed25519_key` e `known_hosts` (a chave de host da VM é gerada aqui e entra pelo
  cloud-init; o SSH confere com `HostKeyAlias=corerouter-lab`, então trocar de IP no DHCP não
  pede confiança de novo). Conexão SSH mestre (`ControlPersist`) deixa cada comando em ms.
- **Rede sem mexer no host.** Gerência (`mgmt0`) na rede `default` NAT do libvirt, que já
  existia: SSH e apt. Os enlaces de teste são pares de NICs **virtio** ligados um no outro por
  sockets UDP no `127.0.0.1` do host (`<interface type='udp'>`): `wire0a` ↔ `wire0b` (e
  `wire1a` ↔ `wire1b`… com `--wires`). Nenhuma bridge nova, nenhuma regra de iptables. O par
  fica na mesma VM: ponha cada ponta num namespace (`ip link set wire0b netns cli`) para ter
  roteador e cliente.
- **XDP nativo.** `virtio_net` tem XDP nativo (a r8169 do host não tem). O backend UDP não
  oferece offloads de GRO/TSO ao convidado, que é o que o `virtio_net` exige para aceitar XDP.
- **Pacotes** pelo cloud-init: build-essential, clang, llvm, pkg-config, iproute2, tcpdump, ppp,
  pppoe (rp-pppoe), ethtool, nftables, rsync, git, curl, jq, qemu-guest-agent. `unattended-upgrades`
  e os timers do apt ficam desligados (não disputam o lock nem mudam a VM entre rodadas).
- **CPU `host-model`, não `host-passthrough`.** Com passthrough o convidado recebia o CET
  (shadow stack) do host, que o KVM do kernel 7.0 oferece e o QEMU 8.2 não administra. Depois de
  ~45 min de uso, todo processo novo (sudo, bash, sshd) caía no mesmo endereço com erro de
  página 0x44/0x46 (acesso de shadow stack), **medido** em 2026-10-25. Com `host-model` (EPYC-Genoa
  + extras) o convidado não vê `user_shstk`.
- **`spec_rstack_overflow=off` no convidado** (`/etc/default/grub.d/90-corerouter-lab.cfg`,
  reaplicado pelo `up` se faltar). O `host-model` não diz ao convidado que a CPU é imune ao SRSO
  vindo do espaço de usuário (o libvirt 10.0 não tem nome para esses bits). O convidado escolhia
  então "Safe RET" em todo retorno do kernel e ficava 3× mais lento (veth 558 contra 1811 kpps,
  **medido**). O kernel do host também não usa Safe RET nesta CPU ("IBPB on VMEXIT only"):
  o convidado fica igual ao metal.
- **Kernel HWE 7.0** (`linux-generic-hwe-24.04`; o `create` reinicia nele): o 6.8 do 24.04 GA
  recusa o nosso programa XDP no verificador ("combined stack size of 3 calls is 544. Too
  large", **medido**; gap G2.5g).
- **Rust** pelo rustup em `/opt/rust` (root); o `rust-toolchain.toml` completa os componentes
  no primeiro `cargo`.

## Desempenho

- Cache de build persistente por worktree (`/srv/lab/<worktree>/target`): o `rsync -a` preserva
  as datas, então a rodada seguinte é incremental. Worktrees diferentes não se atropelam (pasta
  e alvo próprios) e podem rodar ao mesmo tempo; 8 vCPUs dão paralelismo ao `cargo`.
- Números (**medidos**, 2026-10-25, 8 vCPUs, 8 GiB; com 16 GiB e `host-model` o `xdp-root` quente
  levou 74,5 s e os PERF ficaram iguais): `create` 156 s com a imagem em cache; `xdp-root`
  completo 103 s com cache frio e 76 s quente (0,1 s de compilação; o resto são os testes); um
  teste só 4,9 s; `sync` sem mudança 0,2 s; `reset` 8,6 s. Detalhes no `docs/perf.md`.

## Limites

- Uma VM para todas as sessões: os testes usam nomes fixos de namespace (`crxdp`, `crxsub`) e um
  apaga o do outro; os números de pps também dividem CPU. Por isso o `run` é exclusivo (trava
  `flock` dentro da VM; quem chega espera e vê quem segura). Uma worktree com um `vm_lab.rs` antigo,
  sem a trava, ainda colide: faça `git merge origin/main`.
- `reset` volta o disco inteiro, inclusive o cache de build: tire um `snapshot` depois de uma
  compilação longa se quiser voltar a ele quente.
- O snapshot é interno ao qcow2 e só com a VM desligada (`snapshot` desliga e religa).
- Desempenho medido na VM é de virtio, não de placa física: serve para comparar antes/depois,
  não como número de produção.
- Disco: a imagem tem ~600 MB; o overlay cresce com o uso (o teto é `--disk`).
- Se algum dia faltar permissão do libvirt (polkit), a alternativa sem root é
  `qemu:///session` com rede de usuário e encaminhamento de porta SSH; não foi preciso.

## Alternativas

O runner do CI (`.github/workflows/xdp-root.yml`) continua sendo o portão, e o usuário ainda
pode rodar `cargo xtask xdp-root` no terminal dele (veja `AGENTS.md`, "Acesso root e testes de
rede").
