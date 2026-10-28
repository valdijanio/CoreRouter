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
cargo xtask vm-lab status          # estado, dono da trava e idade, endereço, snapshots, disco, NICs
cargo xtask vm-lab unlock          # quem segura a trava; --force encerra o que sobrou de rodada morta
cargo xtask vm-lab tools --check   # as ferramentas de terceiros estão lá? (o agente roda)
cargo xtask vm-lab tools           # instala as que faltam e tira o snapshot `tools` (o usuário roda)
cargo xtask vm-lab reset           # volta o disco ao snapshot `tools` (ou `clean`) e liga
```

| Subcomando | O que faz |
|---|---|
| `create [--cpus N] [--memory MiB] [--disk GiB] [--wires N]` | Baixa a imagem Ubuntu 24.04 cloud uma vez e confere com o `SHA256SUMS` publicado (recusa e apaga se não bate), cria um overlay qcow2 fino, o seed do cloud-init, define e liga a VM, espera o cloud-init, instala o Rust e tira o snapshot `clean`. Padrão: 8 vCPUs, 16384 MiB, 20 GiB, 1 fio. |
| `up` / `down` | Liga e espera o SSH / desliga (ACPI; força depois de 90 s). |
| `ssh [cmd…]` | Shell ou um comando como `lab`. |
| `sync` | `rsync` da worktree para `/srv/lab/<worktree>/src` (sem `target*`, `.git`, `.claude/`, `vm/`, `plan/`; o app copia o `.claude/` para cada worktree, com o que estiver estacionado lá). |
| `put <arquivo…>` | Copia arquivos do host para `/srv/lab/inbox/` na VM (uma captura, um arquivo de config). |
| `tools [--check]` | Instala as ferramentas de terceiros declaradas em `xtask/src/vm_tools.rs` que faltam, imprime o que está instalado e tira o snapshot `tools`; `--check` só confere e diz o que falta. Idempotente. Veja "Ferramentas de terceiros". |
| `run [--no-sync] [--shared] [--lock-timeout 30m] -- <cmd…>` | Confere a saúde da VM (root, processos novos, disco > 2 GiB e memória > 1 GiB livres; se falhar duas vezes, `reset` para `clean` sozinho), `sync`, pega a trava `/run/corerouter-lab.lock` (uma rodada por vez; `--shared` pula, só para compilar) e roda o comando **como root** em `/srv/lab/<worktree>/src`, com `CARGO_TARGET_DIR=/srv/lab/<worktree>/target`; saída ao vivo, código de saída repassado, tempo da rodada no fim. Um argumento só é uma linha de shell (`run -- 'a && b'`); vários são citados um a um. Espera a trava até `--lock-timeout` (ou `$COREROUTER_VM_LOCK_TIMEOUT`; padrão 30 min; `900`, `90s`, `30m`, `1h`) e então falha com código 75 dizendo quem a segura; o prazo vale só para a espera, nunca para a rodada. No fim avisa dos processos que o comando deixou vivos na VM. |
| `unlock [--force]` | Mostra a trava: dono (worktree, PID do `run` no host, round), há quanto tempo, e os processos que a seguram, esperam por ela ou sobraram de rodadas. Com `--force`, encerra (TERM, KILL depois de 5 s) os processos de rodadas cujo `vm-lab run` já não existe no host, o que solta a trava. Nunca mexe numa rodada viva nem em quem só espera. |
| `snapshot [nome] [--force]` / `reset [nome] [--force]` | Snapshot interno do disco (com a VM desligada; sem imagem de RAM) / volta o disco a ele e liga, mantendo a definição atual da VM (CPU, memória). Padrão `tools` (ou `clean`, se não houver `tools`). Recusa enquanto alguém está numa rodada: a trava do `run` na VM ou `vm/root.lock` no host (rodada à mão do usuário); `--force` passa por cima. Veja "Travas: regras e como destravar". |
| `destroy` | Apaga a VM, o overlay e o seed; a imagem baixada e a chave ficam. |

## Travas: regras e como destravar (G0.26b)

### As duas travas

| Trava | Onde | Quem pega | Para quê |
|---|---|---|---|
| `/run/corerouter-lab.lock` (+ `.lock.owner`) | dentro da VM | o próprio `vm-lab run` (sem `--shared`) | uma rodada de root por vez: os testes usam nomes fixos de namespace (`crxdp`, `crxsub`) e dividem CPU. **É a trava das sessões.** |
| `vm/root.lock` | no host | só o **usuário**, à mão: `flock vm/root.lock cargo xtask vm-lab tools` | segura `snapshot` e `reset` (que recusam enquanto ela existe) durante uma rodada manual dele. |

O `.lock.owner` diz de quem é a rodada (`worktree=`, `round=`, `host_pid=` do `vm-lab run` no
host e `started=` em segundos Unix). Cada processo da rodada leva `COREROUTER_LAB_ROUND=<round>`
no ambiente: é assim que o `run` acha o que sobrou e que o `unlock` distingue rodada viva de
rodada morta (o round é `<pid>.<início>` do processo no host, então um PID reaproveitado não
passa por vivo).

### Regras

- **Sessões usam só `cargo xtask vm-lab run`**, nunca `flock vm/root.lock cargo xtask vm-lab run …`.
  A `run` já espera sozinha pela trava da VM. Com as duas, uma sessão segura `vm/root.lock` e
  espera a da VM enquanto a outra espera `vm/root.lock`: ninguém anda.
- **Teste que sobe daemon (FRR, servidor, `pppd`) o desliga no fim, mesmo em falha**, com `trap`:

  ```sh
  trap 'pkill -x zebra; pkill -x bgpd; ip netns del crfrr 2>/dev/null' EXIT
  ```

  Desde o G0.26b o comando roda com o descritor da trava fechado, então um daemon esquecido não
  trava mais a VM, mas ainda atrapalha a próxima rodada (porta ocupada, namespace com o mesmo
  nome). O `run` avisa no fim, com PID e comando, quando sobra processo da rodada.
- A espera tem prazo (`--lock-timeout`, padrão 30 min). Estourou: a saída já diz quem segura,
  há quanto tempo e quais processos; siga a receita abaixo.

### O incidente de 2026-10-28

1. O `run` pegava a trava com `exec 9>>/run/corerouter-lab.lock; flock 9` e o comando herdava o
   fd 9. Um teste subiu um `zebra` do FRR como daemon; ele ficou vivo depois da rodada segurando
   a trava para sempre (`fuser -v` mostrava `frr 29514 zebra`), e o `.lock.owner` apontava para a
   rodada morta.
2. As sessões rodavam `flock vm/root.lock cargo xtask vm-lab run …`: a sessão A segurava
   `vm/root.lock` esperando a trava da VM (presa pelo zebra) e a B esperava `vm/root.lock`.
3. `flock 9` esperava sem prazo e sem avisar: ~40 min parados.

Correção (G0.26b): o comando roda com `9>&-`; a espera é `flock -w`; o owner ganhou round e
PID do host; o `run` lista o que sobrou; `unlock` e `status` mostram e destravam.

### Diagnóstico

```sh
cargo xtask vm-lab status                      # "rounds: busy: … held by <worktree> (host pid N) for 12m03s"
cargo xtask vm-lab unlock                      # dono, idade, processos (segura / espera / sobrou)
cargo xtask vm-lab ssh sudo fuser -v /run/corerouter-lab.lock
cargo xtask vm-lab ssh cat /run/corerouter-lab.lock.owner
pgrep -af 'vm-lab run'                         # no host: as rodadas vivas
pgrep -ax flock                                # no host: alguém embrulhou em flock vm/root.lock?
```

### Solução

```sh
cargo xtask vm-lab unlock --force
```

Encerra os processos de rodadas cujo `vm-lab run` já não existe no host (TERM, KILL depois de
5 s) e, com isso, solta a trava. Se o dono ainda está vivo, o `unlock` recusa: espere, ou pare
aquele `vm-lab run` (Ctrl-C) e rode de novo. Um dono gravado por um `vm_lab.rs` antigo (linha
`/srv/lab/<worktree> since …`) conta como vivo enquanto houver um `vm-lab run` daquela worktree no
host. Se o `unlock` não puder decidir, ele diz o PID para encerrar à mão
(`cargo xtask vm-lab ssh sudo kill <pid>`). `vm/root.lock` no host é do usuário: quem o segura é
um `flock` visível no `pgrep -ax flock`.

## Ferramentas de terceiros

O nosso código (a worktree, compilada dentro da VM) roda pelo `vm-lab run` sem perguntar nada.
Programas de terceiros baixados, como o `.deb` do BNG Blaster, são outra história: o classificador
do modo automático do app bloqueia o agente de instalá-los ou executá-los ("Code from External"),
mesmo com o `cargo xtask vm-lab` liberado. Isso é proposital: código de fora entra por decisão
humana. Por isso a instalação é do usuário, **uma vez por ferramenta nova**, e fica:

1. A ferramenta é declarada em `xtask/src/vm_tools.rs` (`TOOLS`), revisada como código: pacote,
   versão, URL oficial (`https://`) e SHA-256 do `.deb`, ou só o nome, para pacote do arquivo
   assinado do Ubuntu. Confira o hash contra o publicado pelo projeto (no GitHub, o `digest` do
   asset do release).
2. O usuário roda `cargo xtask vm-lab tools`. O comando baixa cada `.deb` uma vez para
   `vm/tools/`, confere o hash no host e de novo na VM, instala tudo num `apt-get install` só (o
   apt resolve as dependências do `.deb`), imprime as versões e tira o snapshot `tools`. Se o
   hash não bate, o arquivo é apagado e nada é instalado. Pode rodar dentro do `flock vm/root.lock …` de
   sempre: a trava do próprio comando não impede o snapshot.
3. A partir daí `reset` (e o reset automático do health-check) volta para `tools`, com as
   ferramentas dentro. Os agentes rodam `cargo xtask vm-lab tools --check` antes do lab: se
   faltar algo, a mensagem diz exatamente o que pedir ao usuário.

Acrescentar uma ferramenta: uma entrada em `TOOLS` num PR (com o link do hash publicado no corpo),
e depois do merge o usuário roda `cargo xtask vm-lab tools`. Hoje: BNG Blaster 1.0.1 (`.deb` do
release da rtbrick), `ppp`, `pppoe`, `tcpdump`, `iperf3`, `ethtool` e o FRR 10.7.1 com
`frr-pythontools` e `libyang3` (`.deb` de deb.frrouting.org, G3.1), `qemu-system-x86`, `unzip` e
`traceroute` (G3.9: o RouterOS CHR roda em QEMU/KVM aninhado dentro da VM; a imagem do CHR o
próprio `scripts/routeros-interop.sh` baixa e confere com o SHA-256 da MikroTik, e o roteiro
instala os três pacotes do Ubuntu se faltarem). Veja `docs/producao-core.md`, "Laboratório".

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
  `flock` dentro da VM; quem chega espera até o prazo e vê quem segura). Uma worktree com um `vm_lab.rs` antigo,
  sem a trava, ainda colide: faça `git merge origin/main`.
- `reset` volta o disco inteiro, inclusive o cache de build (o snapshot `tools` não tem cache): tire um `snapshot` depois de uma
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
