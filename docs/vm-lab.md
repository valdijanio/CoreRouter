# Laboratório em VM com root para agentes (G0.26)

Os testes que precisam de root de verdade (carregar XDP, `BPF_PROG_LOAD`, o laboratório do BNG
com BNG Blaster e `pppd`) não rodam no host: os agentes nunca usam `sudo` lá. Em vez de esperar o
usuário rodar no terminal dele ou o runner do CI (~15 min, 4 vCPUs), eles rodam numa VM libvirt
local, onde o agente é root. O root fica dentro da VM.

São duas VMs desde a G0.26c (veja "Duas VMs"): a `corerouter-lab` (VM 1, 8 vCPUs, 16 GiB) para
as **medições de desempenho** e a `corerouter-lab2` (VM 2, 4 vCPUs, 6 GiB) para os **testes de
funcionamento**. O `vm-lab run` sem `--vm` usa a livre (a 2 primeiro); `--perf` pede a 1.

## Receita

```sh
cargo xtask vm-lab create          # uma vez: imagem, VM, pacotes, rustup, snapshot `clean`
cargo xtask vm-lab --vm 2 create --from 1   # a VM 2: cópia do snapshot `tools` da 1 (~75 s)
cargo xtask vm-lab run -- cargo test -p corerouter-hal-linux --test netns_l2   # a VM livre
cargo xtask vm-lab run --perf -- scripts/dns-stress-lab.sh …                   # medição: VM 1
cargo xtask vm-lab pin             # mapa de CPUs ao vivo nas duas VMs e no runner do CI
cargo xtask vm-lab run -- env COREROUTER_REQUIRE_XDP=1 cargo xtask xdp-root
cargo xtask vm-lab run -- cargo test -p corerouter-hal-linux --test xdp_root --no-run
cargo xtask vm-lab ssh             # shell como `lab` (sudo sem senha lá dentro)
cargo xtask vm-lab status          # as duas VMs: estado, CPUs, dono da trava e idade, endereço, snapshots, disco, NICs
cargo xtask vm-lab unlock          # quem segura a trava; --force encerra o que sobrou de rodada morta
cargo xtask vm-lab tools --check   # as ferramentas de terceiros estão lá? (o agente roda)
cargo xtask vm-lab tools           # instala as que faltam e tira o snapshot `tools` (o usuário roda)
cargo xtask vm-lab reset           # volta o disco ao snapshot `tools` (ou `clean`) e liga
```

Todo subcomando aceita `--vm 1|2` logo depois de `vm-lab` (ou `$COREROUTER_VM_LAB`; também
`lab`, `lab2` ou o nome inteiro). Sem ele: `run` escolhe, `status` e `unlock` mostram as duas, os
outros usam a VM 1, como antes.

| Subcomando | O que faz |
|---|---|
| `create [--cpus N] [--memory MiB] [--disk GiB] [--wires N] [--from 1]` | `--from 1` (G0.26c): copia o disco do snapshot `tools` (ou `clean`) da VM 1 com `qemu-img convert -U -l snapshot.name=tools`, como overlay sobre a mesma imagem base, sem parar nem tocar a VM 1 (os clusters de um snapshot não mudam enquanto ele existe), e liga com um seed novo (`instance-id`, hostname, MACs, chave de host próprios): o cloud-init a trata como máquina nova. Depois deixa só a chave dela no `authorized_keys`, gera outro `machine-id` e tira o snapshot `tools`. Sem `--from`: baixa a imagem Ubuntu 24.04 cloud uma vez e confere com o `SHA256SUMS` publicado (recusa e apaga se não bate), cria um overlay qcow2 fino, o seed do cloud-init, define e liga a VM, espera o cloud-init, instala o Rust e tira o snapshot `clean`. Padrão: VM 1 com 8 vCPUs, 16384 MiB, 40 GiB (20 GiB até 2026-11-13; veja "Disco"); VM 2 com 4 vCPUs, 6144 MiB, 30 GiB; 1 fio. |
| `up` / `down` | Liga e espera o SSH / desliga (ACPI; força depois de 90 s). |
| `ssh [cmd…]` | Shell ou um comando como `lab`. |
| `sync` | `rsync` da worktree para `/srv/lab/<worktree>/src` (sem `target*`, `.git`, `.claude/`, `vm/`, `plan/`; o app copia o `.claude/` para cada worktree, com o que estiver estacionado lá). |
| `put <arquivo…>` | Copia arquivos do host para `/srv/lab/inbox/` na VM (uma captura, um arquivo de config). |
| `tools [--check]` | Instala as ferramentas de terceiros declaradas em `xtask/src/vm_tools.rs` que faltam, imprime o que está instalado e tira o snapshot `tools`; `--check` só confere e diz o que falta. Idempotente. Veja "Ferramentas de terceiros". |
| `run [--perf [--no-quiet]] [--vm N] [--no-sync] [--shared] [--lock-timeout 30m] -- <cmd…>` | Escolhe a VM (veja "Duas VMs": `--perf` é a 1; sem `--vm`, a livre, a 2 primeiro) e diz qual na primeira linha. Com `--perf`, tira das CPUs da VM 1 os processos deste usuário no host enquanto a rodada segura a trava ("Medição silenciosa"). Confere a saúde da VM (root, processos novos, disco > 2 GiB e memória > 1 GiB livres; o que faz quando falha está em "Saúde da VM: reiniciar ou esperar": disco curto apaga os `target` que nenhuma rodada usa, e o `reset` sozinho só acontece sem outra rodada na VM), `sync`, pega a trava `/run/corerouter-lab.lock` (uma rodada por vez; `--shared` pula, só para compilar) e roda o comando **como root** em `/srv/lab/<worktree>/src`, com `CARGO_TARGET_DIR=/srv/lab/<worktree>/target`; saída ao vivo, código de saída repassado, tempo da rodada no fim. Um argumento só é uma linha de shell (`run -- 'a && b'`); vários são citados um a um. Espera a trava até `--lock-timeout` (ou `$COREROUTER_VM_LOCK_TIMEOUT`; padrão 30 min; `900`, `90s`, `30m`, `1h`) e então falha com código 75 dizendo quem a segura; o prazo vale só para a espera, nunca para a rodada. No fim avisa dos processos que o comando deixou vivos na VM. Uma rodada por worktree: se já há uma rodada da mesma worktree esperando ou rodando na VM, o `run` recusa antes do `sync` (ele sobrescreveria o código dela em `src`); `--no-sync` roda sobre o código que está lá. |
| `pick [--perf]` | Imprime o número da VM que um `run` pegaria agora. Para roteiro que faz `put` ou `ssh` antes do `run`: `export COREROUTER_VM_LAB=${COREROUTER_VM_LAB:-$(cargo xtask vm-lab pick)}`, e os três passos vão para a mesma VM. |
| `pin [--vm 1\|2\|ci] [--force]` | Aplica o mapa de CPUs ("CPUs por VM") com `virsh vcpupin/emulatorpin --live --config`: vale na hora e fica na definição, sem reiniciar. Sem `--vm`: as duas VMs do laboratório e o runner do CI. VM do laboratório com rodada é pulada (diz quando tentar de novo), salvo `--force`. |
| `unlock [--force]` | Sem `--vm`, nas duas VMs. Mostra a trava: dono (worktree, PID do `run` no host, round), há quanto tempo, e os processos que a seguram, esperam por ela ou sobraram de rodadas. Com `--force`, encerra (TERM, KILL depois de 5 s) os processos de rodadas cujo `vm-lab run` já não existe no host, o que solta a trava. Nunca mexe numa rodada viva nem em quem só espera. |
| `snapshot [nome] [--force]` / `reset [nome] [--force]` | Snapshot interno do disco (com a VM desligada; sem imagem de RAM) / volta o disco a ele e liga, mantendo a definição atual da VM (CPU, memória). Padrão `tools` (ou `clean`, se não houver `tools`). Recusa enquanto alguém está numa rodada: um `vm-lab run` vivo deste host com rodada na VM (segurando a trava, esperando por ela ou `--shared`), a trava do `run` na VM ou `vm/root.lock` no host (rodada à mão do usuário); `--force` passa por cima. Veja "Travas: regras e como destravar". |
| `destroy` | Apaga a VM, o overlay e o seed; a imagem baixada e a chave ficam. |

## Duas VMs (G0.26c, 2026-11-20)

Na rodada da fase C (2026-11-20) a fila levou 8–10 min do PR à `main` e o atraso das sessões veio
da VM única: a G3.4z esperou a rodada do DNS, que segurava a VM havia 919 s (**medido**).

| | `corerouter-lab` (VM 1) | `corerouter-lab2` (VM 2) |
|---|---|---|
| Para quê | medições de desempenho (`run --perf`) | testes de funcionamento (`run` a pega primeiro) |
| vCPUs, memória, disco | 8, 16 GiB, 20 GiB (40 se criada de novo) | 4, 6 GiB, 30 GiB |
| Arquivos no host | `vm/` (os mesmos de antes) | `vm/corerouter-lab2/` |
| MAC de gerência, fios | `…:72:01`, `…:73:nn` | `…:72:02`, `…:74:nn` |
| Portas UDP dos fios | 47210–47217 | 47230–47237 |
| CPUs do host (vCPU, QEMU) | 8–15 (um núcleo por vCPU), 24–31 | 4–7, 20–23 |

- **Cada VM tem disco, seed, chave SSH (`id_ed25519`, `known_hosts`, alias de host próprio),
  snapshots, `health.lock` e `root.lock` próprios**, e a trava de rodada
  (`/run/corerouter-lab.lock`) fica dentro de cada uma. Os caches compartilhados são só a imagem
  base (`vm/base/`) e os `.deb` (`vm/tools/`). A VM 1 ficou com os arquivos e nomes de antes:
  uma worktree com um `vm_lab.rs` antigo continua usando a VM 1 e é vista pelas novas como
  rodada nela.
- **Qual VM o `run` usa** (função pura `pick`, testes `pick_prefers_a_free_vm_2…`): `--perf` →
  VM 1; senão a VM livre, a 2 primeiro; as duas ocupadas → a com menos rodadas (empate: a 2);
  sem VM 2 criada → a 1, como antes. Ocupada = rodada viva nela vista do host (o ssh da rodada
  traz `HostKeyAlias=<nome>`) ou um `run` entre a conferência de saúde e a rodada (segura o
  `health.lock` dela). `--vm N` (ou `$COREROUTER_VM_LAB`) escolhe à mão; `--perf` com `--vm 2`
  é erro.
- **Cache de build por VM:** cada VM tem o seu `/srv/lab/<worktree>/target`. Uma rodada que cai
  na outra VM compila do zero ali (hal-linux: 40 s na VM 2, **medido**). Para compilar com
  `--shared` e depois rodar a medição, use `--perf` nos dois.
- **`put` e `ssh` vão para a VM 1 sem `--vm`.** Roteiro que copia antes do `run` fixa a VM:
  `wifi-bond-lab.sh`, `hostap-hwsim.sh` e `frr-topotests.sh` usam `vm-lab pick`;
  `dns-stress-lab.sh` e `ospf-stress-lab.sh` (medições) usam a 1.
- **Ferramentas:** a VM 2 criada com `--from 1` herda as do snapshot `tools` da 1. O que faltar
  aparece em `cargo xtask vm-lab --vm 2 tools --check`, e quem instala é o usuário
  (`cargo xtask vm-lab --vm 2 tools`). Em 2026-11-20 faltavam nas duas `qemu-system-x86`,
  `unzip` e `traceroute` (só o interop com o CHR usa); com o pedido do usuário, as duas voltaram
  ao `tools`, receberam os três e ganharam um `tools` novo (14 de 14, sem caches de build).

### CPUs por VM

O host é um Ryzen AI MAX+ 395: 16 núcleos com SMT em dois CCDs, cada um com o próprio L3. O CCD0
tem os núcleos 0–7 (CPUs 0–7 e as irmãs 16–23); o CCD1, os núcleos 8–15 (CPUs 8–15 e 24–31).

| VM | vCPU → CPU do host | QEMU (emulador, E/S) |
|---|---|---|
| `corerouter-lab` | vCPU i → 8+i (CCD1, um núcleo físico por vCPU) | 24–31 (irmãs SMT dos mesmos núcleos) |
| `corerouter-lab2` | 0–3 → 4–7 (CCD0) | 20–23 |
| `corerouter-ci` (runner, `ci_runner.rs`) | 16 vCPUs → 0–7 e 16–23 (CCD0 inteiro) | 0–7, 16–23 |
| `corerouter-teste` (do usuário) | sem mapa | — |

Nenhuma outra VM usa o CCD1: a medição na VM 1 não divide núcleo nem L3 com outro convidado. A VM 2
e o runner dividem o CCD0; os dois testam funcionamento, e a divisão só custa velocidade. O mapa
está em `VMS` e `CI_VCPU_CPUS` (`xtask/src/vm_lab.rs`; teste `the_measurement_vm_shares_no_cpu`),
entra no XML do `create` (das duas VMs e do `ci-runner create`) e o `vm-lab pin` o aplica ao vivo
numa VM que já existe. O `status` mostra o mapa de cada VM e se ele confere.

**O que o mapa não isola sozinho:** os processos do próprio host (os `cargo` das sessões, o app)
podem rodar nas CPUs 8–15 e 24–31. Para a medição, o `run --perf` os tira de lá enquanto mede
("Medição silenciosa", abaixo).

### Medição silenciosa (G0.26d)

Enquanto uma rodada `run --perf` segura a trava da VM 1, os processos **deste usuário** no host
saem das CPUs da VM 1 (8–15 e 24–31) e voltam no fim. Não precisa de root: um usuário pode mudar a
afinidade de CPU dos próprios processos (`taskset`, do util-linux), e nada da configuração do
sistema muda. Foi a opção escolhida pelo usuário em 2026-11-20, no lugar de `AllowedCPUs` no
`user.slice`, que exigiria root e deixaria as compilações do host com metade das CPUs o tempo
todo.

- **Quando:** só numa rodada `--perf` exclusiva na VM 1, e só depois de ela pegar a trava. A
  espera pela trava e uma compilação com `--shared --perf` não mexem em nada. `--no-quiet` (ou
  `$COREROUTER_VM_QUIET=0`) mede sem isso.
- **Como** (`xtask/src/vm_lab/quiet.rs`):
  1. o script da rodada imprime `vm-lab: quiet: lock taken` quando pega a trava; o host lê o
     stderr da rodada, faz a primeira varredura (0,2–1,2 s para ~300 processos, **medido**) e
     cria `/run/corerouter-lab.quiet.<round>` na VM;
  2. a rodada só começa o comando depois desse arquivo (no máximo 15 s);
  3. uma thread (`vm-lab-quiet`) varre o `/proc` a cada 2 s e tira das CPUs da VM 1 cada
     processo deste usuário que ainda esteja nelas (`taskset -a -p -c`, todas as threads). Os
     filhos de um processo já movido herdam a máscara;
  4. no fim, cada processo movido recebe de volta a máscara que tinha. Quem nasceu durante a
     rodada com exatamente a máscara reduzida ganha todas as CPUs. Quem mudou de máscara no meio
     tempo fica como está.
- **Se o `run` morrer** (Ctrl-C, `kill -9`): o estado fica em `vm/quiet.state` (dono, CPUs e a
  máscara original de cada processo, com o instante de início, para um PID reaproveitado não
  passar por outro). O próximo comando `vm-lab` qualquer devolve tudo, se o dono já não existe,
  e diz quantos devolveu. Conferido com `kill -9` no meio de uma rodada: o `status` seguinte
  devolveu 310 processos e nenhum ficou na máscara reduzida (**medido**).
- **O `status`** mostra a linha `quiet:` enquanto uma rodada mantém processos fora.
- **O que não sai:** processos de outros usuários e do root (serviços, threads do kernel; num
  2026-11-20 havia uma thread do ClickHouse do usuário `clickhouse` no CCD1) e as outras VMs (já
  fora pelo mapa).

Medição (2026-11-20, **medido**, carga do `### Medição` acima, 15 repetições por bloco):

| host | `--perf` | blocos | mediana de cada bloco | CV dentro do bloco | pior |
|---|---|---|---|---|---|
| sem os laços (carga 4–19) | silencioso | 2 | 826, 864 ms | 1,5–2,6 % | 950 ms |
| sem os laços (carga 4–19) | `--no-quiet` | 2 | 838, 902 ms | 0,9–7,5 % | 1056 ms |
| 32 laços ocupados + sessões (carga 19 → 64) | silencioso | 3 | 881, 901, 951 ms | 3,5–8,6 % | 1167 ms |
| idem | `--no-quiet` | 3 | 2155, 2622, 2695 ms | 7,0–16,3 % | 3094 ms |

- **Sob carga, a medição silenciosa fica 2,9× mais rápida e com metade da variação**, a ~5–10 % do
  host sem os laços.
- **A sobra não é tempo de CPU.** Numa rodada silenciosa sob carga 65–83 (com o runner do CI
  ocupado), o `/proc/stat` mostrou as CPUs 8–15 com 99 % de tempo de convidado e as irmãs 24–31
  com 93 % ociosas (**medido**): nada mais roda ali. Os +15–25 % e os 4–9 % de variação que
  sobram vêm do que os dois CCDs dividem (controlador de memória, interconexão, orçamento de
  energia do pacote). Uma carga que cabe no L3 (16 MiB) deu o mesmo (CV 4–5 %), então não é só
  banda de memória. Afinidade não resolve isso.
- **Para comparar antes/depois de um PR:** meça os dois lados com o host em carga parecida (blocos
  intercalados) e, para caminho quente, conte instruções (`perf stat -e instructions:u`), que não
  dependem do clock nem da memória.

### Medição (2026-11-20, **medido**)

Carga fixa na VM 1: 8 processos em paralelo, cada um com `sha256sum` de um arquivo de 512 MiB em
`/dev/shm`, três vezes; 15 repetições por bloco, tempo de parede de cada uma. Carga na VM 2: builds
release do `corerouter-hal-linux` em laço (uma rodada de funcionamento típica). Blocos
intercalados (com e sem mapa, com e sem carga na VM 2), host com carga média de 5 a 15 (outras
sessões compilando).

| VM 1 | VM 2 | blocos de 15 | mediana de cada bloco | CV dentro do bloco | pior repetição |
|---|---|---|---|---|---|
| com mapa | compilando | 4 | 940, 951, 951, 952 ms | 0,5–1,1 % | 984 ms |
| sem mapa | compilando | 3 | 936, 917, 965 ms | 0,7–2,4 % | 1014 ms |
| com mapa | parada | 3 | 943, 954, 983 ms | 0,7–1,2 % | 1007 ms |
| com mapa | parada, host com carga 13 | 1 | 1004 ms | 24 % | 1865 ms |
| sem mapa | parada | 2 | 936, 965 ms | 1,9 %, 21 % | 1544 ms |

- **A VM 2 compilando não muda a medição da VM 1 de forma visível:** 940–952 ms com ela
  compilando, 943–983 ms com ela parada; a diferença fica abaixo do que o host varia sozinho.
- **O mapa reduz a variação** dentro do bloco sob carga (CV 0,5–1,1 % contra 0,7–2,4 %; pior
  caso 984 contra 1014 ms). A mediana não muda de forma consistente (sem o mapa: de 917 a
  965 ms).
- **O ruído grande vem do host:** quando a carga do host subiu de 10 para 15, a VM 1 teve CV de
  20–24 % com e sem mapa (pior caso 1865 ms). Medição de PR: repita os blocos e compare a
  mediana; o `AllowedCPUs` acima é o que tiraria esse ruído.

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

## Saúde da VM: reiniciar ou esperar (2026-11-13)

Antes de cada rodada o `run` confere a VM: `sudo` funciona, cinco processos novos sobem, e há mais
de 2 GiB livres em `/srv/lab` e mais de 1 GiB de `MemAvailable`. Até 2026-11-13, qualquer falha
virava `reset` (`virsh destroy` + `snapshot-revert`) **mesmo com outra rodada no meio**. Às 15:16
daquele dia isso matou a fase C de DNS contra o notebook e uma rodada da G4.1w (as duas saíram com
255): o disco estava abaixo de 2 GiB porque uma rodada compilava em release. Os logs das sessões
mostram o mesmo motivo em outras rodadas (181, 1734 e 2007 MiB livres).

**Regra:** o `reset` automático só acontece com a VM sem rodada viva. A decisão é a função pura
`verdict` (`xtask/src/vm_lab.rs`, testes `a_live_round_is_never_reset` e vizinhos):

| Saúde | Sem rodada viva | Com rodada viva |
|---|---|---|
| boa | segue | segue (espera a trava na VM, como sempre) |
| disco curto, limpeza ainda não tentada | limpa os caches de build | limpa os caches de build |
| disco curto depois da limpeza, memória curta, root ou processos falhando, SSH sem resposta | `reset` para `tools` (ou `clean`); falhou de novo depois dele: erro | **espera**: confere de novo a cada 30 s; dentro do `--lock-timeout` |
| ainda ruim quando o `--lock-timeout` acaba | — | erro dizendo quem está na VM; nada é reiniciado |

- **Rodada viva** é um `vm-lab run` deste host cuja rodada já está na VM: o `ssh … sudo env
  COREROUTER_LAB_ROUND=<round> bash -c …` dele aparece no `/proc` do host, e o `vm-lab run` dono do
  round ainda existe (o mesmo teste do `unlock`). Vale para quem segura a trava, quem espera por
  ela e quem roda com `--shared`. Funciona com a VM sem responder ao SSH, porque só lê o host. O
  `vm/root.lock` segurado pelo usuário também conta. O `snapshot` e o `reset` à mão usam a mesma
  conta e recusam sem `--force`.
- **SSH lento sob carga não é VM morta.** Com rodada viva a conferência usa `ConnectTimeout=30` e
  até 180 s de resposta (sem rodada: 10 s e 60 s), e uma falha só leva a esperar e conferir de
  novo. Quando a rodada acaba e a VM ainda não responde, aí sim é `reset`.
- **Disco curto:** antes de declarar a VM doente, o `run` apaga os `/srv/lab/<worktree>/target`
  das worktrees sem rodada viva, do menos recente para o mais (data mais nova até dois níveis
  dentro do `target`), até ter 6 GiB livres. Ficam o `target` de toda rodada viva e o do próprio
  `run`, e todos os `src` (o próximo `run` daquela worktree só recompila). A saída lista o que
  saiu, o tamanho e a idade.
- **Uma conferência por vez:** a conferência, a limpeza e o `reset` rodam com `vm/health.lock`
  (trava de arquivo no host), que o `run` só solta quando o `ssh` da rodada dele já começou (e
  passou a contar como rodada viva para os outros). Assim dois `run` não reiniciam a VM juntos,
  e nenhum reinicia entre a conferência de outro e o começo da rodada dele.
- O tempo esperado na conferência sai do `--lock-timeout`: a espera pela trava dentro da VM fica
  com o que sobrou.

Uma worktree com um `vm_lab.rs` anterior a esta regra ainda reinicia por cima das outras: faça
`git merge origin/main` antes de usar o laboratório.

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

- **libvirt `qemu:///system`**, sem `sudo`: o usuário está no grupo `libvirt`. As VMs se chamam
  `corerouter-lab` e `corerouter-lab2`; a `corerouter-teste` e as `nl-node-*` são do usuário e
  nunca são tocadas, e a `corerouter-ci` é do `cargo xtask ci-runner` (o `vm-lab pin` só fixa as
  CPUs dela).
- **Arquivos em `vm/` do checkout principal** (no `.gitignore`), compartilhado por todas as
  worktrees (`$COREROUTER_VM_DIR` muda; os da VM 2 ficam em `vm/corerouter-lab2/`, com os
  mesmos nomes): `base/` (imagem e `SHA256SUMS`), `corerouter-lab.qcow2`
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

- Duas VMs para todas as sessões: dentro de cada uma os testes usam nomes fixos de namespace
  (`crxdp`, `crxsub`) e um apaga o do outro; os números de pps também dividem CPU. Por isso o
  `run` é exclusivo por VM (trava `flock` dentro dela; quem chega espera até o prazo e vê quem
  segura), e duas rodadas só andam juntas em VMs diferentes. Uma worktree com um `vm_lab.rs` antigo,
  sem a trava, ainda colide: faça `git merge origin/main`.
- `reset` volta o disco inteiro, inclusive o cache de build (o snapshot `tools` não tem cache): tire um `snapshot` depois de uma
  compilação longa se quiser voltar a ele quente.
- O snapshot é interno ao qcow2 e só com a VM desligada (`snapshot` desliga e religa).
- Desempenho medido na VM é de virtio, não de placa física: serve para comparar antes/depois,
  não como número de produção.
- **Disco** (revisto em 2026-11-13). A imagem tem ~600 MB e o overlay cresce com o uso, até o
  `--disk`. Com 20 GiB, o sistema do snapshot `tools` (Rust, FRR, BNG Blaster, QEMU para o CHR)
  ocupa 7,1 GiB dos 19 GiB da raiz (**medido**): sobram ~12 GiB para os `target` de todas as
  worktrees, e duas compilações em release já chegam perto do limite de 2 GiB. Por isso o
  `create` passou a 40 GiB (o overlay é fino: o host só gasta o que a VM escreve; o `/home`,
  onde fica o `vm/`, tinha 69 GiB livres em 2026-11-13). Para crescer a VM que já existe, sem
  rodada nenhuma (`cargo xtask vm-lab status`):

  ```sh
  cargo xtask vm-lab reset tools        # o disco que vai virar o novo `tools`
  cargo xtask vm-lab down
  qemu-img resize vm/corerouter-lab.qcow2 40G
  cargo xtask vm-lab up                 # o cloud-init (growpart + resizefs) cresce a raiz no boot
  cargo xtask vm-lab ssh df -h /        # confira: ~39G
  cargo xtask vm-lab snapshot tools     # obrigatório: senão o próximo reset volta a 20 GiB
  ```

  O `qemu-img resize` aceita qcow2 com snapshots internos (QEMU 8.2), mas cada snapshot guarda o
  próprio tamanho e voltar a ele devolve o disco a esse tamanho (**medido** com uma imagem de
  teste: 1 GiB → `resize` 2 GiB → `snapshot -a` → 1 GiB). Por isso o `tools` é tirado de novo; o
  `clean` fica com 20 GiB (só serve se o `tools` sumir).
- Se algum dia faltar permissão do libvirt (polkit), a alternativa sem root é
  `qemu:///session` com rede de usuário e encaminhamento de porta SSH; não foi preciso.

## Alternativas

O runner do CI (`.github/workflows/xdp-root.yml`) continua sendo o portão, e o usuário ainda
pode rodar `cargo xtask xdp-root` no terminal dele (veja `AGENTS.md`, "Acesso root e testes de
rede").
