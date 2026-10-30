# Runner próprio do CI (`corerouter-ci`)

Os jobs pesados do lote da fila de entrada (`test`, `bench-check`, `netns`) rodam num runner
self-hosted do GitHub Actions dentro de uma VM própria e descartável nesta máquina, em vez dos
runners de 4 vCPU do GitHub. O repositório é **público**, então o desenho parte da regra da
documentação do GitHub: runner próprio em repositório público só pode receber código confiável.

```sh
cargo xtask ci-runner create        # a VM, uma vez (o agente pode rodar)
cargo xtask ci-runner register      # O USUÁRIO roda: pede o token e registra os runners
cargo xtask ci-runner status        # VM, runners, job em andamento, veredictos, visão do GitHub
cargo xtask ci-runner check-network # de dentro da VM: internet sim; LAN, host e IPv6 não
cargo xtask ci-runner reset         # volta ao snapshot `registered` (o cache de build fica)
cargo xtask ci-runner down          # desliga: a fila passa a usar os runners do GitHub
cargo xtask ci-runner unregister --yes   # O USUÁRIO roda: remove os runners do GitHub
cargo xtask ci-runner destroy       # apaga a VM e os discos
```

## Como funciona

| Peça | O quê |
|---|---|
| VM | `corerouter-ci` no `qemu:///system`, criada sem `sudo` como a `corerouter-lab` (`xtask/src/ci_runner.rs`, que reaproveita a imagem verificada, o `virsh` e o SSH do `vm_lab.rs`). Padrão: 16 vCPUs, 16 GiB, disco de sistema de 40 GiB e disco de cache de 200 GiB, ambos qcow2 finos em `/srv/build/ci-runner/` (`$COREROUTER_CI_RUNNER_DIR`). |
| Runners | 3 instâncias (`corerouter-ci-1…3`, rótulo `corerouter`), uma por job: o lote tem 4 jobs pesados (`test` 1/2 e 2/2, `bench-check`, `netns`). Cada uma é `corerouter-runner@<n>.service`, como o usuário `runner`, **sem sudo**, com `NoNewPrivileges`, `ProtectSystem=full` e `PrivateTmp`. O pacote do runner é o oficial, fixado por versão e SHA-256 (`RUNNER_VERSION`); depois ele se atualiza sozinho, como o GitHub exige. |
| Memória | 16 GiB mais 16 GiB de swap no disco de cache: com 3 jobs ao mesmo tempo o bench `frames` (6,4 GB de RSS) levou OOM sem swap (**medido**), e o host não tem RAM livre para uma VM maior. |
| Cache | Cada runner tem o próprio `CARGO_TARGET_DIR=/var/cache/corerouter-ci/target-<n>` no disco de cache, que sobrevive ao `reset`: é daí que vem o ganho (os runners do GitHub restauram ~1,5 min de cache e recompilam o resto a cada job). O `cargo xtask ci` divide as 3 vagas entre eles (`XDG_RUNTIME_DIR=/run/corerouter-ci`). |
| Pacotes e kernel | O `runner` está no grupo `systemd-journal`, como no runner do GitHub (os testes do `oslog` leem o journal da máquina). Os cabeçalhos da GUI, `nftables`, `clang`, o nextest, a toolchain do `rust-toolchain.toml` e o kernel HWE já vêm na VM. Os módulos de `ci/kernel-modules/` e o `vrf` são carregados no boot, e o `reset`/`up` relê a lista do checkout; os user namespaces sem root ficam liberados. A action `setup` pula apt, rust-cache, nextest e `sudo modprobe` quando `runner.environment == 'self-hosted'` e só confere os módulos. |
| `xdp-root` e `lint` | Ficam no GitHub. O `xdp-root` roda o binário de teste como root (`sudo ip netns exec`), e dentro da VM o `runner` não tem sudo; além disso ele mede vazão, que a VM dividida com os outros jobs distorceria. O `lint` leva ~1,5 min e não é o gargalo. |

### Só código confiável chega ao runner

Três camadas, cada uma suficiente para o caso comum:

1. **Roteamento no workflow** (`.github/workflows/ci.yml`, job `changes`, saída `runs_on`): os
   jobs pesados vão para `[self-hosted, corerouter]` só em `workflow_dispatch` numa branch
   `queue/*` com a entrada `runner=corerouter` (o lote da fila) e em `push` na `main` quando a
   variável do repositório `CI_RUNNER` vale `corerouter`. `pull_request` — inclusive de fork —
   fica sempre em `ubuntu-latest`. Só quem tem escrita no repositório dispara `workflow_dispatch`
   ou cria `queue/*`.
2. **Hook do runner** (`ACTIONS_RUNNER_HOOK_JOB_STARTED=/etc/corerouter-ci/job-started.sh`, do
   root, posto pelo `EnvironmentFile` da unit, fora do alcance do job): roda antes de cada job e
   o **reprova antes do primeiro passo** se não for `push` em `refs/heads/main` ou
   `workflow_dispatch` em `refs/heads/queue/*` de `valdijanio/CoreRouter`. Variável ausente
   reprova (falha fechada). Isto vale mesmo que um PR de fork altere o `ci.yml` para pedir
   `runs-on: self-hosted`: o `pull_request` usa o workflow do próprio PR, então só o roteamento
   não bastaria. Cada veredicto vai para `/var/lib/corerouter-ci/jobs.log` (`status` mostra os
   últimos).
3. **Fila de entrada** (`scripts/land.sh`): um lote com algum PR de fork (`isCrossRepository`)
   vai inteiro para os runners do GitHub. Só quem tem escrita põe o rótulo `fila`.

### Rede: só a internet

A VM fica na rede `default` do libvirt (NAT em `192.168.122.0/24`). Sem filtro, um processo nela
alcançaria a LAN da casa (`192.168.0.0/24`), o roteador e todo serviço do host que escuta em
`0.0.0.0` (inclusive pelo `192.168.122.1`). Por isso a interface leva o nwfilter
`corerouter-ci-egress`, aplicado pelo libvirt **no host** (ebtables na porta da bridge; root
dentro da VM não o desliga):

- passa: DNS e DHCP para o gateway do NAT; o resto da internet;
- cai: `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `169.254/16`, `127/8`, `0/8`,
  multicast/reservado (`224/3`), **todo endereço do host** (lido de `ip -4 addr` a cada
  `create`/`up`/`reset`: o host tem um endereço público no `lo`, que as faixas privadas não
  cobririam) e todo IPv6.

`cargo xtask ci-runner check-network` confere de dentro da VM, como root: DNS e HTTPS para o
GitHub respondem; o gateway da LAN, cada endereço do host (portas 22, 53, 80, 443, 7979 e 8729 e
ping), endereços das faixas privadas e IPv6 não. O `create` falha se algo vazar.

### Reset e cache

- Os snapshots (`base`, `registered`) são internos ao disco de sistema, com `qemu-img snapshot` e a
  VM desligada: o snapshot interno do libvirt leva todos os discos, e o de cache tem de ficar.
- `reset` desliga os runners (recusa se houver job em andamento, salvo `--force`), volta o disco
  de sistema ao snapshot `registered` (ou `base`, antes do registro) e liga. O disco de cache
  fica; `--wipe-cache` o limpa (use depois de um incidente ou se o cache crescer demais).
- `reset --if-due [N]` só reseta depois de N jobs (padrão 40, ~10 lotes). A fila contínua o
  chama quando fica ociosa (no máximo a cada 10 min; `CI_RUNNER_RESET_JOBS`). Durante o reset
  (~1 min) os runners ficam offline e o próximo lote vai para o GitHub.
- **Por que não `--ephemeral`/JIT:** um runner efêmero se desregistra depois de um job e precisa
  de um token novo a cada job. O token de registro vale 1 hora, então isso exigiria guardar no
  host um token de administrador (PAT ou GitHub App) para gerar os JIT — um segredo mais
  poderoso do que o que se protege. Aqui o runner é persistente, mas só recebe código confiável
  (hook), não tem sudo nem rede local, e o disco volta ao snapshot a cada N jobs. Se um dia houver
  PR de fora no runner, o próximo passo é o JIT com um GitHub App de escopo mínimo.

## Etapa do usuário (uma vez)

**Feita em 2026-10-30:** os três runners estão registrados e `online`, o snapshot `registered`
existe e a opção de fork acima está ligada. Um token novo só é preciso depois de `destroy`, de
`unregister` ou de a VM ficar mais de 14 dias desligada (o GitHub remove o runner sumido).


1. **Conferir as opções do repositório** (GitHub → Settings → Actions → General):
   - *Fork pull request workflows from outside collaborators* → **Require approval for all
     external contributors** (ligado em 2026-10-30). Um PR de fork não roda nada
     sem a sua aprovação, e nunca aprove um que mexa em `.github/`.
   - *Workflow permissions* → **Read repository contents and packages permissions** (já está) e
     *Allow GitHub Actions to create and approve pull requests* desmarcado (já está).
   - *Actions permissions*: hoje *Allow all actions*. Opcional: *Allow … and select non-…* com
     *Require actions to be pinned to a full-length commit SHA* (o `ci.yml` já fixa por SHA).

   Pelo terminal, se preferir:

   ```bash
   gh api -X PUT repos/valdijanio/CoreRouter/actions/permissions/fork-pr-contributor-approval -f approval_policy=all_external_contributors
   ```

2. **Registrar os runners** (a VM já criada):

   ```bash
   cargo xtask ci-runner register
   ```

   Ele pede o token (GitHub → Settings → Actions → Runners → **New self-hosted runner** →
   Linux; copie o valor depois de `--token`, válido por 1 hora). O token é lido do terminal sem
   eco e vai à VM pelo stdin do SSH (`ACTIONS_RUNNER_INPUT_TOKEN`): nunca aparece em argumento,
   arquivo ou log. Registra os 3 runners com o rótulo `corerouter`, liga os serviços e tira o
   snapshot `registered`.

3. **Conferir:** `cargo xtask ci-runner status` mostra os três `online` no GitHub. O próximo lote
   da fila sai com "runner corerouter" no log; para testar já,
   `gh workflow run ci.yml --ref <uma branch queue/…> -f runner=corerouter`.

4. **Opcional — `main` também no runner:** a `main` não está no caminho da fila (o lote já
   testou a mesma árvore), e um job em `self-hosted` sem runner online fica até 24 h na fila do
   Actions. Ligue só se quiser:

   ```bash
   gh variable set CI_RUNNER -R valdijanio/CoreRouter --body corerouter
   ```

   e desligue com `gh variable delete CI_RUNNER -R valdijanio/CoreRouter` antes de um `down`
   longo.

## Operação

| Situação | Comando |
|---|---|
| Desligar por um tempo | `cargo xtask ci-runner down`. O GitHub mostra os runners offline e a fila usa os do GitHub. Religar: `up`. |
| Lote preso em "Waiting for a runner" | O runner caiu depois da fila escolher. `ci-runner status`; `ci-runner up`; ou cancele o run e deixe a fila repetir (ela escolhe de novo). |
| Módulo novo em `ci/kernel-modules/` | O `setup` no runner falha dizendo qual módulo falta. `cargo xtask ci-runner reset` no checkout atualizado relê a lista e carrega. |
| Suspeita de comprometimento | `ci-runner down`, `unregister --yes`, `destroy`; confira `jobs.log` antes (`ssh sudo cat /var/lib/corerouter-ci/jobs.log`); recrie e registre de novo com token novo. |
| Revogar de vez | `cargo xtask ci-runner unregister --yes` (ou GitHub → Settings → Actions → Runners → … → Remove), `ci-runner destroy` e, se ligou, `gh variable delete CI_RUNNER`. A fila volta sozinha aos runners do GitHub. |
| Forçar a escolha da fila | `LAND_CI_RUNNER=github scripts/land.sh --watch` (ou `corerouter`). |
| Rodar algo como um job | `cargo xtask ci-runner run --rev <commit> -- cargo xtask ci --only test` (exporta o commit, roda como `runner` com o ambiente dos runners). |

Recursos do host: a VM pega 16 vCPUs e 16 GiB enquanto ligada (o host tem 32 núcleos e 62 GiB; a
`corerouter-lab` usa 8/16). Desligue-a (`down`) quando precisar da máquina inteira.
