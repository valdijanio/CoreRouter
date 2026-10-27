# Imagem do sistema (G1.6a)

A imagem que vai no disco do roteador: kernel LTS, rootfs squashfs só de leitura, `/config`
gravável, `corerouter-init` como PID 1 e `corerouter-daemon` como único serviço. Construída
pelo Buildroot a partir de `os/` (uma árvore `BR2_EXTERNAL`), testada no QEMU sem root.

```sh
cargo xtask os check                 # confere a configuração (sem rede; também roda no `cargo xtask ci`)
cargo xtask os build                 # baixa e confere o Buildroot fixado, compila e grava os/out/build/images/disk.img
cargo xtask os boot-test             # boota no QEMU (KVM do usuário ou TCG) e faz ping no canal de controle TLS
cargo xtask os boot-test --efi       # o mesmo, pelo firmware UEFI (OVMF) e o disco inteiro
cargo xtask os boot-test --append corerouter.shell=ttyS0 --timeout 600   # com shell de manutenção na serial
```

Partes seguintes: G1.6b (A/B, assinatura, dm-verity, `system.package.update` com volta
automática, G1.26h) e G1.6c (instalador ISO/USB, qcow2/OVA, FRR e firmware na imagem).

## O que entra na imagem

| Parte | O quê | Onde |
|---|---|---|
| Buildroot | 2025.02.19, ramo **LTS** (correções de segurança até março de 2028); tarball conferido pelo SHA-256 do `.sign` assinado | `os/buildroot.lock` |
| Toolchain | Bootlin x86-64 glibc stable 2024.05-1 (gcc 13.3, glibc 2.39), pronta e com hash no Buildroot | `os/configs/corerouter_x86_64_defconfig` |
| Kernel | Linux **6.18.59** LTS (suporte projetado até dez/2028), `x86_64_defconfig` + fragmento; SHA-256 do `sha256sums.asc` assinado do kernel.org, conferido pelo Buildroot e de novo pelo xtask | `os/board/x86_64/linux.fragment`, `os/patches/linux/linux.hash` |
| Init | `corerouter-init` (Rust, este workspace) | `apps/corerouter-init` |
| Roteador | `corerouter-daemon --backend linux --config-dir /config --control 7979 --listen 0.0.0.0:8729` | `os/package/corerouter` |
| Espaço de usuário | `nft` (nftables com JSON, pelo `nft -j` do hal-linux), glibc, busybox (só para o shell de manutenção) | defconfig |

Tudo que o roteador precisa no kernel é `=y` (sem módulos): eBPF/XDP com BTF e JIT sempre
ligado, AF_XDP, nftables completo (NAT, conntrack, flowtable, fib, socket, synproxy), **VRF**
(`CONFIG_NET_VRF=y`, que destrava o `ip.vrf.add`, G1.14), MPLS (roteamento e túnel), bonding,
802.1Q, bridge com VLAN filtering, PPP/PPPoE, L2TP, WireGuard, VXLAN, GRE, filas (HTB, fq,
fq_codel, cake) e as placas ixgbe/ixgbevf, i40e/iavf (`I40EVF`), ice, mlx5, virtio, e1000/e1000e/igb/igc
e r8169. O `cargo xtask os build` confere que **todo** `=y` do fragmento sobreviveu ao
`olddefconfig` (um símbolo cuja dependência falta some sem aviso) e falha se algum sumiu.

### Disco

GPT com GUIDs fixos (imagem reprodutível):

| Partição | Tamanho | Conteúdo |
|---|---|---|
| `efi` | 32 MiB | vfat; `EFI/BOOT/BOOTX64.EFI` é o próprio kernel (EFI stub), sem bootloader |
| `rootfs-a` | 256 MiB | squashfs zstd, montado só de leitura (`root=PARTUUID=…`, tipo "Linux root x86-64" do Discoverable Partitions Spec) |
| `rootfs-b` | 256 MiB | vazio; o slot B do G1.6b (o layout não muda numa atualização em campo) |
| `config` | 64 MiB | ext4 vazio, rótulo `config`; vira `/config` |

A linha de comando está **dentro do kernel** (`CONFIG_CMDLINE`): `console=tty0
console=ttyS0,115200 root=PARTUUID=<rootfs-a> rootfstype=squashfs ro
init=/usr/sbin/corerouter-init panic=10 quiet`. O `cargo xtask os check` confere que o
PARTUUID bate com o `rootfs-a` do `genimage.cfg` e que o `init=` é o binário que o pacote
instala. `panic=10`: um kernel panic reinicia o roteador em 10 s, em vez de ficar parado.

### `corerouter-init` (PID 1 em Rust)

Faz só o que um appliance precisa, em ~450 linhas sem `unsafe` (rustix, signal-hook,
netlink-sys, já no `Cargo.lock`):

1. monta `/proc`, `/sys`, `/dev` (devtmpfs), `/dev/pts`, `/dev/shm`, `/run`, `/tmp`, `/var`
   (tmpfs com teto), `/sys/fs/cgroup` (cgroup2), `/sys/fs/bpf` (os mapas XDP do G2.5) e
   `tracefs`; a raiz continua squashfs só de leitura;
2. lê `corerouter.*` da linha de comando do kernel (valores hostis recusados e cortados);
3. sobe o `lo` com uma mensagem `RTM_NEWLINK` (sem binário `ip`): o canal de controle escuta em
   `127.0.0.1`;
4. monta `/config` da partição de rótulo `config` (espera até 5 s pelo probe assíncrono). Sem
   partição ou com falha de montagem, monta tmpfs e avisa em letras grandes que a
   configuração não sobrevive ao reboot: o roteador sobe e pode ser consertado pela rede;
5. inicia o daemon com ambiente limpo, saída em `/var/log/corerouter-daemon.log` (copiado e
   truncado acima de 8 MiB: um daemon falante nem enche o `/var` nem trava na serial de
   115200 baud), e o reinicia se cair: 0,5 s dobrando até 30 s, zerando depois de 60 s de pé.
   Nunca desiste: roteador sem plano de controle é pior que um tentando de novo. Ao cair, as
   últimas 20 linhas do log vão para a console;
6. colhe todo filho que termina (inclusive órfãos), como todo PID 1 tem de fazer;
7. avisa quando o daemon responde `ping` em `127.0.0.1:7979` pela primeira vez (`ready:` com o
   tempo desde o início do kernel) e, 10 s depois, a memória em uso (`idle:`);
8. desliga limpo pelos sinais que o busybox `reboot`/`poweroff`/`halt` mandam ao PID 1
   (SIGTERM/SIGUSR2/SIGUSR1) e por Ctrl-Alt-Del (SIGINT): SIGTERM ao daemon, 10 s para salvar,
   SIGKILL, `sync`, desmonta `/config` (ou remonta só de leitura), `reboot(2)`.

**Sem shell por padrão.** `corerouter.shell=ttyS0` na linha de comando abre um `sh` do busybox
naquela console (reaberto se sair), para laboratório e recuperação. Como a linha de comando está
gravada no kernel, ligar o shell num roteador em campo exige outra imagem ou acesso ao
firmware: é acesso físico, como o console serial de um Juniper.

## Pesquisa

Fontes: [Buildroot, download e LTS](https://buildroot.org/download.html),
[manual do Buildroot](https://buildroot.org/downloads/manual/manual.html) (BR2_EXTERNAL,
`BR2_PER_PACKAGE_DIRECTORIES`, `BR2_REPRODUCIBLE`), [kernel.org releases](https://www.kernel.org/category/releases.html),
[MikroTik: Upgrading and installation](https://help.mikrotik.com/docs/spaces/ROS/pages/328142/Upgrading+and+installation),
[VyOS: Update VyOS](https://docs.vyos.io/en/latest/installation/update.html),
[Talos](https://docs.siderolabs.com/talos), [Flatcar: update strategies](https://www.flatcar.org/docs/latest/setup/releases/update-strategies/),
[Junos: instalação e upgrade de software](https://www.juniper.net/documentation/us/en/software/junos/software-installation-and-upgrade/),
[RAUC](https://rauc.readthedocs.io/en/latest/basic.html), [Discoverable Partitions
Specification](https://uapi-group.org/specifications/specs/discoverable_partitions_specification/).

### Como os outros fazem imagem e atualização

| Sistema | Imagem | Atualização | Volta automática |
|---|---|---|---|
| **MikroTik RouterOS v7** | Pacotes `.npk` assinados pela MikroTik (o `routeros` principal e extras); x86/CHR instalado por ISO/imagem | `/system package update` (canal, Download, Download&Install); RouterBOOT atualizado à parte | Sem A/B automático; falha séria = Netinstall |
| **VyOS** | ISO com squashfs + overlay gravável por imagem; várias imagens lado a lado no GRUB | `add system image <url>` copia a config para a nova; LTS assinado com PGP | Escolher a imagem anterior no GRUB (manual) |
| **Juniper Junos** | Partições de boot primária e alternativa (snapshot) | `request system software add … validate` testa a config na versão nova antes; `request system snapshot` | Boot pela alternativa se a primária falhar |
| **Talos** | squashfs só de leitura, `machined` (Go) é o PID 1, **sem shell nem SSH**, só API | Imagem inteira A/B | Volta ao slot anterior se o boot não se confirmar |
| **Flatcar** | `/usr` A/B (USR-A/USR-B) só de leitura com dm-verity | `update_engine` baixa e grava o slot inativo, assinatura conferida | Atributos de prioridade/tentativas na GPT: boot ruim volta ao anterior |

O que tiramos daí:

- **Imagem inteira, só de leitura, sem gerenciador de pacotes** (Talos, Flatcar): o que roda é
  exatamente o que foi testado; nenhum "pacote extra" muda a imagem em campo. O MikroTik mostra
  o custo de pacotes separados: versões de pacote e de RouterBOOT descasadas.
- **Configuração fora da imagem** (`/config`, como o `/config` do VyOS): a imagem troca, a
  configuração fica. Diferente do VyOS, uma configuração só (não uma cópia por imagem); a
  migração de formato entre versões é do daemon (G0.6).
- **Validar antes de trocar** (Junos `validate`): no G1.6b, o slot novo sobe a config atual em
  modo de teste antes de virar o padrão.
- **A/B com contador de tentativas e confirmação** (Flatcar, Talos): é o G1.6b. O G1.6a já
  reserva o `rootfs-b` para não precisar reparticionar depois.
- **Sem shell, só API** (Talos, MikroTik): o roteador é operado por comandos (`Session::execute`,
  CLI, MCP, GUI); o shell só existe com flag de boot.

### Buildroot × alternativas

| Opção | Por que sim | Por que não | Veredito |
|---|---|---|---|
| **Buildroot LTS** | Imagem pequena com só o que pedimos; `BR2_EXTERNAL` mantém tudo nosso em `os/`; reprodutível (`BR2_REPRODUCIBLE`); um `make`; ramo LTS de 3 anos | Sem pacotes em campo (é o objetivo); recompila tudo ao mudar a toolchain | **Adotado** |
| Yocto/OpenEmbedded | Camadas, SDK, atualização por pacote | Curva grande, builds de horas, muito mais do que precisamos | Não |
| Alpine/Debian "imutável" | Pacotes prontos | Distro de uso geral: superfície maior, atualização por pacote não atômica | Só desenvolvimento |
| `mkosi`/imagem própria sem Buildroot | Simples | Teríamos de manter toolchain, glibc e nftables à mão | Não |

### Init: Rust × busybox init × systemd

| Opção | Prós | Contras |
|---|---|---|
| **`corerouter-init` em Rust** (adotado) | Só faz o que o appliance precisa; mesmas regras do projeto (sem panic, entrada hostil); mede o próprio boot; um binário a menos de terceiros no caminho do boot; base para o boot de teste do G1.6b (confirmar o slot quando o daemon responde) | Código nosso no PID 1: um erro derruba o boot. Mitigado: nada de `unwrap`, toda falha registra e segue, testes da parte pura, `panic=10` reinicia |
| busybox `init` + `inittab` | Maduro, minúsculo | Respawn sem backoff, sem prontidão, scripts de shell no boot (o que queremos tirar) |
| systemd | Paralelismo, watchdog, journald | Grande para um appliance; o supervisor de serviços já é o do daemon (G0.10) |

### RAUC × atualizador próprio em Rust (decisão para o G1.6b)

O RAUC é maduro (A/B, bundles squashfs assinados obrigatoriamente, formato verity para
streaming por HTTP, integração com GRUB/barebox/U-Boot, `mark-good`/`mark-bad`). Para o
CoreRouter a recomendação é **um atualizador próprio em Rust no G1.6b**, porque:

- a atualização tem de ser **um comando** (`system.package.update`), com journal, Safe Mode e
  confirmação pela GUI/MCP; o RAUC é um serviço D-Bus em C que teríamos de orquestrar;
- o boot sem bootloader (EFI stub; A/B por `BootNext`/`BootOrder` da UEFI ou por um UKI por
  slot) não é um dos bootloaders que o RAUC já integra;
- o formato que precisamos é pequeno: squashfs + árvore dm-verity + manifesto assinado com
  ed25519 (crate puro em Rust), conferidos antes de gravar o slot inativo.

Fica a ressalva para rever com dados: se o atualizador próprio passar de ~1.500 linhas ou
precisar de streaming delta, o RAUC volta a ser a opção (o formato de bundle verity dele é bom).

### O que ficou de fora e por quê

- **A/B, dm-verity, assinatura, atualização**: G1.6b.
- **Instalador, qcow2/OVA, FRR na imagem, firmware**: G1.6c. Sem o `linux-firmware`, a placa
  `ice` sobe em modo seguro (sem o pacote DDP: sem ajuste fino de RSS/flow director); ixgbe, i40e
  e mlx5 não precisam de arquivo de firmware.
- **Secure Boot**: o kernel é o próprio `BOOTX64.EFI`; assinar o EFI stub (ou um UKI) entra
  junto com a assinatura da imagem no G1.6b.
- **musl/estático**: a toolchain glibc do Bootlin serve ao daemon e ao `nft`; o daemon liga
  contra a mesma glibc da imagem (sem baixar outro alvo do Rust).

## Build reprodutível

- O Buildroot é fixado por versão **e** SHA-256 (`os/buildroot.lock`), baixado uma vez para
  `os/dl/` e extraído em `os/out/` (as duas pastas no `.gitignore`). Todo pacote é conferido
  pelo hash (`BR2_DOWNLOAD_FORCE_CHECK_HASHES`); o kernel, pelo `linux.hash` nosso.
- `BR2_REPRODUCIBLE`: `SOURCE_DATE_EPOCH` fixo, datas e ordem dos arquivos do squashfs fixas.
  GUIDs, volume id do vfat e UUID/hash seed do ext4 fixos no `genimage.cfg`.
- O Rust: `cargo build --release --locked --offline` com o cargo do `rust-toolchain.toml`,
  `--remap-path-prefix` para não gravar caminhos desta máquina, e ligado pelo gcc da toolchain
  do Buildroot contra a glibc da imagem (`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER`,
  `CC_x86_64_unknown_linux_gnu`). Como o alvo tem o mesmo nome do host, os build scripts também
  são ligados por esse gcc: a glibc da toolchain (2.39) não pode ser mais nova que a do host
  (hoje 2.39 nos dois).
- Medição de reprodutibilidade: veja "Números".

## Desempenho e paralelismo

### Build

- **Por pacote** o Buildroot já usa `-j$(nproc+1)` (`BR2_JLEVEL=0`); o kernel é o pacote mais
  longo e paraleliza bem.
- **Entre pacotes**: `BR2_PER_PACKAGE_DIRECTORIES=y` deixa usar `make -jN` no topo
  (`cargo xtask os build --top-jobs N`), com pacotes independentes compilando ao mesmo tempo.
- **Cache de download**: `os/dl/` fica entre builds; nada é baixado de novo.
- **Cache de compilação**: `BR2_CCACHE` em `os/out/ccache` (C/C++ do Buildroot e do kernel).
  O Rust tem o próprio cache incremental em `os/out/build/cargo-target`, fora da pasta do
  pacote, para o `corerouter-dirclean` de cada build não jogar fora as dependências.

### Boot

- Nada de módulos, udev, scripts ou serviços em série: o init monta, sobe o `lo`, monta
  `/config` e dispara o daemon. O paralelismo do boot é o do kernel (probe assíncrono das
  placas) e o do próprio daemon (threads por serviço, G0.10). Um segundo serviço no init
  não ajudaria: o único trabalho depois do kernel é o daemon ficar pronto.
- `quiet`: o kernel não escreve centenas de linhas na serial de 115200 baud (~11 KB/s) antes
  do init.
- squashfs zstd com `SQUASHFS_COMPILE_DECOMP_MULTI_PERCPU` (descompressão em paralelo, um
  descompressor por CPU) e `SQUASHFS_FILE_DIRECT`.

## Números
