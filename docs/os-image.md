# Imagem do sistema (G1.6a, G1.6b, G1.6c, G1.6e, G1.6k, G1.6m)

A imagem que vai no disco do roteador: kernel LTS, rootfs squashfs só de leitura, `/config`
gravável, `corerouter-init` como PID 1 e `corerouter-daemon` como único serviço. Construída
pelo Buildroot a partir de `os/` (uma árvore `BR2_EXTERNAL`), testada no QEMU sem root.

```sh
cargo xtask os check                 # confere a configuração (sem rede; também roda no `cargo xtask ci`)
cargo xtask os build                 # baixa e confere o Buildroot fixado, compila e grava os/out/build/images/disk.img
cargo xtask os boot-test             # boota no QEMU (KVM do usuário ou TCG) e faz ping no canal de controle TLS
cargo xtask os boot-test --tcg       # sem KVM (emulação; ~3× mais lento)
cargo xtask os boot-test --efi       # o mesmo, pelo firmware UEFI (OVMF) e o disco inteiro
cargo xtask os boot-test --append corerouter.shell=ttyS0 --timeout 600   # com shell de manutenção na serial
cargo xtask os ab-test               # G1.6b: os 4 cenários A/B no QEMU (UEFI, sem root)
cargo xtask os install-test          # G1.6c: instalador (CD, USB, interativo), qcow2 e OVA no QEMU
cargo xtask os frr-test              # G1.6k: dois roteadores da imagem com OSPF, SR, LDP e BFD entre eles
cargo xtask os package --out b.crpkg --version 0.1.1 --build 1800000000  # outro pacote deste build
cargo xtask os build --only crpkg    # G1.6e: só o pacote de atualização (sem disk.img, ISO, qcow2, OVA)
cargo xtask os push --to 127.0.0.1:7990   # G1.6e: --only crpkg, envia pela rede, espera o slot novo confirmar
```

A/B e atualização: seção "A/B e atualização segura (G1.6b)" abaixo. Instalador, imagens de VM e
FRR: seção "Instalador, imagens de VM e FRR (G1.6c)" no fim.

## O que entra na imagem

| Parte | O quê | Onde |
|---|---|---|
| Buildroot | 2025.02.19, ramo **LTS** (correções de segurança até março de 2028); tarball conferido pelo SHA-256 do `.sign` assinado | `os/buildroot.lock` |
| Toolchain | Bootlin x86-64 glibc stable 2024.05-1 (gcc 13.3, glibc 2.39), pronta e com hash no Buildroot | `os/configs/corerouter_x86_64_defconfig` |
| Kernel | Linux **6.18.59** LTS (suporte projetado até dez/2028), `x86_64_defconfig` + fragmento; SHA-256 do `sha256sums.asc` assinado do kernel.org, conferido pelo Buildroot e de novo pelo xtask | `os/board/x86_64/linux.fragment`, `os/patches/linux/linux.hash` |
| Init | `corerouter-init` (Rust, este workspace) | `apps/corerouter-init` |
| Roteador | `corerouter-daemon --backend linux --config-dir /config --control 7979 --listen 0.0.0.0:8729` | `os/package/corerouter` |
| Espaço de usuário | `nft` sem JSON e sem CLI interativa (só diagnóstico no shell de manutenção: o hal-linux fala nfnetlink, G2.8), glibc, busybox (só para o shell de manutenção) | defconfig |
| Roteamento | FRR **10.7.1** com libyang 3.13.6 (a versão validada na VM do laboratório; receita do Buildroot `master` portada, G1.6k): `mgmtd`, `zebra`, `staticd`, `bgpd`, `ospfd`, `ospf6d`, `ldpd`, `bfdd`, iniciados pelo `corerouter-init`; sem `vtysh`, scripts nem bash (G1.6c) | defconfig, `post-build.sh`, `os/buildroot-patches/` |

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
| `efi` | 128 MiB | vfat; `EFI/BOOT/BOOTX64.EFI` é o kernel do slot A (EFI stub), `EFI/COREROUTER/B.EFI` o do B, `A.HDR`/`B.HDR` os cabeçalhos assinados; sem bootloader (G1.6b: era 32 MiB, não cabiam dois kernels) |
| `rootfs-a` | 256 MiB | squashfs zstd + a árvore do dm-verity logo depois (`rootfs.img`), tipo "Linux root x86-64" do Discoverable Partitions Spec |
| `rootfs-b` | 256 MiB | o slot B, gravado pela primeira atualização |
| `config` | 64 MiB | ext4 vazio, rótulo `config`; vira `/config` |

A linha de comando básica está **dentro do kernel** (`CONFIG_CMDLINE`): `console=tty0
console=ttyS0,115200 root=PARTUUID=<rootfs-a> rootfstype=squashfs ro
init=/usr/sbin/corerouter-init panic=10 quiet`. É a do **caminho de fallback** (o primeiro
boot de uma imagem gravada, ou NVRAM apagada); cada slot boota pela sua entrada `Boot####` da
UEFI, que acrescenta o dm-verity, os parâmetros de Tuning › Boot e `corerouter.slot` (G1.6b). O `cargo xtask os check` confere que o
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
   em seguida dá às portas os nomes do RouterOS (`eth0` → `ether1`…, G1.6m, abaixo);
5. inicia o daemon com ambiente limpo, saída em `/var/log/corerouter-daemon.log` (copiado e
   truncado acima de 8 MiB: um daemon falante nem enche o `/var` nem trava na serial de
   115200 baud), e o reinicia se cair: 0,5 s dobrando até 30 s, zerando depois de 60 s de pé.
   Nunca desiste: roteador sem plano de controle é pior que um tentando de novo. Ao cair, as
   últimas 20 linhas do log vão para a console;
6. colhe todo filho que termina (inclusive órfãos), como todo PID 1 tem de fazer: `wait4(-1)`.
   Até a G1.6m era `waitpid(None)` do rustix, que é `wait4(0)`, só o grupo de processos do
   próprio init; o shell de manutenção (sessão própria) virava zumbi e nunca voltava;
7. avisa quando o daemon responde `ping` em `127.0.0.1:7979` pela primeira vez (`ready:` com o
   tempo desde o início do kernel) e, 10 s depois, a memória em uso (`idle:`);
8. desliga limpo pelos sinais que o busybox `reboot`/`poweroff`/`halt` mandam ao PID 1
   (SIGTERM/SIGUSR2/SIGUSR1) e por Ctrl-Alt-Del (SIGINT): SIGTERM ao daemon, 10 s para salvar,
   SIGKILL, `sync`, desmonta `/config` (ou remonta só de leitura), `reboot(2)`.

**Sem shell por padrão.** `corerouter.shell=ttyS0` na linha de comando abre um `sh` do busybox
naquela console (aberto de novo 1 s depois de sair: `exit`, Ctrl-D), para laboratório e
recuperação. Como a linha de comando está
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
- G1.6k: `os/buildroot-patches/*.patch` (em ordem de nome) é aplicado à árvore extraída. Só
  receitas de `package/` (o `os check` recusa outro caminho), cada versão nova com o hash
  dela no `.hash` do pacote. Um carimbo com o SHA-256 dos patches fica na árvore; patch
  mudou, a árvore é extraída de novo do tarball (nunca um patch por cima de outro). Ao trocar a
  versão de um pacote, faça um build limpo (`rm -rf os/out/build`): o `target/` do Buildroot não
  apaga os arquivos da versão anterior (a `libyang.so.2` ficou no build incremental).
- `BR2_REPRODUCIBLE`: `SOURCE_DATE_EPOCH` fixo, datas e ordem dos arquivos do squashfs fixas.
  GUIDs, volume id do vfat e UUID/hash seed do ext4 fixos no `genimage.cfg`.
- O Rust: `cargo build --release --locked --offline` com o cargo do `rust-toolchain.toml`,
  `--remap-path-prefix` para não gravar caminhos desta máquina, e ligado pelo gcc da toolchain
  do Buildroot contra a glibc da imagem (`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER`,
  `CC_x86_64_unknown_linux_gnu`). Como o alvo tem o mesmo nome do host, os build scripts também
  são ligados por esse gcc: a glibc da toolchain (2.39) não pode ser mais nova que a do host
  (hoje 2.39 nos dois).
- Duas fontes de diferença apareceram na medição e foram corrigidas:
  - **BTF do kernel.** O `pahole -j` do kbuild do 6.18 gera o BTF em paralelo sem a opção
    `reproducible_build`, e a ordem dos tipos dependia do escalonamento das threads.
    `os/patches/linux/0001-kbuild-btf-reproducible-build.patch` liga a opção (pahole ≥ 1.26;
    o do Buildroot é o 1.27).
  - **ext4 do `/config`.** O `mke2fs` e o `e2fsck` que o genimage roda gravavam a hora real no
    superbloco. O `post-image.sh` exporta `E2FSPROGS_FAKE_TIME` e `E2FSCK_TIME` com o
    `SOURCE_DATE_EPOCH`.
- O commit entra no daemon (`corerouter-buildinfo`, mostrado em `server.info`): commits diferentes
  dão binários diferentes, como deve ser. Do mesmo commit, o binário sai igual.

## Desempenho e paralelismo

### Build

- **Por pacote** o Buildroot já usa `-j$(nproc+1)` (`BR2_JLEVEL=0`); o kernel é o pacote mais
  longo e paraleliza bem.
- **Entre pacotes**: `BR2_PER_PACKAGE_DIRECTORIES=y` deixa usar `make -jN` no topo
  (`cargo xtask os build --top-jobs N`), com pacotes independentes compilando ao mesmo tempo.
- **Cache de download**: `os/dl/` fica entre builds; nada é baixado de novo.
- **Cache de compilação**: `BR2_CCACHE` em `os/out/ccache` (C/C++ do Buildroot e do kernel).
  O Rust tem o próprio cache incremental em `os/out/cargo-target`, fora da pasta do pacote
  e do `O=` do Buildroot: nem o `corerouter-dirclean` de cada build nem um build limpo jogam
  fora as dependências (frio, o Rust era 154 s de um build limpo de 447 s, **medido**).

### Boot

- Nada de módulos, udev, scripts ou serviços em série: o init monta, sobe o `lo`, monta
  `/config` e dispara o daemon. O paralelismo do boot é o do kernel (probe assíncrono das
  placas) e o do próprio daemon (threads por serviço, G0.10). Um segundo serviço no init
  não ajudaria: o único trabalho depois do kernel é o daemon ficar pronto.
- `quiet`: o kernel não escreve centenas de linhas na serial de 115200 baud (~11 KB/s) antes
  do init.
- squashfs zstd com `SQUASHFS_COMPILE_DECOMP_MULTI_PERCPU` (descompressão em paralelo, um
  descompressor por CPU) e `SQUASHFS_FILE_DIRECT`.

### Endereço de rede no teste

A imagem sobe sem endereço em nenhuma porta: nada roda DHCP sem configuração. Com `-kernel`, o
boot-test acrescenta à linha de comando o `ip=10.0.2.15::10.0.2.2:255.255.255.0::eth0:off` do
próprio kernel (`CONFIG_IP_PNP`), o endereço da rede de usuário do QEMU. O `eth0` é o nome do
kernel, que vale antes do init: o init renomeia a porta (`ether1`) baixando-a e subindo de novo
(o kernel não renomeia uma porta ativa); o endereço fica, a rota padrão do `ip=` cai. Assim o
encaminhamento de porta chega ao `0.0.0.0:8729` do daemon. Com `--efi` vale a linha de
comando gravada no kernel: o teste confere a prontidão pelo loopback e pula o ping TLS. A
configuração padrão de primeiro boot (cliente DHCP na primeira porta, como o CHR do RouterOS)
é a gap G1.6d. Com ela, o `--efi` também passa a fazer o ping.

## Números

Todos **medidos** em 2026-10-27, AMD Ryzen AI Max+ 395 (32 threads), 62 GiB, NVMe, Linux Mint
22.3, com outras sessões de agente usando a máquina ao mesmo tempo (os tempos variam por isso).

### Build

| Situação | Tempo de parede | Observação |
|---|---|---|
| Primeiro build, tudo frio (downloads de ~360 MB, ccache vazio, sem `-j` de topo) | 15 min 02 s | CPU somada 85 min (paralelismo médio ~5,7×) |
| Build limpo (`os/out/build` apagado), ccache quente, **sem** `-j` de topo | 447 s | Rust frio 154 s (38%), kernel 64 s, ferramentas de host o resto |
| Build limpo, ccache quente, **`--top-jobs 33`** | 207–219 s (3 rodadas) | **2,1×** do paralelismo entre pacotes (`BR2_PER_PACKAGE_DIRECTORIES`) |
| Mudou o fragmento do kernel (`linux-reconfigure`) | 169 s | |
| Sem mudança (quente) | 24–26 s | cargo sem trabalho, rootfs e disco regravados |

Desde a medição do build limpo, o cache do Rust fica em `os/out/cargo-target`, fora do `O=`: um
build limpo do Buildroot não recompila mais o Rust (o build seguinte levou 165 s sem `-j` de
topo, com o cargo frio numa pasta nova).

**Reprodutível:** dois builds limpos do mesmo commit, um terceiro com outro nível de `-j` e um
quarto com o cache do cargo em outra pasta deram o **mesmo** `bzImage` (`40e26533…`), o mesmo
`rootfs.squashfs` (`f8580cbe…`), a mesma ESP e o mesmo daemon. O `disk.img` ficou igual entre
builds depois da correção do ext4.

### Tamanho

| Peça | Tamanho |
|---|---|
| `rootfs.squashfs` (zstd) | **14,4 MiB** (38 MiB descomprimido) |
| └ `corerouter-daemon` (sem símbolos) | 27 MiB |
| └ glibc e bibliotecas (`/lib`, `/usr/lib`) | 9,2 MiB |
| └ busybox / `corerouter-init` / `nft` | 0,7 MiB / 0,5 MiB / 24 KiB (+ libnftables) |
| `bzImage` (com BTF, tudo `=y`) | 19,1 MiB |
| `disk.img` | 609 MiB, quase todo partições vazias (rootfs-b e folga); 33 MiB com `zstd` |

### Boot (QEMU, 2 vCPUs, 1 GiB, virtio)

| Modo | Kernel → daemon responde `ping` | Partida do QEMU → `ready` | Memória ociosa |
|---|---|---|---|
| KVM, `-kernel` (10 rodadas) | 0,69–1,20 s (mediana 0,74 s) | 0,98–1,87 s | 47–58 MiB |
| KVM, UEFI (OVMF → EFI stub, disco inteiro) | 0,73 s | 3,74 s (o firmware leva ~3 s) | 49 MiB |
| TCG (sem KVM) | 2,89 s | 3,78 s | 48 MiB |

Dentro desse tempo: o init leva 7–23 ms (montagens, `lo`, `/config`), e o daemon, 52–126 ms
da partida até o primeiro `pong`. O resto é o kernel até o PID 1 (~0,6 s, probe das placas e
dos discos). O ping TLS do host, pelo encaminhamento de porta do QEMU, respondeu em 14–17 ms.

## A/B e atualização segura (G1.6b)

```sh
corerouter-cli run system.package.check '{"path":"/tmp/x.crpkg"}'     # assinatura e hashes, sem gravar
corerouter-cli run system.package.update '{"path":"/tmp/x.crpkg"}'    # grava o outro slot, reinicia em teste
corerouter-cli run system.package.print                               # slots, teste em curso, último resultado
corerouter-cli run system.package.confirm                             # confirmação manual (confirm=manual)
corerouter-cli run system.package.downgrade                           # boota o slot anterior (mais antigo) em teste
corerouter-cli run system.tuning.boot.apply                           # G1.26h: parâmetros de boot no slot inativo
```

Na GUI: **System › Packages** (slots, teste com prazo, Install and reboot, Downgrade, Check,
Scrub) e **System › Tuning › Boot** (o que cada slot carrega, "Apply on slot X and reboot").

### Como funciona

- **O bootloader é o gerenciador de boot da UEFI.** Cada slot tem um `Boot####` ("CoreRouter A"
  / "CoreRouter B") que aponta para o kernel do slot na ESP; os *options* da entrada são a linha
  de comando (UCS-2), acrescentada à embutida no kernel. `BootOrder` tem o slot confirmado
  primeiro e o outro em segundo.
- **O boot de teste é o `BootNext`.** O firmware boota a entrada uma vez e apaga a variável
  antes (UEFI 2.10 §3.1.2): qualquer falha do teste — pânico do kernel, parâmetro que não boota,
  daemon que nunca responde, queda de energia, alguém desligando a caixa — termina no slot do
  `BootOrder`, o anterior. É um contador de boot de **uma** tentativa, sem bootloader nosso nem
  variável a decrementar (como o Flatcar com `tries=1`). Um firmware que não apaga o
  `BootNext` é detectado: o init apaga e o próximo boot volta (ou, se ele nem bootou o
  `BootNext`, o resultado diz "this box cannot run a trial boot").
- **dm-verity sem initramfs.** A entrada do slot traz `root=/dev/dm-0 dm-mod.waitfor=PARTUUID=…
  dm-mod.create="vroot,,,ro,0 <setores> verity 1 PARTUUID=… PARTUUID=… 4096 4096 <blocos>
  <blocos> sha256 <raiz> <sal>"` (dm-init, `CONFIG_DM_INIT`): o kernel monta a raiz pelo dm-verity
  com o hash raiz do manifesto assinado. Dado e árvore na mesma partição; a árvore é a do
  `veritysetup format --no-superblock` (formato 1, conferido byte a byte num teste quando o host
  tem o `veritysetup`). Um hash raiz errado impede o boot (testado: "metadata block … is
  corrupted", pânico, volta). A verificação é **sob demanda** (cada bloco ao ser lido), não no
  boot.
- **`panic=10` é a última palavra** da linha do slot: nenhum parâmetro do operador desliga o
  reinício depois de um pânico.
- **Confirmação.** `confirm=auto` (padrão): o daemon do slot novo confirma quando está de pé há
  10 s e toda interface que tinha endereço e rodava antes da atualização roda de novo (gerência
  alcançável). `confirm=manual`: um operador confirma pela GUI/CLI/MCP dentro do prazo (como o
  `commit confirmed` do Junos ou o `auto-abort-timer` do IOS-XE). Confirmar = reescrever o
  `BootOrder` com o slot novo primeiro (uma escrita atômica de variável).
- **Prazo.** O `corerouter-init` sabe que é um teste (estado em `/config/package/state.json` +
  slot em uso pela `corerouter.slot=` + `BootOrder`) e reinicia se não houver confirmação em
  `timeout` s (30–3600, padrão 300) contados do início do boot.
- **A configuração volta junto.** Antes de trocar de slot, o `/config` inteiro (com o
  `format_version`) é copiado para `/config/package/config-<slot>/`. No boot de volta depois de
  um teste que falhou, o init restaura a cópia **antes** do daemon ler a config; um downgrade
  boota a cópia que aquele slot rodou por último (se ele lê o formato).
- **O slot em uso nunca é escrito**, e o slot alvo sai do `BootOrder` e perde o cabeçalho
  antes de ser gravado: meio gravado, ele não é volta de ninguém. A ordem dos passos está no
  topo de `crates/sysupdate/src/ab.rs`.
- **Pacote assinado.** `.crpkg` = cabeçalho (magic, manifesto JSON, id da chave, assinatura
  Ed25519) + kernel + rootfs (squashfs + árvore). O cabeçalho vem primeiro: a assinatura é
  conferida antes de gravar um byte; o payload é gravado e hasheado no caminho (SHA-256 de cada
  parte, no manifesto) e o rootfs é relido do disco (sem o cache de páginas) com a árvore
  recalculada. A imagem só leva a **chave pública** (`/etc/corerouter/image-keys/<id>.pub`); a
  privada fica fora do repositório (`cargo xtask os build --key <pkcs8>` ou
  `$COREROUTER_IMAGE_KEY`; sem elas, uma chave de desenvolvimento gerada uma vez em
  `os/out/keys/`, ignorada pelo git). Atualizar para um build mais antigo é recusado
  ("use system.package.downgrade").
- **Parâmetros carregados:** `console=`, `ip=` e `corerouter.shell=` da linha em uso que não
  estão na embutida passam para o slot gravado (como o `linux_append` de OEM do Flatcar): uma
  console serial noutra porta continua depois de atualizar.
- **Fora da imagem** (PC de desenvolvimento com `--backend linux`, navegador) o serviço não
  liga e diz por quê: só roda quando o PID 1 é o `corerouter-init`, para nunca escrever as
  variáveis de boot ou os discos de um host. Com `--backend virtual --config-dir` há um
  **laboratório**: slots em arquivos esparsos, variáveis numa pasta, o reboot do firmware
  simulado (mesmo código do roteador).

### O teste em QEMU (`cargo xtask os ab-test`)

QEMU como usuário, OVMF com NVRAM própria, disco em qcow2 sobre o `disk.img`. O primeiro boot de
cada cenário é o de fábrica (`-kernel` com `ip=` e `corerouter.shell=ttyS0`): o roteador cria as
suas entradas de boot (carregando esses parâmetros). Daí em diante, só o firmware decide. O teste
fala com o daemon pela console serial (`corerouter-init run <comando>`, o cliente do canal de
controle que o shell de manutenção usa) e cada reboot é um QEMU novo (`-no-reboot`).

| Cenário | O que prova |
|---|---|
| `update` | A boota pela entrada com dm-verity; pacote B (mesma imagem, versão e build novos) conferido, gravado; boot de teste de B, confirmação automática, B padrão, A intacto; parâmetro de Tuning na linha de B e não na de A; segundo boot em B sem teste |
| `no-confirm` | B com um daemon que nunca responde (squashfs refeito pelo teste): o init reinicia no prazo (30 s), o firmware boota A, a config volta, `failed` em B |
| `bad-signature` | pacote assinado por uma chave gerada na hora e jogada fora: recusado; pacote da chave certa com um byte do payload trocado: recusado ("signed hashes"); B continua vazio, nenhum teste armado |
| `bad-param` | `system.tuning.boot.apply` com `drill=true` (um `init=` que não existe, depois de `intel_idle.max_cstate=1`): o kernel de B entra em pânico, `panic=10`, o firmware boota A; a linha de A não mudou |

### Pesquisa

Fontes: [MikroTik: Packages](https://help.mikrotik.com/docs/spaces/ROS/pages/40992872/Upgrading+and+installation)
e [upgrade](https://manual.mikrotik.com/docs/getting-started/installation-and-upgrade/upgrade/),
[Junos `request system software add`](https://juniper.net/documentation/en_US/junos13.1/topics/reference/command-summary/request-system-software-add.html)
e [`rollback`](https://juniper.net/documentation/en_US/junos13.2/topics/reference/command-summary/request-system-software-rollback.html),
[IOS-XE install mode](https://www.cisco.com/c/en/us/td/docs/routers/C8000V/Configuration/c8000v-installation-configuration-guide/m_installing-the-software-using-install-commands.html),
[VyOS: update](https://docs.vyos.io/en/latest/installation/update.html) e
[image](https://docs.vyos.io/en/1.5/installation/image.html), [Flatcar: manual rollbacks](https://www.flatcar.org/docs/latest/diagnostics/manual-rollbacks/),
[Talos: upgrading](https://docs.siderolabs.com/talos/v1.11/configure-your-talos-cluster/lifecycle-management/upgrading-talos),
[RAUC reference](https://rauc.readthedocs.io/en/latest/reference.html), [SWUpdate](https://swupdate.org/),
[Mender state scripts](https://github.com/mendersoftware/mender-docs/blob/2.3.x/04.Artifacts/50.State-scripts/docs.md),
[UEFI 2.10 §3 Boot Manager](https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html),
[efivarfs](https://www.kernel.org/doc/html/latest/filesystems/efivarfs.html),
[dm-verity](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html),
[dm-init](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/dm-init.html).

| Sistema | Instalar | Volta automática | O que tiramos |
|---|---|---|---|
| **MikroTik RouterOS v7** | `/system package update` (canais stable/long-term/testing/development; `install` baixa, instala e reinicia); `/system package downgrade` com os `.npk` antigos enviados | Nenhuma: boot ruim = Netinstall | Nomes (`update`, `downgrade`, canal); o `install` que reinicia |
| **Junos** | `request system software add … validate` (valida a config contra a versão nova), raiz dupla nos SRX | `request system software rollback` (manual) | Validar antes de trocar; manter a versão anterior inteira |
| **Cisco IOS-XE** | `install add`/`activate` com `auto-abort-timer` (30–1200 min, padrão 120) e `install commit` | Sem commit no prazo, volta à versão confirmada | Prazo obrigatório de confirmação; manual × automático |
| **VyOS** | `add system image <url>`; cópia da config por imagem; GPG nas LTS | Escolher no GRUB (manual) | Config versionada com a imagem |
| **Flatcar** | `update_engine` grava USR-B; GPT `priority/tries/successful` | GRUB volta se não marcar `successful` (~2 min de pé) | `tries=1`; marca de sucesso depois de um tempo de pé |
| **Talos** | imagem inteira A/B por API | volta ao anterior se não bootar | Só API; imagem inteira |
| **RAUC / SWUpdate / Mender** | bundle assinado (RAUC: verity + CMS; manifesto com hash raiz), streaming por HTTP | contador do bootloader (U-Boot/barebox/GRUB), `mark-good` | Manifesto assinado com o hash raiz; streaming; marcar bom depois do health check |

**Adotado:** imagem inteira A/B, pacote com manifesto assinado (como o bundle verity do RAUC),
gravação em fluxo com hash, contador de uma tentativa (Flatcar), confirmação com prazo
(IOS-XE/Junos), confirmação automática por saúde depois de um tempo de pé (Flatcar, RAUC
`mark-good`), config que volta com a imagem (VyOS), nomes do MikroTik.

**Melhor que os outros (o que o motor permite):** a atualização é um **comando** (journal,
GUI, CLI, MCP); a confirmação automática olha a **gerência** (as interfaces que tinham endereço
voltaram), não só "o processo subiu"; a config volta **sozinha** num teste que falha; o Tuning ›
Boot usa o mesmo caminho (parâmetro que não boota volta sozinho); `drill` testa a volta numa
caixa real (firmware que ignora `BootNext` é detectado); Scrub relê o slot de reserva.

**RAUC × atualizador próprio (decisão do G1.6a revista com números).** O G1.6a pôs a régua:
passou de ~1.500 linhas, reavaliar. **Passou:** `crates/sysupdate` tem 2.230 linhas de código
(sem testes, comentários e linhas em branco; **medido**), das quais ~250 são o laboratório
virtual e ~150 o status para a GUI, que existiriam com o RAUC também. Reavaliado:

- o RAUC tem um backend `efi` (BootOrder/BootNext via `efibootmgr`) e o bundle verity com
  manifesto assinado: substituiria `package`, `verity`, `efi` e metade do `ab` (~1.300 linhas);
- não substituiria: o comando com journal/GUI/MCP, o serviço do daemon, o prazo do teste e a
  decisão de boot no init (o RAUC espera um watchdog ou um `mark-good` externo), a cópia da
  config com o `format_version`, o laboratório;
- traria para a imagem (hoje 15 MiB, sem D-Bus nem OpenSSL) o `rauc` em C com GLib, D-Bus,
  OpenSSL (CMS), `efibootmgr` e `squashfs-tools`: **estimado** +6–8 MiB no squashfs e um
  segundo processo com root no caminho da atualização;
- o nosso grava 34 MiB em 36–53 ms e relê/confere em 12–17 ms (**medido**); o RAUC não seria
  mais rápido nisso (mesmo `sha256`/dm-verity).

Fica o atualizador próprio. Revê-se quando precisarmos de **streaming delta por HTTP** (o índice
de blocos do RAUC é bom nisso): gap G1.6e.

### Desempenho e paralelismo

- **Gravação em fluxo contínuo:** uma thread lê e hasheia (SHA-256 com SHA-NI do `ring`),
  outra grava, com 4 buffers de 1 MiB em voo (fila limitada). Medido no bench
  `package_copy/64MiB_to_file`: **1,30 GiB/s em pipeline × 1,21 GiB/s sequencial** (+8%);
  o gargalo é o disco/cache de páginas, não o hash (2,0 GiB/s num núcleo).
- **Verificação:** a releitura recalcula a árvore do dm-verity. O nível 0 (um hash por bloco de
  4 KiB, quase todo o trabalho) é dividido entre threads por faixas contíguas de blocos de
  hash, cada thread escrevendo a sua parte (sem lock). Medido (`verity_tree`): 16 MiB em
  **7,7 ms** com 1, 4 ou 8 threads (iguais: abaixo de 64 MiB não divide); 256 MiB (um slot
  cheio) **126 ms com 1 thread, 33 ms com 4, 18 ms com 8** (7,1×).
- **Gravar e verificar ao mesmo tempo?** O hash de trânsito já acontece durante a gravação; a
  releitura tem de vir depois do `fsync` e do `fadvise(DONTNEED)` (senão confere o cache, não o
  disco). Com a imagem de hoje a releitura custa 12–17 ms: não vale a complexidade.
- **Lock do `Session`:** os comandos só põem um trabalho na fila (um por vez, "busy" senão); o
  serviço `package` faz a E/S sem o lock e o pega só para entregar progresso (no máximo 10/s) e
  o resultado. O estado lido a cada 2 s custa algumas leituras de arquivos pequenos e duas
  conferências de assinatura.
- **O custo do dm-verity no boot** é sob demanda e ficou abaixo do ruído: o kernel → daemon
  pronto foi 0,72 s sem verity e 0,70–0,73 s com (**medido**).

### Números

**Medidos** em 2026-10-27, AMD Ryzen AI Max+ 395, KVM, 2 vCPUs, 1 GiB, virtio, build de
desenvolvimento do mesmo commit; o host tinha outras sessões rodando.

| O quê | Valor |
|---|---|
| Pacote (`corerouter.crpkg`) | **34,1 MiB** (kernel 19,1 + squashfs 14,9 + árvore verity 124 KiB) |
| Selar a imagem (`corerouter-image seal`: árvore, manifesto, assinatura, pacote) | 59–63 ms |
| `system.package.check` (assinatura + SHA-256 de 34 MiB) | 20–23 ms |
| Gravar o slot B (kernel + rootfs, hash no caminho, `fsync`) | 36–53 ms |
| Reler o slot B e recalcular a árvore | 12–17 ms |
| Cópia da config | 6–7 ms |
| `system.package.update` inteiro | 115–143 ms |
| Kernel → daemon pronto, fallback sem verity / slot A com verity / teste de B | 0,72 s / 0,70 s / 0,72–0,73 s |
| Partida do QEMU (OVMF) → teste de B confirmado | 14,5 s (10 s são a carência de propósito) |
| Teste sem confirmação (prazo 30 s) → reboot | 32,0 s |
| Parâmetro que não boota → reset (`panic=10`) | 11,6 s |
| `cargo xtask os ab-test` (4 cenários, 13 boots) | 94,5 s |
| Build da imagem com A/B (rebuild incremental) | 91–156 s |

### O que ficou de fora e por quê

- **Envio do pacote pela GUI e download pelo canal** (o `install` do MikroTik baixa sozinho):
  o envio pelo canal de controle e o download de um endereço HTTP(S) entraram na G1.6e (seção
  "Pacote pela rede" abaixo); o canal com índice de versões (`check-for-updates`), ainda não.
- **Watchdog de hardware no boot de teste e Secure Boot (UKI assinado):** um kernel que trava
  antes do init (sem pânico) só volta com um reset; a raiz é conferida pelo hash raiz que está
  na NVRAM, e o kernel na ESP não é assinado. Gap G1.6f.
- **Instalador e imagens de VM** criando as entradas de boot na instalação: G1.6c (até lá, o
  primeiro boot de uma imagem gravada sobe sem verity, pelo fallback, e cria as entradas).

## Instalador, imagens de VM e FRR (G1.6c)

```sh
cargo xtask os build          # também grava corerouter-install.iso, corerouter.qcow2 e corerouter.ova
cargo xtask os install-test   # instala de CD e de USB num disco virtual, boota, confere; qcow2 e OVA
```

Saídas em `os/out/build/images/`:

| Arquivo | Para quê |
|---|---|
| `corerouter-install.iso` | ISO híbrida: CD (El Torito UEFI) ou pendrive (`dd`, GPT com a partição EFI). Instala no disco do roteador |
| `corerouter.qcow2` | KVM/Proxmox: o `disk.img` (já A/B) em qcow2 comprimido |
| `corerouter.ova` | VMware/VirtualBox: OVF 1.0 + manifesto SHA-256 + VMDK streamOptimized |
| `corerouter.crpkg` | o pacote de atualização (também dentro da ISO) |

### Como o instalador funciona

- **Um segundo kernel, não um bootloader.** O roteador boota sem bootloader (EFI stub, A/B por
  `BootNext`), e a linha de comando embutida aponta para o `rootfs-a`. A ISO não pode usar essa
  linha: num CD não há PARTUUID, e num disco com CoreRouter instalado o mesmo PARTUUID existiria
  duas vezes. O pacote `os/package/corerouter-installer` compila o **mesmo** kernel (o mesmo
  tarball e hash, o `.config` final da imagem) com `installer.fragment` por cima: outra linha de
  comando (`corerouter.mode=install`, sem `root=`), um initramfs embutido e sem BTF. O
  initramfs é uma lista do `gen_init_cpio` (donos e modos fixos: reprodutível) com o
  `corerouter-init`, as bibliotecas que ele usa e as chaves públicas da imagem. Roda inteiro na
  RAM: o pendrive pode sair depois.
- **A ISO é escrita em Rust** (`crates/sysupdate/src/iso.rs`, `corerouter-image installer`):
  ISO 9660 nível 2, El Torito com a entrada da plataforma EFI (0xEF) e, na área de sistema, MBR
  protetor + GPT com uma partição EFI sobre a **mesma** imagem FAT (`efiboot.vfat`, do genimage).
  Como CD, o firmware usa o El Torito; como disco (pendrive), a GPT. Sem xorriso nem GRUB.
- **A carga** vai como arquivos da ISO: `INSTALL.JSON` (o layout lido do GPT do `disk.img` e o
  SHA-256 de cada arquivo), `INSTALL.SIG` (assinatura Ed25519 do índice, com a mesma chave dos
  pacotes), `COREROUTER.CRPKG` (o pacote: o rootfs vai para o slot A), `ESP.IMG` (a ESP sem os
  blocos zerados do fim) e `CONFIG.IMG` (o ext4 vazio do `/config`, sem o fim zerado). O
  instalador acha a mídia pelo volume id `COREROUTER_INSTALL` e lê os arquivos pelo diretório
  raiz, direto do dispositivo (sem driver de ISO 9660).
- **Gravação** (`crates/sysupdate/src/install.rs`): confere as duas assinaturas e o tamanho do
  disco antes de escrever um byte; zera o primeiro e o último MiB (tabelas, rótulos de RAID/LVM
  antigos); grava ESP, slot A e `/config` em fluxo (uma thread lê e calcula o SHA-256, outra
  grava); `fsync`, descarta o cache e relê tudo em paralelo (ESP e `/config` pelo SHA-256, o slot
  A recalculando a árvore do dm-verity contra o hash raiz assinado); **por último** a GPT
  (primária e reserva), relida. Uma queda antes disso deixa um disco que o firmware não boota,
  nunca um meio gravado que ele boota. O slot B fica para a primeira atualização.
- **Entrada de boot:** `Boot####` "CoreRouter A" com a linha do slot (dm-verity, `corerouter.slot=a`,
  `panic=10`) primeiro no `BootOrder`; uma "CoreRouter B" de instalação anterior sai. O primeiro
  boot já é pelo dm-verity, e o disco instalado boota antes do pendrive que ficou espetado.
- **Nunca grava sem confirmação nem na mídia.** A tabela mostra nome, tamanho, modelo, série,
  barramento e o que o disco tem (vazio, GPT com as partições, CoreRouter). Não são oferecidos: a
  mídia do instalador, drives ópticos, discos só de leitura, menores que a imagem ou com uma
  imagem do instalador. Depois de escolher, o operador **digita o nome do disco**; outra coisa
  volta sem gravar. O que foi digitado antes de cada pergunta é descartado. O alvo é aberto com
  `O_EXCL` (recusado se algo o usa).
- **Manter a configuração:** num disco com CoreRouter cuja partição `config` está no mesmo lugar,
  o instalador pergunta se mantém (como o *keep old configuration* do Netinstall).
- **Consoles:** VGA (`tty1`) e serial (`ttyS0`, 115200) ao mesmo tempo; a resposta vale do
  console onde foi digitada.
- **Endereço de gerência do primeiro boot:** o instalador lista as portas com os nomes que o
  roteador vai dar (`ether1 (link up, 52:54:…)`), pergunta (`ether1 192.0.2.10/24 192.0.2.1`,
  ou vazio; porta que não existe é recusada) e grava `corerouter.mgmt=` na entrada do slot A.
  No primeiro boot o init avisa nos consoles (VGA e serial) o endereço, a porta e de onde veio,
  habilita a porta, aplica `ip.address.add` e a rota padrão pelo canal de controle e grava
  `/config/.installer-mgmt-applied` com fsync: não reaplica depois (nem se a configuração for
  mantida numa reinstalação). Uma entrada com o nome do kernel (`eth0`, instalador antigo) vale
  para a mesma placa renomeada. A atualização não leva o parâmetro para o slot B.
- **Assistente de console** (`corerouter-init setup`, G1.6m): enquanto nenhuma porta tem
  endereço, o console diz que não há terminal de comandos ali e convida a configurar (de novo a
  cada 5 min); lista as portas numeradas com link e MAC, pede a porta pelo número ou nome
  (sem padrão: Enter vazio cancela) e confirma (`Use ether1 (link up, 52:54:…)? [y/N]`), depois
  endereço, gateway e a senha do `admin` (sem ela o login pela rede é recusado), mostra o
  resumo e só aplica com `y`. A pergunta que espera resposta reaparece a cada 30 s (quem
  conecta o console serial depois vê o que está pendente). Com endereço, Enter no console
  mostra os endereços e como conectar pela GUI e pela CLI.
- **Instalação sem interação** só pelo hipervisor: `-fw_cfg
  name=opt/org.corerouter/autoinstall,string=<json>` do QEMU, que nenhuma máquina física tem; o
  JSON nomeia o disco duas vezes (`disk`, `confirm`), e `append` só aceita `console=`, `ip=` e
  `corerouter.shell=`. É a flag do `install-test`.
- **Só UEFI.** Ver a pesquisa abaixo.

### FRR na imagem

- **FRR 10.7.1 e libyang 3.13.6 (G1.6k).** O Buildroot 2025.02.19 traz o FRR 10.3 e a libyang
  2.1.148; OSPF, LDP, Segment Routing, TI-LFA e o BFD distribuído (`bfddp`) foram validados no
  FRR 10.7.1 da VM do laboratório (com a libyang 3.13.6 do deb.frrouting.org), e um core
  OSPF/MPLS em produção roda a versão testada. O `master` do Buildroot já tem FRR 10.7.0 e
  libyang 3.13.6 (commits `34dfa10d` e `c49e140b`, e os anteriores: protobuf opcional, opção de
  ECMP, cabeçalhos em staging): `os/buildroot-patches/0001-package-frr-10.7.1-libyang-3.13.6.patch`
  porta essas receitas para o 2025.02.19 e sobe o FRR para 10.7.1. As opções ficam as mesmas
  (`--enable-multipath=256`, protobuf ligado, `BR2_PACKAGE_FRR_BFD`, sem `vtysh` na imagem).
  - **Hashes:** o tarball é o arquivo da tag `frr-10.7.1` no GitHub (`6aaf9d89…`, o commit
    `f8c0b08d` no cabeçalho pax é o da tag assinada); baixados do mesmo jeito, o 10.7.0 e a
    libyang 3.13.6 dão os hashes do `master` do Buildroot. O Buildroot confere os dois no build
    (`frr-10.7.1.tar.gz: OK`).
  - **Alternativas:** `FRR_OVERRIDE_SRCDIR` (o que a G1.6c previa) tira o pacote da conferência
    de hash do Buildroot e mostra a versão como `custom`; um pacote externo com outro nome
    duplica a receita inteira e o `select` do nftables. O patch é pequeno (145 linhas, só
    `package/frr` e `package/libyang`) e falha alto se a receita mudar num Buildroot novo.
  - **Saída:** quando um LTS do Buildroot trouxer FRR ≥ 10.7.1, apagar o patch.
- **O que o `frr-test` prova** (`cargo xtask os frr-test`, `xtask/src/os/frr.rs`): dois
  roteadores da imagem no QEMU, sem root, com os `ether1` ligados por um par de sockets UDP do
  QEMU no loopback do host. Cada um é configurado só por comandos (13, os mesmos de CLI/MCP):
  endereço e `/32` na `lo`, OSPFv2 ponto a ponto, SR com prefix SID automático (sem TI-LFA,
  desligado em produção pela G3.4l), MPLS e LDP no `ether1`, um peer BFD. E tem de ler de volta
  do FRR: vizinho OSPF `Full` (`ospfd`), o prefix SID do outro com rótulo (`16002`, saída
  implicit-null), LDP `operational` (`ldpd`), sessão BFD `up` (a do `bfdd`, rodada pelo motor
  do daemon como data plane), rótulos na tabela MPLS do kernel (`zebra`), ping entre as
  loopbacks pela rota OSPF e a versão que o `zebra --version` diz igual à do patch.
  - **Achados:** o perfil `bfd` do interface-template OSPF não chega ao `ospfd`
    (`crates/proto-ospf/src/frr.rs`: "BFD: not typed into FRR"): o OSPF não cai pelo BFD,
    só o BGP (gap G3.6l). E o `bfdd` não imprime os valores padrão do perfil (`detect-multiplier 3`,
    `receive-interval 300`, …) que o render manda: o hal-frr os digita de novo a cada sync, nos
    dois FRR (gap G3.6m). Os dois foram corrigidos na G3.9 (`docs/producao-core.md`).
- **O `corerouter-init` inicia os daemons** (`mgmtd`, `zebra`, `staticd`, `bgpd`, `ospfd`,
  `ospf6d`, `ldpd`, `bfdd`), em primeiro plano, com o mesmo backoff de reinício do daemon,
  `-P 0` (sem vty TCP: só os sockets em `/var/run/frr`), log em `/var/log/frr-<daemon>.log` (com o
  mesmo corte de 8 MiB) e `zebra -s 90000000` (buffer de netlink recomendado para tabela cheia).
  Sem `watchfrr`/`frrinit.sh` (bash) nem `frr.conf`: a configuração mora no `/config` e chega
  pelo hal-frr; os daemons sobem vazios e o daemon passa `--frr /var/run/frr`. Eles caem para o
  usuário `frr` com as capacidades que precisam (`libcap`).
- **Fora da imagem** (`post-build.sh`): `vtysh` (o único que liga readline), bash, readline,
  ncurses, o runtime C++ que a toolchain copia, scripts Python e os daemons que o CoreRouter não
  configura (rip, isis, pim, babel, eigrp, …). O `nft` deixa de ter CLI interativa (ela puxava
  readline). Assim a imagem continua **sem GPL-3.0** (bash e readline são GPL-3.0). O `os build`
  confere que todo ELF da imagem acha as bibliotecas que pede (uma remoção a mais falha o build).

### Imagens de VM

- **qcow2**: `qemu-img convert -c` (zlib) do `disk.img`, que já é a imagem instalada A/B. O
  primeiro boot é pelo caminho de mídia removível e cria as entradas de boot (G1.6b).
- **OVA** (`corerouter-image ova`): ustar com o `.ovf` primeiro, o `.mf` (SHA-256) e o disco
  (DSP0243). VMDK streamOptimized pelo `qemu-img`. Máquina: 2 vCPUs, 1 GiB, SATA/AHCI, duas
  e1000, `firmware=efi` (VMware). No VirtualBox, marcar "Enable EFI" depois de importar (o OVF não
  tem como dizer isso ao VirtualBox sem o XML próprio dele).
- **cloud-init: não agora.** O MikroTik CHR não usa cloud-init (sobe com DHCP na primeira porta);
  o VyOS tem. Para o IP inicial, a configuração padrão de primeiro boot do G1.6d (cliente DHCP na
  primeira porta, como o CHR) e o assistente de console resolvem Proxmox/VMware/VirtualBox; o
  datasource NoCloud (o disco `cidata` do Proxmox) vira a gap G1.6h.

### Pesquisa

Fontes: [MikroTik Netinstall](https://help.mikrotik.com/docs/spaces/ROS/pages/24805390/Netinstall)
e [pacote Netinstall v7](https://manual.mikrotik.com/docs/7.25/getting-started/installation-and-upgrade/netinstall/netinstall-package),
[MikroTik CHR](https://help.mikrotik.com/docs/spaces/ROS/pages/18350234/Cloud+Hosted+Router+CHR),
[VyOS: install](https://docs.vyos.io/en/rolling/_sources/installation/install.rst.txt),
[Talos: ISO](https://docs.siderolabs.com/talos/v1.13/platform-specific-installations/bare-metal-platforms/iso),
[OPNsense: instalação (Thomas-Krenn)](https://www.thomas-krenn.com/en/wiki/Install_OPNsense) e
[Dasharo/Protectli](https://docs.dasharo.com/unified/protectli/os-installation-opnsense/),
[AWS: boot UEFI/BIOS](https://aws.amazon.com/about-aws/whats-new/2023/03/amazon-ec2-create-amis-boot-uefi-legacy-bios),
[UEFI 2.10 §5.3 (GPT) e §13.3 (El Torito)](https://uefi.org/specs/UEFI/2.10/),
ECMA-119 (ISO 9660), El Torito 1.0, [DMTF DSP0243 (OVF)](https://www.dmtf.org/standards/ovf),
[FRR: zebra `-s`](https://docs.frrouting.org/en/latest/zebra.html), manual do Buildroot
(`<pkg>_DL_SUBDIR`, `<pkg>-rebuild`).

| Sistema | Como instala | O que tiramos |
|---|---|---|
| **MikroTik Netinstall** | Pela rede (PXE/BOOTP) de um PC; *keep old configuration*; *configure script* que vira a configuração padrão; script de modo de uma vez (7.22+) | Manter a configuração; um ajuste de primeiro boot de uma vez (`corerouter.mgmt=`) |
| **MikroTik CHR** | Imagens prontas (raw, VMDK, VHDX, qcow2/OVA); DHCP na primeira porta; sem cloud-init | Imagens de VM já instaladas; o IP inicial pelo G1.6d |
| **VyOS** | Boota a ISO viva, `install image`: confirmação [y/N], nome da imagem, disco ≥ 2 GB, tamanho da raiz; cloud-init nas imagens de nuvem | Assistente no console; disco mínimo recusado; confirmação |
| **OPNsense/pfSense** | Login `installer` na ISO, escolhe ZFS/UFS, escolhe o disco e **confirma de novo** | Duas etapas: escolher e confirmar |
| **Talos** | ISO metal (BIOS e UEFI no x86; a de Secure Boot só UEFI); o instalador grava a imagem inteira | Imagem inteira e só leitura; o instalador é o próprio sistema |
| **Flatcar** | `flatcar-install -d /dev/sdX` (exige o disco por nome) | Disco por nome, sem padrão |
| **Junos/IOS-XE** | Mídia de instalação/USB de recuperação, `request system snapshot`/`install` | Mídia separada do sistema instalado |

**Adotado:** ISO viva que roda da RAM (VyOS, Talos), disco escolhido e **nome digitado**
(mais forte que o [y/N] do VyOS e a segunda confirmação do OPNsense: digitar o nome não sai
por reflexo), manter a configuração (Netinstall), ajuste de primeiro boot aplicado uma vez
(script de modo do Netinstall), imagens de VM prontas (CHR), assistente de console.

**Melhor que os outros (o que o motor permite):** o instalador confere assinatura (índice e
pacote) antes de escrever e **relê tudo** do disco (o VyOS e o Netinstall não releem); a GPT é
o último passo; o primeiro boot já sobe no dm-verity pela entrada criada; o IP de gerência e o
assistente são **comandos** pelo canal de controle (journal, mesmas validações do CLI/MCP); a
instalação sem interação só existe dentro do hipervisor (fw_cfg), então um pendrive esquecido
num roteador nunca apaga um disco sozinho.

**ISO: genimage × xorriso × Rust.** O tipo `iso` do genimage chama o `genisoimage` (cdrkit)
e não monta a GPT híbrida que o pendrive UEFI precisa. O xorriso está no
Buildroot (`host-xorriso`, 1.5.4, GPL-3.0, download extra) e faz tudo, mas o Buildroot só o
usa com GRUB/isolinux. Escrever a ISO em Rust deu ~540 linhas com testes (o leitor que o
instalador usa vem junto), saída idêntica entre builds, sem download nem ferramenta GPL-3.0 no
build. **Adotado: Rust**; o `file`, o `sfdisk` e o OVMF (CD e USB) aceitam a imagem.

**BIOS legado: não agora.** A imagem instalada só boota por UEFI (EFI stub, A/B por
`BootOrder`/`BootNext`, G1.6b); BIOS exigiria um bootloader (GRUB ou syslinux) e outro esquema
de A/B só para ele. Quem ainda precisa: o Proxmox cria VMs com SeaBIOS por padrão (OVMF é uma
opção na criação), algumas nuvens bootam imagens próprias por BIOS (a AWS só passou a aceitar
imagem que boota nos dois em 2023), e servidores antigos sem UEFI. O Talos ainda faz ISO BIOS +
UEFI no x86. Servidores atuais têm UEFI (e há fornecedores que já desligam o CSM). Fica a gap G1.6g, com o número do custo: um bootloader na
ESP e o A/B por variável dele.

**OVA:** `qemu-img` (VMDK streamOptimized, o único que uma OVA pode levar) + OVF e tar escritos
em Rust (`corerouter-image ova`), datas fixas. O OVA ainda não é reprodutível: o `qemu-img`
põe um `CID` aleatório no descritor do VMDK (achado na G1.6k, gap G1.6l).

### Desempenho e paralelismo

- **Gravação em fluxo:** o instalador usa o `package::copy` do G1.6b: uma thread lê da mídia e
  calcula o SHA-256, outra grava (4 buffers de 1 MiB em voo). Conferir o hash **durante** a
  gravação é o hash da origem em trânsito; a releitura do disco só pode vir depois do `fsync` e
  do descarte do cache (senão confere a RAM, não o disco).
- **Releitura em paralelo:** uma thread por região (ESP, slot A, `/config`), e a árvore do
  dm-verity do slot A em N threads (G1.6b). Medido no bench `install` (ISO em memória → arquivo,
  20 MiB de ESP, 20 MiB de rootfs, 64 MiB de `/config`, 109 MiB gravados; máquina compartilhada,
  ±10%): sequencial e releitura serial **158 ms**; em fluxo e serial **127 ms**; sequencial e
  releitura paralela **109 ms**; em fluxo e paralela **121 ms** (empate com o anterior dentro do
  ruído). Os dois juntos ficam ligados: num disco real, com a mídia mais lenta que o disco (USB 2,
  CD), o fluxo é o que esconde a leitura da mídia.
- **No QEMU** (KVM, virtio, ISO como CD): 104 MiB gravados em 70–130 ms, relidos em 30–38 ms,
  instalação inteira 0,1–0,3 s; do QEMU ligado ao desligado depois de instalar, **2,1–2,5 s**
  (o firmware é ~1,5 s). Reinstalar mantendo a configuração grava 40 MiB em 35 ms.
- **FRR no boot:** os 8 daemons sobem em paralelo com o daemon do CoreRouter (o init não espera
  um pelo outro: o hal-frr reanexa quando os sockets aparecem). Kernel → daemon pronto
  0,75–0,82 s (era 0,69–1,20 s sem FRR), kernel → os 8 sockets vty do FRR 0,77–0,78 s.
- **Memória:** ociosa 93–98 MiB (era 48–58 MiB); RSS do FRR: mgmtd 11,5, zebra 14, staticd 8,
  bgpd 17, ospfd 10,7, ospf6d 10, ldpd 8, bfdd 8,5 MiB (com as bibliotecas compartilhadas
  contadas em cada um). Subir só os daemons configurados é a gap G1.6i.

### Números

**Medidos** em 2026-10-27, AMD Ryzen AI Max+ 395, KVM, 2 vCPUs, 1 GiB, build do mesmo commit, com
outras sessões usando a máquina.

| O quê | Valor |
|---|---|
| `rootfs.squashfs` com FRR | **19,3 MiB** (era 14,4–14,9 MiB: FRR acrescenta ~4,5 MiB comprimidos) |
| `corerouter.crpkg` | 38,5 MiB (era 34,1) |
| Kernel do instalador (com o initramfs) | 18,3 MiB, num FAT de 30 MiB |
| `corerouter-install.iso` | **96,2 MiB** (pacote 38,5 + ESP 19,4 + boot 30 + `/config` 8,2) |
| `corerouter.qcow2` | **38,9 MiB** (disco virtual de 705 MiB) |
| `corerouter.ova` | **38,8 MiB** |
| Montar ISO + índice (`corerouter-image installer`) | 0,35–0,41 s |
| qcow2 / OVA a partir do `disk.img` | 0,5 s / 0,8 s |
| Instalar (gravar + reler + GPT) | 0,1–0,3 s; QEMU ligado → desligado 2,1–3,3 s |
| Boot do disco instalado: kernel → daemon / → FRR | 0,76–0,82 s / 0,77–0,78 s |
| qcow2 e OVA: QEMU ligado → daemon pronto | 2,0–2,1 s |
| `cargo xtask os install-test` (6 boots, 3 instalações) | 33,2 s |
| Rebuild incremental da imagem (com o kernel do instalador) | 32–49 s |

### FRR 10.3 → 10.7.1 (G1.6k)

**Medidos** em 2026-10-28, AMD Ryzen AI Max+ 395, KVM, 2 vCPUs, 1 GiB; builds limpos do mesmo
commit, um com o patch e outro sem, com outras sessões usando a máquina.

| O quê | FRR 10.3 / libyang 2.1.148 | FRR 10.7.1 / libyang 3.13.6 |
|---|---|---|
| `rootfs.squashfs` | 21,4 MiB | **21,7 MiB** (+0,3) |
| FRR + libyang no rootfs, descomprimido | 13,6 MiB | 14,2 MiB |
| `corerouter.crpkg` / ISO / qcow2 / OVA | 40,7 / 98,4 / 41,1 / 40,9 MiB | 41,0 / 98,7 / 41,4 / 41,2 MiB |
| RSS dos 8 daemons com OSPF+SR+LDP no ar (`frr-test`) | 85,7 MiB | **88,5 MiB** (+2,8; bgpd +0,9, zebra +0,5, mgmtd +0,5) |
| `MemAvailable` nesse ponto (de 949 MiB) | 836,6 MiB | 834,7 MiB |
| Kernel → os 8 sockets vty / → daemon pronto | 0,76 / 0,81 s | 0,75 / 0,80 s |
| Vizinho OSPF `Full` / LDP `operational` depois da config | 1,9 / 11,9 s | 1,5 / 11,5 s (o `ldpd` espera 10 s fixos, RFC 5443) |
| BFD `up` (peer explícito, 300 ms × 3) | não medido | já `up` na primeira leitura, depois do LDP |
| `frr-test` inteiro | — | 25 s |
| Build limpo da imagem, ccache e cargo quentes | — | 164 s (`--top-jobs 17`), 427 s sem `-j` de topo |

**Reprodutível:** dois builds limpos com o patch (um com `--top-jobs 17`, outro sem `-j` de
topo) deram o mesmo `bzImage`, `rootfs.squashfs`, `disk.img`, pacote e imagens de VM, e o mesmo
`target/` arquivo por arquivo. Só o **OVA** saiu diferente, e não pelo FRR: o `qemu-img`
(8.2) grava um `CID` aleatório no descritor do VMDK a cada conversão (dois `convert` do mesmo
`disk.img` diferem no byte 549). Gap G1.6l.

### O que ficou de fora e por quê

- **BIOS legado:** gap G1.6g (acima).
- **cloud-init (NoCloud/`cidata`):** gap G1.6h; o IP inicial pelo G1.6d e pelo assistente.
- **Só os daemons do FRR configurados** (hoje sobem os 8, ~88 MiB de RSS somado): gap G1.6i.
- **`/config` do tamanho do resto do disco:** o layout é o do `disk.img` (64 MiB); crescer a
  partição e o ext4 na instalação fica para quando o `/config` precisar (logs persistentes).
- **Dois discos CoreRouter na mesma caixa:** os PARTUUIDs são fixos (a linha de comando embutida
  do fallback aponta para o `rootfs-a`); o instalador recusa um disco com a imagem do
  instalador, mas não um segundo CoreRouter. Anotado como risco.
- **`linux-firmware` (pacote DDP da `ice`)**: não entrou; a `ice` segue em modo seguro (G1.6a).
  Gap G1.6j.
- **Senha do `admin` no instalador:** não vai na linha de comando (fica na NVRAM); o assistente
  de console do primeiro boot a pede.

## Primeiro boot de verdade: nomes de porta, console e shell (G1.6m)

Achados de uma instalação do `corerouter.qcow2` numa VM libvirt (UEFI, 3 placas virtio), em
2026-10-28, e o que mudou.

### Nomes de porta: `ether1…` desde o boot

O kernel chama as portas `eth0`, `eth1`… na ordem de probe; a GUI, os documentos e o operador
de MikroTik usam `ether1`, `ether2`…. O init renomeia antes do daemon subir
(`apps/corerouter-init/src/ports.rs` decide, `links.rs` faz o `RTM_NEWLINK` com `IFLA_IFNAME`):

- **Ordem do barramento, não do probe:** caminho PCI do dispositivo, depois `dev_port` (placa
  com várias portas numa função), depois o MAC. O probe em paralelo muda a ordem entre boots
  (relatos do RouterOS em VM e o T9127 do VyOS com a `ice`). O init espera a lista de links
  ficar parada por 100 ms (no máximo 2 s) antes de numerar.
- **O nome segue a placa** (`/config/.port-names`: nome, MAC, caminho), como o `hw-id` do VyOS:
  placa nova ganha o próximo número livre e não desloca as outras.
- **Placa trocada no mesmo slot** (MAC sumiu, MAC novo no mesmo caminho PCI) fica com o nome da
  antiga, como o slot/porta do Junos: a configuração daquela porta continua valendo. O nome de
  uma placa que sumiu fica reservado (a configuração aponta para ele); apagar o arquivo
  renumera tudo a partir de `ether1` no boot seguinte.
- **Configuração de antes (G1.6c) sem o mapa:** os nomes do kernel ficam (`eth0` na
  configuração continua existindo) e o mapa os registra; placa nova depois disso vira `etherN`.
  Renomear quebraria a gerência (lockout).
- **`corerouter.mgmt=eth0,…`** (instalador antigo, NVRAM antiga) vale para a placa que o kernel
  chamou de `eth0` neste boot, já renomeada: a tradução é pelo dispositivo, não pelo número.
- **Porta ativa** (o `ip=` do kernel nos testes): o kernel não renomeia porta ativa; o init a
  baixa, renomeia e sobe; o endereço IPv4 fica e as rotas por ela caem.
- O daemon não muda: porta física é gerenciada pela regra 6 do `owner.rs` qualquer que seja o
  nome; `--manage` não é usado na imagem.

### Interfaces que o kernel criava sozinho

Com os drivers `=y`, cada um criava a sua no namespace inicial durante os initcalls: `bond0`,
`dummy0`, e as "fallback" dos túneis `gre0`, `gretap0`, `erspan0`, `ip6gre0`, `ip6tnl0`,
`sit0`, `tunl0`. Apareciam em Interfaces como "not managed".

- `bonding.max_bonds=0 dummy.numdummies=0` na linha de comando embutida (e no
  `BUILTIN_CMDLINE` do `corerouter-sysupdate`, que o `os check` confere): bonds e loopbacks o
  hal-linux cria por netlink.
- Os túneis: o `sysctl.net.core.fb_tunnels_only_for_init_net=2` da linha de comando chega tarde
  (o kernel aplica `sysctl.*` em `do_sysctl_args()`, depois dos initcalls; conferido no
  `init/main.c` do 6.18). `os/patches/linux/0002-net-no-fallback-tunnel-devices.patch` muda o
  padrão do sysctl para 2 (uma linha). Nada no CoreRouter usa as fallback (o hal-frr e o
  hal-linux criam o que usam); sem elas, GRE/IPIP sem túnel configurado é descartado, o que é
  o comportamento seguro.
- O `cargo xtask os build` reaplica os patches do kernel quando mudam (`linux-dirclean`; antes
  só o fragmento era acompanhado).

### Shell de manutenção que parava

Reproduzido sem root (QEMU com duas seriais em pty e uma VM libvirt de sessão com
`virsh console --force`): reconectar o console não quebra nada; **sair do shell** (`exit`,
Ctrl-D) sim. O init colhia filhos com `waitpid(None, NOHANG)` do rustix 1.x, que é `wait4(0)`:
só o grupo de processos do PID 1. O shell (`setsid -c`, sessão e grupo próprios) virava zumbi,
o init nunca via a saída e não abria outro; o eco que aparecia era o da disciplina de linha do
`ttyS0` (aberto pelo `/dev/console`), sem ninguém lendo. O mesmo deixava zumbis de qualquer
órfão com grupo próprio. Agora é `wait4(-1)` (`rustix::process::wait`); o `install-test` dá
`exit` no shell, espera o novo e confere que não há zumbi.

### `corerouter.mgmt=` herdado de outra VM

Uma VM nova com o nome de uma antiga herdou a NVRAM (`/var/lib/libvirt/qemu/nvram/<nome>_VARS.fd`
não é apagado com `virsh undefine` sem `--nvram`) e a entrada "CoreRouter A" com
`corerouter.mgmt=`. Os PARTUUIDs da imagem são fixos, então a entrada antiga boota o disco
novo e o endereço foi aplicado; por isso o assistente não apareceu. O marcador não aparecer é
compatível com a VM desligada à força logo depois: o daemon faz fsync da configuração e o
marcador era um `write` simples (o ext4 grava em até 5 s). Agora o marcador é gravado com
fsync do arquivo e do diretório, e o init diz nos consoles qual endereço, em que porta, que
veio da entrada de boot, e como sair disso (`virsh start --reset-nvram`; no Proxmox, um EFI
disk novo). Porta que não existe: o endereço não é aplicado e o assistente pergunta.

### Pesquisa

- **MikroTik RouterOS v7:** portas `etherN` com `default-name` fixo por porta de hardware; no
  x86/CHR a numeração segue a detecção, e há relatos de nomes trocados entre boots em VM e de
  `default-name` duplicado no CHR ([fórum: CHR x86 random names](https://forum.mikrotik.com/t/chr-x86-ethernet-interfaces-random-names/115361),
  [NIC order issues](https://forum.mikrotik.com/t/routeros-6-40-4-nic-order-issues/112975),
  [duplicate default-name](https://forum.mikrotik.com/t/chr-duplicate-default-name-on-interfaces/130582));
  numa máquina física, o nome só muda se a placa mudar de slot PCI
  ([fórum](https://forum.mikrotik.com/t/how-are-hardware-ports-associated-with-names/125582)).
  O console do CHR abre o login (sem senha na primeira vez) e um terminal completo.
- **VyOS:** `ethN` com `hw-id` (o MAC permanente) gravado na configuração; o renomeio é por
  udev (`vyos_net_name`), com corrida conhecida com placas lentas
  ([docs](https://docs.vyos.io/en/1.5/troubleshooting/interfaces.html),
  [T9127](https://vyos.dev/T9127), [T9141](https://vyos.dev/T9141)).
- **OPNsense/pfSense:** nomes do driver (`vtnet0`, `igb1`); o menu do console atribui WAN/LAN
  e pergunta antes de aplicar ([docs](https://docs.opnsense.org/manual/how-tos/vlan_and_lagg.html)).
- **Junos:** nome pela posição física (`ge-0/0/1`): placa trocada no mesmo lugar herda a
  configuração.
- **Adotado:** nomes do RouterOS, ordem do barramento (melhor que a detecção), o nome preso ao
  MAC (VyOS) e ao slot quando a placa é trocada (Junos); no console, a confirmação explícita
  e o resumo antes de aplicar (OPNsense).
- **Extras que entraram:** a pergunta pendente reaparece (console serial conectado depois); Enter
  num console com endereço mostra o status; o aviso do `corerouter.mgmt=` com a origem; o
  instalador recusa porta inexistente.
- **Ficou de fora:** renomear placa que aparece depois do boot (hot-plug; hoje fica `ethN` até
  o próximo boot); escolher o nome no console; o cliente DHCP de fábrica (G1.6d).

### Desempenho e paralelismo

Tudo roda uma vez no boot, fora de caminho quente. O renomeio é uma mensagem netlink por porta
(três com a porta ativa), O(n) no número de portas; a decisão (`assign`) é O(n·m) com n, m ≤
1024, irrelevante. A única espera é a de a lista de links parar de mudar (100 ms de silêncio,
2 s no máximo): é o que evita numerar antes de um driver lento terminar. Não há o que dividir
entre núcleos. O assistente e o aviso rodam em processo e thread próprios, sem lock com o
laço do PID 1.

### Números (G1.6m)

**Medido** em 2026-10-28, KVM no host de desenvolvimento, build release da imagem:

- kernel → daemon responde `ping`: 0,90–0,91 s em três `boot-test` (0,92 s na imagem da
  `main` antes); com a espera de 300 ms de silêncio dos links eram 1,10 s, por isso 100 ms;
- `early boot done`: 110–112 ms (14 ms antes; a diferença é a espera dos links);
- `install-test` completo: 40,8 s; `/sys/class/net` com 3 placas: `ether1 ether2 ether3 lo`
  (antes: mais `bond0`, `dummy0` e sete túneis de fallback);
- build da imagem do zero numa worktree (toolchain externa e downloads em cache): 1064 s; um
  build incremental só do init: 56 s.

## Pacote pela rede e ciclo rápido de teste (G1.6e)

Até a G1.6b o `.crpkg` tinha de estar no disco do roteador (um arquivo em `/tmp`, um pendrive).
Agora ele vai pelo **canal de controle** (TLS, ou o canal local de uma GUI com `--control`), em
blocos, e é gravado no slot inativo **enquanto chega**.

```sh
# Do PC de desenvolvimento, numa VM que já roda a imagem (sem recriá-la):
cargo xtask os push --to 127.0.0.1:7990                     # o canal local da GUI que gerencia a VM (token local)
cargo xtask os push --to 192.0.2.10:8729 --user admin       # direto no roteador, TLS ($COREROUTER_PASSWORD ou prompt)
cargo xtask os push --to … --no-build --confirm manual      # pacote já construído; confirmação manual

# Qualquer pacote, de qualquer máquina:
corerouter-cli --connect tls://192.0.2.10:8729 --user admin upload corerouter.crpkg --wait
corerouter-cli --connect … upload corerouter.crpkg '{"check":true}'    # só confere, não grava
```

Na GUI: **System › Packages › From this computer** (digite o caminho ou solte o `.crpkg` na
janela), **Upload and check** ou **Upload and install…**, barra de progresso e **Abort**.

### O ciclo rápido

`os push` faz, e cronometra, cada etapa:

1. `cargo xtask os build --only crpkg`: o build de sempre até o `corerouter-image seal` (rootfs,
   árvore do dm-verity, manifesto assinado, `corerouter.crpkg`) e para: sem o `disk.img` (o
   genimage), sem a ISO do instalador e o kernel dele, sem o qcow2 e o OVA;
2. `corerouter-cli upload --wait`: envia, espera gravar e reler, espera o roteador voltar do
   reboot **no slot novo** e o boot de teste se confirmar (ou voltar ao anterior: aí falha e
   diz por quê).

A VM não é recriada: `/config` (com a senha do `admin` e o certificado TLS) fica, o
`known_hosts` do PC continua valendo e a GUI reconecta sozinha. A versão (`build`) é a hora do
commit: dois builds do mesmo commit (mudanças ainda não commitadas) têm o mesmo `build`, e
atualizar para o mesmo `build` é permitido.

### Como funciona

- **Comandos** (`crates/engine/src/cmd/package.rs`): `system.package.upload.start {size, check?,
  downgrade?, confirm?, timeout?, reboot?}` põe um trabalho na fila (as mesmas regras do
  `update`: um por vez, nenhum boot de teste pendente, só na imagem A/B) e devolve o id do envio;
  `system.package.upload.chunk {upload, offset, data}` leva cada bloco em base64 (até 4 MiB
  decodificados; o cliente manda 1 MiB) **em ordem** (`offset` tem de ser o que já chegou);
  `system.package.upload.abort` interrompe. O bloco não entra no journal (seria 1 MiB por
  linha) mas pede o grupo `write`, como o `update`.
- **Fila limitada, sem esperar sob o lock.** O engine entrega cada bloco a uma fila de 8 blocos
  (`sync_channel`): no máximo ~8 MiB do pacote em RAM. Fila cheia (o disco atrasou) responde
  `busy: true` e o cliente manda o mesmo bloco de novo; nada bloqueia com o lock do `Session`.
- **O serviço `package` lê a fila como um fluxo** (`crates/sysupdate/src/upload.rs`,
  `ChunkReader`) e chama a mesma instalação de um arquivo (`Platform::install_from`): lê o
  cabeçalho, **confere a assinatura antes de gravar um byte** e o tamanho declarado contra o do
  manifesto, grava kernel e rootfs no slot inativo com o SHA-256 no caminho (uma thread lê e
  hasheia, outra grava), relê o slot sem o cache de páginas e recalcula a árvore do dm-verity, e
  só então grava o cabeçalho, a entrada de boot e o `BootNext`. Daí em diante é o boot de teste da
  G1.6b: confirmação automática ou manual, volta sozinho se não confirmar.
- **Interrupção.** `abort`, a conexão que cai (60 s sem bloco: o envio é abandonado) ou um pacote
  adulterado (hash do payload diferente) terminam o trabalho com erro; o slot inativo fica sem
  cabeçalho (não é volta de ninguém) e o slot em uso continua o padrão. Testado no laboratório
  virtual (`apps/corerouter-daemon/tests/package_upload.rs`), no `sysupdate`
  (`streamed_install_and_its_failures`) e no QEMU (`ab-test --scenario push`).
- **O resultado antes do reboot.** O serviço espera 2 s entre o resultado e o reboot, para quem
  enviou (CLI, GUI) ler o resultado antes de a conexão cair; se cair antes, o `--wait` segue
  pelo estado depois do reboot.

### Download pelo próprio roteador

```sh
corerouter-cli … run system.package.download '{"url":"https://updates.example/corerouter.crpkg"}'
corerouter-cli … run system.package.download '{"url":"http://192.0.2.5:8000/corerouter.crpkg","check":true}'
```

Como o `/system package update install` do RouterOS, mas de um endereço que o operador dá: o
serviço `package` baixa numa thread própria (`pkg-download`) com o cliente HTTP do daemon
(`service/https.rs`: resolvedor do roteador, certificado conferido pelas raízes da Mozilla
embutidas, `ssl_verify=false` como o `ssl-verify=no`, redirecionamento para dentro da LAN
recusado), e o corpo vai em pedaços de 256 KiB pela **mesma** fila limitada do envio até a
mesma instalação em fluxo. `http://` é aceito: o pacote é assinado, o TLS só esconde o que se
baixa. Na GUI, um endereço no campo **Package file** faz o Check e o Install and reboot baixarem.
Erros do servidor (404, conexão cortada) aparecem no resultado do trabalho; nada é gravado no
slot antes de a assinatura conferir.

Fica para depois: o **canal** (um índice por canal — stable, testing… — com a última versão,
como o `check-for-updates` do RouterOS) e o **delta por blocos** (o índice do RAUC): hoje cada
atualização baixa o pacote inteiro (41 MiB).

### O teste em QEMU (`cargo xtask os ab-test --scenario push`)

A imagem A recebe senha do `admin` e um nome (`system.identity.set`); o teste lê a impressão
digital do certificado no log do daemon e roda `corerouter-cli --connect tls://… --user admin
--fingerprint … upload b.crpkg --wait` pela rede de usuário do QEMU (encaminhamento de porta para
o 8729). O roteador grava o slot B, reinicia (cada reboot é um QEMU novo com a mesma NVRAM), o
boot de teste de B se confirma, e o CLI — que fez login de novo **com a mesma senha** e
**exigindo o mesmo certificado** — vê B confirmado. O nome continua (o `/config` ficou). Depois um
pacote cujo daemon nunca responde vai pelo mesmo caminho (`timeout` 30 s): o init reinicia no
prazo, o firmware boota B, a configuração volta, e o CLI sai com erro dizendo que o slot não
ficou.

### Pesquisa

Fontes: [MikroTik: Packages](https://help.mikrotik.com/docs/spaces/ROS/pages/40992872/Packages) e
[Upgrading and installation](https://help.mikrotik.com/docs/spaces/ROS/pages/328142/Upgrading+and+installation),
[VyOS: update](https://docs.vyos.io/en/latest/installation/update.html),
[Junos `request system software add`](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/request-system-software-add.html),
[IOS-XE install mode](https://www.cisco.com/c/en/us/td/docs/routers/C8000V/Configuration/c8000v-installation-configuration-guide/m_installing-the-software-using-install-commands.html),
[RAUC: HTTP streaming](https://rauc.readthedocs.io/en/latest/advanced.html#http-streaming),
[SWUpdate: streaming](https://sbabic.github.io/swupdate/swupdate.html),
[Mender: artifact streaming](https://docs.mender.io/overview/artifact).

| Sistema | Como o pacote chega | Grava enquanto chega? |
|---|---|---|
| **MikroTik RouterOS v7** | Arrastar o `.npk` para Files (WinBox/WebFig, FTP, SFTP) e reiniciar; ou `/system package update` baixa do canal | Não: o `.npk` fica inteiro no armazenamento e é instalado no reboot |
| **VyOS** | `add system image <url>` (HTTP/HTTPS/SCP/arquivo) | Não: baixa a ISO inteira, depois copia o squashfs |
| **Junos** | `request system software add <url>` (FTP/SCP/HTTP) ou um arquivo em `/var/tmp` | Não: o pacote vai para `/var/tmp` primeiro |
| **IOS-XE** | `copy` para a flash, depois `install add file` | Não: o pacote fica na flash |
| **RAUC / SWUpdate / Mender** | bundle por HTTP, servidor de atualização ou API local | **Sim**: RAUC (bundle verity por HTTP range), SWUpdate e Mender gravam o stream direto na partição inativa |

**Adotado:** o pacote vai pelo mesmo canal autenticado da GUI/CLI/MCP (sem abrir FTP/SFTP nem
outra porta), em blocos que vão direto ao slot inativo como no RAUC/SWUpdate/Mender (o roteador não
precisa de espaço para guardar o pacote — o `/config` tem 64 MiB e o pacote 34–41 MiB), com
a assinatura conferida antes do primeiro byte. Os nomes seguem o MikroTik (Packages, check,
install/reboot).

**Melhor que os outros:** a atualização continua um **comando** (journal, permissão de grupo,
MCP); um envio interrompido não deixa lixo no disco nem muda a caixa; e o `os push` fecha o
ciclo de teste (build → envio → boot de teste → confirmação) num comando, medindo cada etapa.

### Desempenho e paralelismo

- **Por bloco**, com o lock do `Session`: conferir os parâmetros, decodificar o base64 e pôr na
  fila. **Medido** (`cargo bench -p corerouter-engine --bench package_upload`): 587 µs por bloco
  de 1 MiB (1,66 GiB/s, com o build da imagem rodando ao lado), uma vez por MiB enviado. O parse da linha JSON acontece antes, na thread da conexão.
- **Gravação:** a mesma da G1.6b — uma thread lê do fluxo e hasheia, outra grava (4 buffers de
  1 MiB); a releitura com a árvore do dm-verity usa até 8 threads. O envio pela rede e a
  gravação andam em paralelo (a fila de 8 blocos é o colchão): o tempo total é o do mais lento.
- **Um bloco em voo por vez** (pedido e resposta): na rede local isso não é o gargalo
  (abaixo); numa WAN de alta latência valeria mandar vários antes da resposta. Fica como ideia,
  sem gap, até alguém atualizar por uma WAN lenta.
- **Não paraleliza mais:** a ordem dos bytes é obrigatória (hash em fluxo, slot gravado em
  sequência) e um envio por vez é regra da atualização.

### Números

**Medidos** em 2026-10-28, AMD Ryzen AI Max+ 395 (32 threads), build release, com outras sessões
usando a máquina.

| O quê | Valor |
|---|---|
| Pacote de hoje | 41,0 MiB (kernel 19,1 + rootfs 21,9) |
| Envio no laboratório virtual (canal local, TCP em loopback) | 41,0 MiB em 0,27 s (152 MiB/s); gravado e conferido 0,88 s depois do início |
| Envio pela GUI (debug, sem GPU, Xvfb) para o laboratório | 41,0 MiB em ~4,7 s (um bloco por quadro da janela) |
| Envio por TLS para o QEMU (KVM, rede de usuário, CLI release) | 41,0 MiB em 2,16 s (19 MiB/s; o gargalo é a rede de usuário do QEMU); gravado e relido 3,17 s depois do início |
| `ab-test --scenario push`: envio → B confirmado (relógio do CLI) | 25,6 s (10 s são a carência da confirmação automática) |
| `os build` incremental (só o daemon mudou), completo | 184 s (`make all` 150 s) |
| `os build --only crpkg`, mesma mudança | 127 s (`make all` 110 s, dos quais 100 s são o cargo release do daemon com LTO); −57 s, −31% |
| `os push` inteiro (build `--only crpkg` + envio + reboot + confirmação) | ~153 s (**estimado**: soma das duas linhas medidas acima) |
| Build frio da imagem numa worktree nova (downloads em cache) | 1207 s |

O que sobra do ciclo é o cargo release do daemon; um perfil de build sem LTO para o ciclo de
teste encurtaria isso, mas o binário testado deixaria de ser o de produção: não entrou.
