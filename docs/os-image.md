# Imagem do sistema (G1.6a, G1.6b)

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
cargo xtask os package --out b.crpkg --version 0.1.1 --build 1800000000  # outro pacote deste build
```

A/B e atualização: seção "A/B e atualização segura (G1.6b)" abaixo. Parte seguinte: G1.6c
(instalador ISO/USB, qcow2/OVA, FRR e firmware na imagem).

## O que entra na imagem

| Parte | O quê | Onde |
|---|---|---|
| Buildroot | 2025.02.19, ramo **LTS** (correções de segurança até março de 2028); tarball conferido pelo SHA-256 do `.sign` assinado | `os/buildroot.lock` |
| Toolchain | Bootlin x86-64 glibc stable 2024.05-1 (gcc 13.3, glibc 2.39), pronta e com hash no Buildroot | `os/configs/corerouter_x86_64_defconfig` |
| Kernel | Linux **6.18.59** LTS (suporte projetado até dez/2028), `x86_64_defconfig` + fragmento; SHA-256 do `sha256sums.asc` assinado do kernel.org, conferido pelo Buildroot e de novo pelo xtask | `os/board/x86_64/linux.fragment`, `os/patches/linux/linux.hash` |
| Init | `corerouter-init` (Rust, este workspace) | `apps/corerouter-init` |
| Roteador | `corerouter-daemon --backend linux --config-dir /config --control 7979 --listen 0.0.0.0:8729` | `os/package/corerouter` |
| Espaço de usuário | `nft` sem JSON (só diagnóstico no shell de manutenção: o hal-linux fala nfnetlink, G2.8), glibc, busybox (só para o shell de manutenção) | defconfig |

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
próprio kernel (`CONFIG_IP_PNP`), o endereço da rede de usuário do QEMU. Assim o
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
  hoje o pacote tem de estar no roteador (arquivo ou dispositivo de bloco). Gap G1.6e, com o
  streaming direto para o slot (sem cópia em RAM).
- **Watchdog de hardware no boot de teste e Secure Boot (UKI assinado):** um kernel que trava
  antes do init (sem pânico) só volta com um reset; a raiz é conferida pelo hash raiz que está
  na NVRAM, e o kernel na ESP não é assinado. Gap G1.6f.
- **Instalador e imagens de VM** criando as entradas de boot na instalação: G1.6c (até lá, o
  primeiro boot de uma imagem gravada sobe sem verity, pelo fallback, e cria as entradas).
