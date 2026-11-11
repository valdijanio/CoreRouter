# Teste em máquina real (G1.6jb)

Roteiro do operador para levar a imagem a uma máquina física: gerar a ISO de instalação, gravar
no pendrive, bootar, colher o que a G1.6jb pede e instalar no disco. A referência técnica de
cada passo está em `docs/os-image.md`.

**Antes de começar:**

- A instalação **apaga o disco escolhido**. Use uma máquina sem dados que importem.
- O teste roda tudo em QEMU antes, sem root. Só gravar o pendrive pede `sudo`, no seu terminal.
- Se uma porta da máquina for para a sua rede de casa, ela fica só como **cliente**: nada de
  servidor DHCP, RA ou anúncio de rota nessa porta.
- **Secure Boot desligado** no firmware. O kernel não é assinado para ele ainda (G1.6f).

## 1. Gerar a ISO (no computador de desenvolvimento, sem root)

Num checkout da `main` atualizada (`git pull`):

```sh
cargo xtask os build                              # ~10–40 min; grava a ISO, o disk.img, o qcow2 e o OVA
cargo xtask os install-test                       # instala de CD e de pendrive no QEMU (UEFI)
cargo xtask os install-test --firmware seabios    # o mesmo por BIOS
cargo xtask os ab-test                            # atualização A/B (UEFI)
cargo xtask os ab-test --firmware seabios         # atualização A/B (BIOS)
```

Só leve ao pendrive uma ISO que passou nos quatro testes. Ela fica em:

```sh
echo "$(cargo xtask os out-dir)/build/images/corerouter-install.iso"
sha256sum "$(cargo xtask os out-dir)/build/images/corerouter-install.iso"   # anote o hash
```

Para usar outra pasta de saída (por exemplo, uma por teste), defina antes
`COREROUTER_OS_OUT=/srv/build/os-out/<nome>`. **Guarde essa pasta:** ela tem a chave que assinou
a imagem, e a atualização pela rede (passo 6) só aceita pacotes da mesma chave.

Se o download do Buildroot ou de alguma ferramenta falhar com erro 503 do GitHub, rode o `build`
de novo: ele continua de onde parou.

## 2. Gravar no pendrive (root: no seu terminal)

A ISO é híbrida: serve como CD e como pendrive gravado com `dd`. Gravá-la com Ventoy ou Rufus
em modo ISO não foi testado.

```sh
lsblk -o NAME,SIZE,MODEL,TRAN,MOUNTPOINTS        # ache o pendrive pelo tamanho, modelo e TRAN=usb
sudo umount /dev/sdX?* 2>/dev/null               # troque sdX pelo pendrive
sudo dd if=<caminho da ISO> of=/dev/sdX bs=4M conv=fsync oflag=direct status=progress
sync
```

Confira duas vezes o `/dev/sdX`: o `dd` apaga o disco que receber, sem perguntar.

## 3. Bootar a máquina pelo pendrive

- O firmware pode ser UEFI ou BIOS (legacy/CSM); os dois funcionam. Escolha o pendrive no menu de
  boot (F12, F11, Esc ou F8, conforme o fabricante).
- Ligue um cabo de rede a uma porta que tenha DHCP.
- **Console:** a tela (VGA) e a serial (`ttyS0`, 115200 8N1) ao mesmo tempo. Se a placa-mãe tem
  serial, ligue-a também: ela mostra o boot inteiro e serve quando a tela não aparece.
- A ISO sobe o **live**, que roda inteiro na RAM. Ele põe cliente DHCP em todas as portas e
  mostra no console os endereços que pegou.

## 4. Colher o resultado do hardware (o que a G1.6jb pede)

Do computador de desenvolvimento, com o endereço que o console mostrou. No live, o `admin` entra
sem senha; aceite o certificado novo na primeira conexão.

```sh
corerouter-gui --connect tls://<IP>:8729                   # GUI (pede o usuário: admin)
R="corerouter-cli --connect tls://<IP>:8729 --user admin"
$R run interface.hardware-problem.print  > hw-problemas.json   # placa sem driver, firmware faltando, ice em Safe Mode
$R run interface.list                    > hw-interfaces.json
$R run system.install.test                                     # teste de rede por porta: driver, link, velocidade, DHCP, gateway, DNS
$R run system.install.print              > hw-instalacao.json  # discos vistos e o resultado do teste
$R run log.os.print                      > hw-log-os.json      # mensagens do kernel (drivers, firmware)
```

Para cada placa, anote o modelo, o driver, a velocidade do link, se pegou DHCP e se apareceu
algum problema. As placas que a G1.6jb pede em `docs/os-image.md` são:

- **Intel E810:** veja se o DDP carregou, quantas filas, o XDP e o tempo da sonda;
- **Mellanox ConnectX-3:** a porta pelo barramento `auxiliary`;
- **Broadcom BCM57xxx:** o driver `bnxt_en`;
- **USB RTL8153:** um adaptador plugado no boot.

O que passar muda de "deve funcionar" para "testada" na tabela dessa doc.

## 5. Instalar no disco

Escolha um dos caminhos:

- **No console do live:** o instalador lista os discos (nome, tamanho, modelo, série e conteúdo).
  Você **digita o nome do disco** para confirmar. Depois ele pergunta o endereço de gerência do
  primeiro boot, por exemplo `ether1 192.0.2.10/24 192.0.2.1`, ou vazio.
- **Pela GUI ou pela CLI:** `system.install.print` e depois `system.install.run`.
  - Num disco vazio, basta digitar o nome do disco.
  - Num disco com dados ou com CoreRouter, `system.install.challenge` mostra um código de 6
    caracteres no console da máquina, que vale por 5 minutos. Sem console, aperte o botão de
    energia 3 vezes em 30 s.

Ao terminar, tire o pendrive e reinicie. O disco boota sozinho, já pelo dm-verity.

## 6. Depois de instalado

- Sem endereço de gerência, o console abre o assistente. Ele pede a porta, o endereço, o gateway
  e a senha do `admin`; sem essa senha, o login pela rede é recusado.
- Repita o passo 4 no sistema instalado e compare com o live.
- Para testar a atualização pela rede, gere um pacote novo e envie:
  `cargo xtask os push --to <IP>:8729 --user admin`. O roteador grava o slot B, reinicia e
  confirma. Se o slot novo falhar, ele volta sozinho para o A.
- Reinicie algumas vezes e desligue no botão uma vez, para ver o `/config` sobreviver.

## O que trazer de volta

Os arquivos `hw-*.json` dos passos 4 e 6, o modelo da máquina e das placas, o firmware usado
(UEFI ou BIOS) e qualquer tela de erro (foto ou texto da serial). Com isso a sessão atualiza a
tabela de placas em `docs/os-image.md` e fecha a G1.6jb, ou abre gaps para o que falhar.
