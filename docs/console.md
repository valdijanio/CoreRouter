# Console local: formato e cor (G1.6zg)

O console local é o que o operador vê na máquina, sem rede: o status do roteador, o assistente
do primeiro boot e o instalador. Ele sai em três lugares ao mesmo tempo:

- a **tela** (`tty1`): o terminal virtual do kernel, em modo texto VGA de 80×25 num boot por
  BIOS e no framebuffer do firmware num boot UEFI (160×50 a 1280×800), com a fonte embutida do
  kernel (CP437);
- a **serial** (`ttyS0`, 115200), com o terminal de quem conecta: `screen`, PuTTY, minicom, o
  serial-over-LAN de um BMC, o console de um hipervisor, um arquivo;
- quem lê por máquina: os testes de imagem (`cargo xtask os *-test`) leem a serial linha a
  linha.

O código fica em `apps/corerouter-init/src/`: `style.rs` (estilos, cor, largura), `console.rs`
(os consoles), `setup.rs` (status e assistente) e `install.rs` (instalador).

## Regras

1. **Só SGR** (`ESC [ … m`): negrito, meio-brilho e as 8 cores, com `ESC[0m` no fim de cada
   trecho e de cada linha. Nada de mover o cursor, limpar a tela, 256 cores ou cor de fundo.
   Quem não conhece cor ignora o parâmetro: o VT100 ("All other parameter values are ignored")
   e o VT do Linux (`drivers/tty/vt/vt.c`, `csi_m` não tem `default:`).
2. **Só ASCII** no texto do init. A serial pode não ser UTF-8, e a fonte do kernel é CP437. (O
   VT do 6.18 troca o glifo que falta por um parecido, `ucs_get_fallback()`; a serial não.)
3. **No máximo 78 colunas** (`style::WIDTH`): nada quebra no meio da palavra numa tela de 80
   colunas, e sobra a última coluna, onde alguns terminais de serial já pulam de linha. Texto
   de fora (erro do daemon, modelo do disco) é quebrado nos espaços ou cortado com `~`.
4. **Legível sem cor.** A cor repete o que a palavra já diz (`OK`, `WARNING`, `FAILED`, `up`,
   `down`, `off`). Com a cor desligada o texto é o mesmo, sem os escapes.
5. **A tela de status cabe em 25 linhas**, com tudo ligado (live, sem senha, alerta de saúde,
   impressão digital). A tabela de portas fica com o que sobra: primeiro as portas com
   endereço, depois as com enlace, e uma linha "... and N more".
6. **Texto de fora não comanda o terminal.** `style::render` troca por `?` todo caractere de
   controle que não seja a quebra de linha (ESC, BEL, CR, C1), venha ele de um erro do daemon,
   do modelo de um disco ou do que foi digitado no outro console.

## Estilos

Um lugar só (`Style::sgr`). O texto é montado com marcas (`style::warn("WARNING")`) e cada
console recebe a cor ou nada (`style::render`).

| Estilo | SGR | Onde |
|---|---|---|
| `Title` | `1` (negrito: branco intenso no VT) | linha do produto, passo `[2/5] Disk`, cabeçalho de tabela, disco oferecido |
| `Key` | `1;36` (ciano intenso) | o endereço para abrir a GUI, a tecla a apertar |
| `Good` | `32` (verde) | `OK`, `up`, `INSTALLED` |
| `Warn` | `1;33` (amarelo) | `WARNING`, `no password` |
| `Bad` | `1;31` (vermelho intenso) | `FAILED`, `!! ALL DATA ON sda WILL BE ERASED !!` |
| `Dim` | `2` (meio-brilho: cinza escuro no VT) | detalhe técnico (commit, chave, tempos), disco não oferecido |
| `Ask` | `1;33` | a pergunta que espera resposta |

No VT o negrito é o bit de intensidade da cor, não uma fonte mais grossa (`vt.c`, `build_attr`),
por isso `1;33` é amarelo e `33` sozinho é marrom. Azul ficou de fora: azul escuro em fundo
preto não se lê no VGA.

## Ligar e desligar a cor

A cor vem ligada na tela e na serial. A linha de comando do kernel decide (`style::Color`):

| Na linha do kernel | Efeito |
|---|---|
| nada | cor em todos os consoles |
| `corerouter.color=screen` | cor só na tela; a serial fica em texto puro |
| `corerouter.color=off` | sem cor |
| `NO_COLOR=1` ([no-color.org](https://no-color.org): presente e não vazio) | sem cor |
| `TERM=dumb` | sem cor |
| `corerouter.color=on` | cor, mesmo com `NO_COLOR` ou `TERM=dumb` |

Na ISO, edite a linha no menu do GRUB (`e`). O instalador leva `corerouter.color=` para o disco
instalado e a atualização o leva de um slot para o outro (`CARRY_PREFIXES`, como `console=`).

As linhas `corerouter-init: …` do PID 1 não têm cor: são log (vão ao `kmsg` e ao log do
roteador). Os testes de imagem tiram os SGR da serial antes de comparar
(`xtask/src/os.rs`, `console_text`) e conferem que a serial veio com cor.

## Perguntas

Todas no mesmo formato (`style::prompt`): `  Pergunta [padrão] (teclas ou forma): `. O que está
entre colchetes é o que o Enter vale; sem colchetes, o Enter vazio cancela ou repete.
Sim ou não é sempre `[y/N]`.

O que é digitado passa por `style::typed`: `^H` e `DEL` apagam (o tty só conhece um dos dois,
conforme o terminal), sequências de escape (uma seta) e caracteres de controle são descartados.

## Telas

**Status** (com endereço; Enter mostra de novo):

```text
CoreRouter 0.1.0-dev.553                    QEMU Standard PC (Q35 + ICH9, 2009)
------------------------------------------------------------------------------
  Web   https://10.0.2.15/  (user admin)
  GUI   corerouter-gui --connect tls://10.0.2.15:8729
  CLI   corerouter-cli --connect tls://10.0.2.15:8729 --user admin
  Cert  SHA256:B9:4D:27:B9:93:4D:3E:08:A5:2E:52:D7:DA:7D:AB:FA:
        C4:84:EF:E3:7A:53:80:EE:90:88:F7:AC:E2:EF:CD:E9

  PORT             LINK   ADDRESS
  ether1           up     10.0.2.15/24
  ether2           off    -

  WARNING  admin has no password: anyone who reaches the router logs in as
           admin with an empty password. Set one from the GUI or the CLI.

  This console has no command shell. Press Enter to show this status again.
```

- `Cert` é a impressão digital SHA-256 do certificado TLS do roteador, igual à que a GUI, a CLI
  e o navegador mostram na primeira conexão. O console é o único caminho que não passa pela
  rede: dá para conferir antes de aceitar.
- `LINK`: `up`, `down` (porta ligada, sem enlace) ou `off` (porta desligada: não dá para saber
  se há cabo).
- Sem endereço, a mesma tela diz `no port has a management address yet` e convida ao
  assistente (de novo a cada 5 min).
- Na ISO live há um `WARNING  live image, NOT INSTALLED` com o que fazer (`i` e Enter instala
  pelo console).

**Assistente do primeiro boot**: passos `[1/4] Management port`, `[2/4] Address`,
`[3/4] Admin password`, `[4/4] Apply`; nada muda antes do `Apply? [y/N]`.

**Instalador**: cabeçalho com firmware e consoles, depois `[1/5] Medium`, `[2/5] Disk`,
`[3/5] Management address for the first boot`, `[4/5] Confirm`, `[5/5] Write`.

- Tabela de discos: o que pode ser o destino tem número e negrito; o que não pode fica
  esmaecido, com `-` no lugar do número e o motivo na linha de baixo.
- Com um disco só para oferecer, o Enter o escolhe (`Disk to install on [1]`). Nada é gravado
  antes de o nome do disco ser digitado no passo 4.
- O passo 4 mostra `!! ALL DATA ON <disco> WILL BE ERASED !!`, o disco (tamanho, modelo,
  serial, o que guarda), a versão e o endereço que vão para ele.
- A gravação cresce numa linha só, uma marca a cada 10% (`Writing vda: 10% 20% … 100%`). Não
  usa `\r`: a linha sai igual na tela, num log da serial e num teste.
- No fim: `OK  INSTALLED CoreRouter <versão> on <disco> in <t> s` em verde, o que fazer agora
  (tirar a mídia, Enter, o endereço para abrir) e os tempos numa linha esmaecida. Erro:
  `FAILED  The install failed: <causa>` em vermelho.
- A instalação não assistida (`fw_cfg`) passa pelos mesmos passos sem perguntar nada.

## Pesquisa

Fontes e o que cada um faz: corpo do PR da G1.6zg e `docs/changes`. Resumo:

- **MikroTik RouterOS v7**: cor ligada por padrão no terminal, com chave para desligar no nome
  de login (`admin+c`, `+e` para terminal burro); banner depois do login.
- **OPNsense/pfSense, OpenWrt, Proxmox, VyOS, TrueNAS**: nenhum usa cor no console local. O
  Proxmox põe a URL de gerência entre duas réguas; o OPNsense mostra uma linha por interface e
  a impressão digital do certificado HTTPS; o OpenWrt repete o aviso de senha vazia até
  corrigir; OPNsense, pfSense e TrueNAS têm menu numerado.
- **systemd**: estado em palavra de largura fixa (`[  OK  ]`), cor como reforço, `ESC[0m` no
  fim; cor decidida por variável explícita, depois `NO_COLOR`, depois `TERM=dumb`.
- **Kernel 6.18.59** (lido no fonte da imagem): `drivers/tty/vt/vt.c` (`csi_m`, `build_attr`,
  `default_utf8`), `drivers/tty/vt/ucs.c` (`ucs_get_fallback`), `drivers/tty/vt/cp437.uni`;
  `init/main.c` (`unknown_bootoption`: parâmetro com ponto não vai para o ambiente do init).

## O que ficou de fora e por quê

- **Tela cheia com janelas, setas e botões** (como o DCUI do ESXi): precisa de movimento de
  cursor e do tamanho do terminal, que a serial não informa; seriam dois caminhos de código
  (tela cheia e linha) e os testes de imagem leem linha a linha. Decisão do dono: não fazer.
- **Caixas em Unicode** e **menu numerado**: G1.6zj.
- **Cor nas linhas do PID 1** e o `…`/`→`/`−` que elas e o `live.rs` ainda escrevem: G1.6zj.
