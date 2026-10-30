# CoreRouter como core OSPF/MPLS ao lado de MikroTik (G3.9)

Roteiro para um primeiro teste em produção: um CoreRouter numa VM entra no core OSPF/LDP que hoje
é só de RouterOS v7, atende poucos clientes de teste e **não vira caminho de trânsito** de ninguém.
Tudo aqui foi exercitado contra um RouterOS 7.25 CHR de verdade no laboratório
(`scripts/routeros-interop.sh`, seção "Laboratório" no fim); os números são de lá, **medidos** em
2026-10-28, VM do laboratório (KVM aninhado), FRR 10.7.1.

Resumo do que interopera e do que não:

| Item | Resultado com RouterOS 7.25 |
|---|---|
| OSPFv2 `ptp` e `broadcast` | ok; em broadcast com prioridade 0 o MikroTik é DR e o CoreRouter fica DROther |
| Autenticação | **md5 e sha256** ok; sha1, sha384 e sha512 **não** (o FRR 10.7.1 empacotado não as tem; o commit agora falha com a mensagem do FRR em vez de mandar pacotes inválidos) |
| MTU diferente | adjacência presa em ExStart/Exchange (RFC 2328 §10.6), `routing.ospf.neighbor.diagnose` diz que é MTU; `mtu_ignore` só do nosso lado resolve |
| Áreas normal, stub, NSSA | ok; tipo diferente nos dois lados não forma adjacência (certo) |
| Redistribuição | só o que o template anuncia (passive) ou a chain deixa passar |
| LDP | sessão por loopback (transport address = LSR id), rótulos nos dois sentidos, tráfego rotulado CHR ⇄ CoreRouter |
| BFD | ok a 300 ms × 4, 300 ms × 3 e 100 ms × 3 (G3.9b: 0 quedas em 30 s numa sessão nova e numa troca com a sessão no ar; antes 15 e 5). Logo depois do Up o RouterOS segue mandando a ~1 s por ~1 s; o CoreRouter segura a detecção lenta até ver a taxa nova. Um `bfdd` do FRR do outro lado do mesmo CHR ainda flapa a 100 ms (13) |
| LSP ping (RFC 8029) | o RouterOS não responde: use ping/traceroute IP e a tabela de rótulos |
| OSPFv3 | ok (ptp, loopback /128 trocada) |

## Pré-requisitos

- **Imagem com FRR 10.7.x** (G1.6k). O laboratório usou o FRR 10.7.1 de deb.frrouting.org. Se a
  imagem vier sem OpenSSL no FRR, valem só md5 e sha256 na autenticação OSPF (acima).
- **VM Proxmox com OVMF (UEFI).** A imagem boota sem bootloader (EFI stub); em SeaBIOS, o padrão do
  Proxmox, ela não sobe (G1.6g). Na criação: *BIOS: OVMF (UEFI)*, um *EFI Disk*, *Machine: q35*,
  disco a partir do `corerouter.qcow2` (`qm importdisk <vmid> corerouter.qcow2 <storage>`), CPU
  `host`, 2 vCPUs e 1 GiB bastam para o teste.
- **Placas virtio** (ou passthrough de uma porta física). Uma placa para o enlace com o MikroTik
  (de preferência uma VLAN ou uma porta só para isso), uma para os clientes de teste e uma de
  gerência, se a gerência não for pelo próprio core. Ponha todas **antes** do primeiro boot: uma
  placa acrescentada com a VM ligada ainda não entra sozinha na configuração (G1.3b); reinicie a
  VM depois de acrescentar.
- **NVRAM nova.** A entrada de boot do instalador carrega o endereço de gerência
  (`corerouter.mgmt=`) e os PARTUUIDs da imagem são fixos: uma VM nova que herde a NVRAM de
  outra (mesmo nome no libvirt, `virsh undefine` sem `--nvram`) boota o disco novo com o
  endereço da antiga, e o assistente não aparece. Crie a VM com NVRAM nova (Proxmox: um *EFI
  Disk* novo; libvirt: `virsh start --reset-nvram <vm>` ou `virsh undefine --nvram` antes de
  recriar). Quando o roteador aplica um `corerouter.mgmt=`, o console diz o endereço, a porta e
  que veio da entrada de boot.
- **Nomes das portas.** A imagem chama as placas de `ether1`, `ether2`… na ordem do barramento
  PCI (a ordem das `net0`, `net1`… do Proxmox), e o nome fica preso ao MAC
  (`/config/.port-names`): placa acrescentada depois ganha o próximo número. Confira no
  assistente, que mostra link e MAC de cada uma, e compare com os MACs do hipervisor.
- **Primeiro IP pelo console.** Não há cloud-init (G1.6h) nem terminal de comandos no console:
  abra o console (noVNC ou serial `qm terminal <vmid>`; libvirt: `virsh console <vm>`) e
  aperte Enter. O assistente de primeiro boot lista as portas, pede a de gerência pelo número
  (e confirma: `Use ether4 (link up, bc:24:11:…)? [y/N]`), o endereço, o gateway e a senha do
  `admin`, mostra o resumo e só aplica com `y`:

  ```text
  Ethernet ports (empty answer: cancel):
    1) ether1 (link up, bc:24:11:00:00:01)
    2) ether2 (no link, bc:24:11:00:00:02)
    3) ether3 (no link, bc:24:11:00:00:03)
    4) ether4 (link up, bc:24:11:00:00:04)
  Management port (number or name): 4
  Use ether4 (link up, bc:24:11:00:00:04)? [y/N] y
  Address/prefix (e.g. 192.0.2.10/24; empty: cancel): 192.0.2.10/24
  Gateway (empty: none): 192.0.2.1
  ```

  A senha do `admin` é opcional aqui: sem ela, como no CHR, o roteador aceita a senha vazia
  pela rede (sempre TLS) e todos os clientes, o log e a saúde avisam até ela ser definida
  (G0.3d). Defina-a no primeiro acesso: entre com a senha vazia e use **Set password** na GUI
  (ou `/user set admin password=…`). Até lá qualquer um que alcance a porta de gerência entra.

  O resto (a configuração abaixo) vai pela rede: `corerouter-cli --connect
  tls://192.0.2.10:8729 --user admin` ou a GUI. Com endereço já posto, Enter no console mostra
  os endereços e os comandos para conectar. O shell de manutenção (`corerouter.shell=ttyS0` na
  entrada de boot) é só para laboratório.

- **MTU de MPLS.** Com LDP, o pacote de 1500 bytes do cliente vira 1504 no enlace. No laboratório
  (enlaces de 1500), o ping de 1500 com DF através do LSP **se perdeu**: aumente o MTU do enlace
  CoreRouter ⇄ MikroTik (no Proxmox, a bridge e a `net0` com `mtu=` maior; no MikroTik
  `l2mtu`/`mtu` da porta e `mpls-mtu` em `/mpls interface`), como já deve estar no resto do core.
  Os dois lados do enlace OSPF com o **mesmo** MTU IP, senão a adjacência não sai de ExStart.

## Configuração de partida (sem atrair tráfego)

O que ela faz: router-id único na loopback; **stub router** (RFC 6987, G3.9c): todo enlace de
trânsito do CoreRouter sai na router-LSA com custo 65535, de uma vez e inclusive num template
acrescentado depois (ninguém calcula caminho de trânsito por ele, mas o que ele anuncia continua
alcançável; medido no caso `stub-router`), e os templates já levam o custo real; depois de cada
partida (reboot, FRR reiniciado) ele fica 300 s como stub router (`stub-router-on-startup`), tempo
para as adjacências, o LDP e o BFD subirem antes de ele voltar a ser trânsito: o RouterOS não tem
sincronização LDP-IGP (RFC 5443); prioridade 0 se o enlace for broadcast (nunca DR/BDR); anuncia **só** a loopback e a
sub-rede dos clientes de teste (templates passivos, sem `redistribute`); autenticação sha256; BFD
300 ms × 4 (detecção em 1,2 s; ver "Como ampliar"); LDP com transport address na loopback; TI-LFA desligado (é o padrão: só
liga com `routing.ospf.segment-routing.set`).

Troque os endereços, a chave e os nomes das portas pelos seus. No terminal do CoreRouter
(`corerouter-cli --connect … shell`, a janela Terminal da GUI ou SSH) cole o bloco inteiro: colar
várias linhas vira um único batch atômico (entra tudo numa revisão ou nada), e `/import
file=core-start.rsc` faz o mesmo a partir de um arquivo.

<!-- lab:core-start (scripts/routeros-interop.sh aplica este bloco como está) -->
```text
/system identity set name=cr-core-teste
/interface loopback add name=lo
/ip address add address=10.255.39.2/32 interface=lo
/ip address add address=10.39.1.2/30 interface=ether1 comment="core MikroTik"
/ip address add address=100.64.39.1/24 interface=ether3 comment="clientes de teste"
/routing bfd profile add name=mikrotik min-tx=300 min-rx=300 multiplier=4
/routing ospf instance add name=v2 router-id=10.255.39.2 stub-router=yes stub-router-on-startup=300
/routing ospf area add name=backbone instance=v2 area-id=0.0.0.0
/routing ospf interface-template add area=backbone interfaces=ether1 type=ptp cost=10 priority=0 auth=sha256 auth-id=1 auth-key=TROQUE-ESTA-CHAVE bfd=mikrotik comment="core MikroTik"
/routing ospf interface-template add area=backbone interfaces=lo passive=yes comment=loopback
/routing ospf interface-template add area=backbone interfaces=ether3 passive=yes comment="clientes de teste"
/mpls ldp add lsr-id=10.255.39.2
/mpls ldp interface add interface=ether1
```

Do lado do MikroTik (que já roda OSPF e LDP no core; ajuste a área e as portas aos nomes que você
usa; `cost` aqui é o custo da ida do MikroTik ao CoreRouter, que só importa para o tráfego
destinado a ele):

<!-- lab:mikrotik-side (aplicado no CHR pelo laboratório) -->
```text
/routing bfd configuration add interfaces=ether1 min-rx=300ms min-tx=300ms multiplier=4 comment=corerouter
/routing ospf interface-template add area=backbone interfaces=ether1 type=ptp cost=10 auth=sha256 auth-id=1 auth-key=TROQUE-ESTA-CHAVE use-bfd=yes comment=corerouter
/mpls ldp interface add interface=ether1 comment=corerouter
```

Equivalências, item por item:

| CoreRouter | RouterOS v7 | Nota |
|---|---|---|
| `/routing ospf instance … router-id=` | `/routing ospf instance set … router-id=` | Único no domínio; na loopback |
| instância `stub-router=yes` | não existe: `cost=65535` em cada interface-template | RFC 6987: só os enlaces de trânsito vão a 65535, a loopback e os passivos mantêm o custo; vale para todo template, inclusive os novos |
| `stub-router-on-startup=300` | não existe (nem LDP-IGP sync) | Depois de cada partida, 300 s sem ser trânsito; só OSPFv2 |
| template `cost=10` | `cost=` no interface-template | O custo vale na saída de cada lado; com o stub router ligado, o de trânsito sai 65535 |
| `priority=0` | `priority=0` | Só conta em `broadcast`; em `ptp` não há eleição |
| `auth=sha256 auth-id=1 auth-key=…` | `auth=sha256 auth-id=1 auth-key=…` | Mesmo key id dos dois lados (o RouterOS loga "wrong SA ID") |
| `bfd=mikrotik` (perfil 300/300/4) | `use-bfd=yes` + `/routing bfd configuration` | O RouterOS só faz BFD nas portas listadas em `configuration`; sem autenticação nem echo |
| `/mpls ldp add lsr-id=` | `/mpls ldp add lsr-id= transport-addresses=` | O nosso usa o LSR id como transport address por padrão |
| `/mpls ldp interface add` | `/mpls ldp interface add` | — |
| templates `passive=yes` | `passive` | Anuncia a rede sem formar vizinho |
| (sem `redistribute`) | — | Nada de `connected`/`static` no começo |

## Antes de ligar (checklist)

- [ ] router-id e loopback novos, que não existem no core (`/routing ospf lsa print` no MikroTik).
- [ ] MTU IP igual nos dois lados do enlace; MTU de enlace com folga para os rótulos.
- [ ] Área e tipo de área iguais (normal com normal; stub ou NSSA nos dois).
- [ ] Mesmo algoritmo, key id e chave (md5 ou sha256).
- [ ] Timers iguais (hello/dead; o padrão dos dois é 10/40 s).
- [ ] BFD listado na `/routing bfd configuration` do MikroTik para a porta.
- [ ] Só a loopback e a sub-rede de teste nos templates do CoreRouter; nenhum `redistribute`.
- [ ] Console da VM aberto (noVNC/serial) para sair mesmo sem rede.
- [ ] Imagem de VM (qcow2/OVA) reiniciada uma vez depois do primeiro boot: o primeiro sobe pelo
  caminho de fallback da UEFI, **sem dm-verity**, e cria as entradas "CoreRouter A/B"; do segundo
  em diante a raiz é conferida. Confira em System › Packages (`system.package.print`: o slot
  `running` com `"verity": true`). O "Shutdown" do hipervisor desliga limpo (G1.6q).
- [ ] Um cliente de teste pronto para pingar através do CoreRouter.

## Como entrar

**Pelo navegador (G1.6o):** a imagem já vem com `https://<endereço do roteador>/` ligado
(`ip.service www-ssl`, porta 443, o mesmo certificado da porta 8729). O navegador avisa que o
certificado é próprio: confira a impressão digital SHA-256 com a do log do daemon (`TLS
certificate fingerprint`) antes de aceitar. Para limitar quem chega na página, como o `address`
do `/ip service`: `/ip service www-ssl set available_from=192.0.2.0/24` (vale na hora, sem
reiniciar; quem já está conectado continua). O HTTP (80) vem desligado e, ligado, só redireciona
para o HTTPS.

1. **Safe Mode** no terminal do CoreRouter (o da GUI ou o `corerouter-cli --connect tls://…`, não o console da VM): Ctrl+X (o prompt mostra `<SAFE>`). Se a sessão cair,
   tudo o que foi feito nela é desfeito, como no RouterOS.
2. Cole o bloco de partida (um batch atômico, uma revisão). Para revisar antes, use o modo
   transacional: `/config mode set mode=transactional`, cole, `/config diff` mostra o que muda,
   `/routing ospf impact` diz quais adjacências caem (nenhuma, na entrada), `/config commit`.
3. Do lado do MikroTik, o bloco dele (também em Safe Mode: Ctrl+X no Winbox/terminal).
4. Confira (próxima seção) e saia do Safe Mode (Ctrl+X de novo) para manter.

Tempos medidos no laboratório com hello 1 s: Full 1,8–7,6 s depois do commit do CoreRouter; rotas
pelo CoreRouter no CHR 6,6–14,4 s (o CHR fica até ~4 s em Loading); com os blocos acima (hello
10 s) o caso `prod` chegou a Full em 11,7–11,9 s. Com o padrão 10/40 s conte até ~40 s
para a adjacência e alguns segundos a mais para as rotas.

## Como monitorar

| O quê | CoreRouter | RouterOS |
|---|---|---|
| Vizinhos OSPF | `/routing ospf neighbor print` (`routing.ospf.neighbor.list`) | `/routing ospf neighbor print` |
| Por que não sobe | `/routing ospf neighbor diagnose interface=ether1` | `/log print where topics~"ospf"` |
| LSDB | `/routing ospf lsa print` (`routing.ospf.lsa.list`) | `/routing ospf lsa print` |
| Rotas OSPF | `/routing ospf route print` | `/ip route print where ospf` |
| LDP | `/mpls ldp neighbor print`, `/mpls forwarding-table page` | `/mpls ldp neighbor print`, `/mpls forwarding-table print` |
| BFD | `/routing bfd session print`, `/routing bfd history print` | `/routing bfd session print` |
| Logs | `/log print` | `/log print` |

O que esperar: vizinho `Full` (ptp) ou `Full · DR` visto do nosso lado; no LDP o MikroTik
`operational` com transport 10.255.39.1; na tabela de rótulos as FECs das loopbacks do core com
rótulo de saída; BFD `up` com 300 ms e detect time 1200 ms; no MikroTik, `/ip route print` com a
sub-rede de teste via o CoreRouter e **nenhuma** outra rota mudada.

## Como sair em segundos

| Como | Comando | Medido no laboratório |
|---|---|---|
| OSPF passivo no enlace com o MikroTik | `/routing ospf interface-template print`, depois `set 0 passive=yes` (o número do print, como no RouterOS) | tráfego de trânsito desviado em < 0,6 s e a sub-rede de teste fora do MikroTik em 1,3–1,9 s, **sem perda** em nenhuma rodada: o BFD avisa AdminDown e o MikroTik derruba o vizinho na hora |
| Desligar a instância | `/routing ospf instance set v2 disabled=yes` | buraco de 0,44–1,4 s |
| Desligar a VM ou cair o enlace | `qm stop <vmid>` no Proxmox | perda de portadora: buraco de 0,6–0,7 s |
| O CoreRouter travar (corte silencioso) | — | com BFD 300 ms × 4: o MikroTik derruba a adjacência em 1,1 s, buraco de 1,55 s (× 3: 0,7–0,8 s e 1,2–1,3 s); **sem BFD**, o dead interval inteiro (40 s no padrão; 3,4 s com dead 4 s no laboratório) |
| Pelo lado MikroTik | `/routing ospf interface-template disable [find comment=corerouter]` | igual ao passivo |

O passivo é a saída recomendada: revise com `/routing ospf impact` (diz que a adjacência de ether1
cai e sugere Safe Mode). Como a configuração de partida já não atrai trânsito, sair só tira a
sub-rede de teste do ar. A volta (tirar o passivo, religar a VM) não abriu buraco no laboratório
(< 0,1 s): o MikroTik só passa a usar o CoreRouter depois do Full.

## Como atualizar a imagem (com volta automática)

A imagem tem dois slots (A/B, G1.6b): a atualização é gravada no slot que **não** está em uso,
conferida e bootada **uma vez em teste**. Se não se confirmar no prazo, o roteador volta sozinho ao
slot anterior, com a configuração que tinha. O slot em uso nunca é escrito.

1. **Antes:** confira o pacote sem gravar nada e veja o estado dos slots:

   ```sh
   corerouter-cli --connect tls://192.0.2.10:8729 --user admin upload corerouter.crpkg '{"check":true}'
   corerouter-cli --connect tls://192.0.2.10:8729 --user admin run system.package.print
   ```

   `signature: ok` e `intact: true`; nenhum `trial` pendente; o outro slot em `standby` ou
   `empty`. O pacote precisa ser assinado pela chave da imagem (a de produção, não a de
   desenvolvimento de `<out>/keys`, `cargo xtask os out-dir`).
2. **Saia do trânsito** se o roteador já for caminho de alguém (seção acima, "Como sair em
   segundos"): o reboot leva ~1 s de kernel e alguns segundos de firmware.
3. **Envie e instale** com confirmação **manual** e prazo curto, numa janela de manutenção:

   ```sh
   corerouter-cli --connect tls://192.0.2.10:8729 --user admin \
     upload corerouter.crpkg '{"confirm":"manual","timeout":600}'
   ```

   O pacote vai pelo canal TLS, em blocos de 1 MiB, direto para o slot inativo (assinatura
   conferida antes do primeiro byte; hashes e dm-verity antes de ativar). Na GUI: System ›
   Packages › From this computer › **Upload and install…**. Um envio interrompido não muda
   nada.
4. **Depois do reboot**, ainda no prazo: confira OSPF (`/routing ospf neighbor print`), LDP, BFD
   e os clientes de teste. Tudo certo: `run system.package.confirm` (ou **Confirm** na GUI).
   Algo errado: não confirme — no fim do prazo o roteador reinicia no slot anterior; para voltar
   já, reinicie a VM pelo hipervisor (`qm reboot <vmid>`): o teste já gastou o `BootNext` e o
   firmware boota o slot anterior.
5. **Voltar depois de confirmado:** `run system.package.downgrade` boota o outro slot (a versão
   anterior) em teste, com a cópia da configuração que ele rodou por último.

O roteador também baixa sozinho de um servidor HTTP(S) que ele alcance (um servidor interno, por
exemplo): `run system.package.download '{"url":"https://…/corerouter.crpkg","confirm":"manual","timeout":600}'`.
Sem acesso de rede ao roteador, o mesmo pacote vai num pendrive: `system.package.update
{"path":"/dev/sdb"}` (G1.6b).

## Como ampliar depois

1. Tirar o stub router quando as adjacências, o LDP e o BFD estiverem de pé:
   `/routing ospf instance set v2 stub-router=no` (ou o botão **Undrain** em Routing › OSPF ›
   Instances), olhando `/routing ospf route print` no MikroTik para ver o que passou a ir pelo
   CoreRouter. O `stub-router-on-startup=300` fica: depois de um reboot ele volta a ser trânsito
   sozinho, 300 s depois da primeira router-LSA. Para manutenção, `stub-router=yes` (**Drain**)
   tira o trânsito antes e `stub-router=no` o devolve. Quem preferir abrir enlace por enlace
   deixa o stub router desligado e começa com `cost=65535` nos templates, baixando um por vez.
2. Mais clientes: mais templates passivos ou um `redistribute` com `out_filter_chain` que aceite só
   as redes certas (caso `redistribute` do laboratório).
3. BFD mais rápido só depois de medir. Com o RouterOS 7.25 e o G3.9b, 100 ms × 3 ficou estável
   no laboratório (0 quedas em 30 s numa sessão nova e numa troca 300 → 100 com a sessão no ar;
   antes 15 e 5). O custo: logo depois de cada subida, até o RouterOS acelerar (~1 s, **medido**),
   a detecção dessa sessão é a lenta (3 × 1 s; o `detect_time_us` da sessão mostra). Desça de
   300 ms × 4 enlace por enlace, olhando `flaps_24h`; o dampening (ligado por padrão) segura uma
   sessão instável caída, e com ela a adjacência OSPF.
4. Graceful restart (G3.4e) e TI-LFA (G3.4d) depois que o CoreRouter for trânsito de verdade.

## Laboratório

```sh
cargo xtask vm-lab run -- scripts/routeros-interop.sh           # todos os casos (~12 min)
cargo xtask vm-lab run -- scripts/routeros-interop.sh ldp bfd   # só alguns
cargo xtask vm-lab run -- env HOLD=600 scripts/routeros-interop.sh ospf-ptp   # e inspecionar
```

Dentro da VM do laboratório: um RouterOS 7.25 CHR (QEMU/KVM aninhado, imagem oficial com o
SHA-256 publicado conferido), o CoreRouter com `--backend linux` e o FRR dele (`-N crcore`, `bfdd`
com o nosso motor como data plane) num namespace, e dois FRR (R3 e R4) para tráfego de ponta a
ponta. O lado RouterOS é configurado pela API REST; o caso `prod` aplica os dois blocos deste
documento como estão.

```text
R3 ── CHR (RouterOS) ── CoreRouter ── R4
          └──────── custo 1000 ───────┘
```

## Pesquisa

- **MikroTik RouterOS v7** (referência de nomes e comportamento):
  [OSPF](https://help.mikrotik.com/docs/spaces/ROS/pages/9863229/OSPF) e a
  [referência de propriedades](https://help.mikrotik.com/docs/spaces/ROS/pages/331612216/routing+ospf)
  (interface-template: `auth` simple/md5/sha1/sha256/sha384/sha512, `auth-id`, `priority` 128 por
  padrão, `type` broadcast por padrão, hello/dead 10/40 s; sem `mtu-ignore` documentado),
  [BFD 7.25](https://manual.mikrotik.com/docs/7.25/user-guides/routing-and-networking-protocols/unicast/bfd/)
  (`use-bfd` no template, sessões só nas portas de `/routing bfd configuration` — o resto é
  proibido por padrão —, sem echo nem autenticação),
  [LDP 7.25](https://manual.mikrotik.com/docs/7.25/user-guides/routing-and-networking-protocols/mpls/ldp)
  (`/mpls ldp add lsr-id= transport-addresses=`). O RouterOS não tem SR-MPLS nem sincronização
  LDP-IGP; o caminho com ele é LDP.
- **Outros:** Junos [overload](https://juniper.net/documentation/en_US/junos12.2/topics/concept/ospf-overload-function-overview.html)
  (`overload timeout`, entrar sem trânsito) e
  [sincronização LDP-IGP](https://juniper.net/documentation/en_US/junos13.1/topics/example/routing-synchronization-between-ldp-and-igps-configuring.html)
  (custo máximo até o LDP subir); Cisco IOS-XE `max-metric router-lsa on-startup` e `mpls ldp
  sync`; o FRR (usado também pelo VyOS) tem os dois (`max-metric router-lsa`, `mpls ldp-sync`).
  O que fazem melhor: o *stub router* cobre todos os enlaces de uma vez e expira sozinho;
  o CoreRouter o tem desde a G3.9c (`stub-router`, `stub-router-on-startup`, sobre o
  `max-metric router-lsa` do `ospfd`).
- **RFCs:** [RFC 2328](https://www.rfc-editor.org/rfc/rfc2328) §10.6 (MTU no DD), §10.5 (bit E),
  §9.4 (eleição de DR, prioridade 0); [RFC 3101](https://www.rfc-editor.org/rfc/rfc3101) (NSSA);
  [RFC 5709](https://www.rfc-editor.org/rfc/rfc5709) (HMAC-SHA no OSPFv2);
  [RFC 6987](https://www.rfc-editor.org/rfc/rfc6987) (stub router); [RFC 5036](https://www.rfc-editor.org/rfc/rfc5036)
  (LDP, transport address §2.5.5); [RFC 5443](https://www.rfc-editor.org/rfc/rfc5443) (LDP-IGP
  sync); [RFC 5880](https://www.rfc-editor.org/rfc/rfc5880) §6.8.3/§6.8.4 (taxas e detect time),
  [RFC 5881](https://www.rfc-editor.org/rfc/rfc5881), [RFC 5882](https://www.rfc-editor.org/rfc/rfc5882);
  [RFC 3032](https://www.rfc-editor.org/rfc/rfc3032) §2.3.2 e [RFC 4950](https://www.rfc-editor.org/rfc/rfc4950)
  (ICMP em pacote rotulado); [RFC 8029](https://www.rfc-editor.org/rfc/rfc8029) (LSP ping, que o
  RouterOS não responde).
- **Fora:** OSPFv3 com autenticação (não testado), BFD multihop e echo (o RouterOS não tem echo),
  L3VPN/VPLS (G3.5c/d), testes com tráfego de verdade (o CHR sem licença limita a 1 Mbit/s por
  porta).
