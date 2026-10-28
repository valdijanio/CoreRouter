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
| BFD | ok a **300 ms × 3**; a 100 ms × 3 toda sessão nova flapa (do lado do RouterOS, que também flapa com o `bfdd` do FRR) |
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
- **Primeiro IP pelo console.** Não há cloud-init (G1.6h): abra o console (noVNC ou serial
  `qm terminal <vmid>`), entre como `admin` sem senha (só no console local), defina a senha e um
  endereço de gerência:

  ```text
  /user set admin password=...
  /ip address add address=192.0.2.10/24 interface=ether4
  /ip route add dst-address=0.0.0.0/0 gateway=192.0.2.1
  ```

- **MTU de MPLS.** Com LDP, o pacote de 1500 bytes do cliente vira 1504 no enlace. No laboratório
  (enlaces de 1500), o ping de 1500 com DF através do LSP **se perdeu**: aumente o MTU do enlace
  CoreRouter ⇄ MikroTik (no Proxmox, a bridge e a `net0` com `mtu=` maior; no MikroTik
  `l2mtu`/`mtu` da porta e `mpls-mtu` em `/mpls interface`), como já deve estar no resto do core.
  Os dois lados do enlace OSPF com o **mesmo** MTU IP, senão a adjacência não sai de ExStart.

## Configuração de partida (sem atrair tráfego)

O que ela faz: router-id único na loopback; **custo 65535** em todo enlace do CoreRouter (ninguém
calcula caminho de trânsito por ele, mas o que ele anuncia continua alcançável; medido no caso
`entry`); prioridade 0 se o enlace for broadcast (nunca DR/BDR); anuncia **só** a loopback e a
sub-rede dos clientes de teste (templates passivos, sem `redistribute`); autenticação sha256; BFD
300 ms × 3 com dampening; LDP com transport address na loopback; TI-LFA desligado (é o padrão: só
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
/routing bfd profile add name=mikrotik min-tx=300 min-rx=300 multiplier=3
/routing ospf instance add name=v2 router-id=10.255.39.2
/routing ospf area add name=backbone instance=v2 area-id=0.0.0.0
/routing ospf interface-template add area=backbone interfaces=ether1 type=ptp cost=65535 priority=0 auth=sha256 auth-id=1 auth-key=TROQUE-ESTA-CHAVE bfd=mikrotik comment="core MikroTik"
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
/routing bfd configuration add interfaces=ether1 min-rx=300ms min-tx=300ms multiplier=3 comment=corerouter
/routing ospf interface-template add area=backbone interfaces=ether1 type=ptp cost=10 auth=sha256 auth-id=1 auth-key=TROQUE-ESTA-CHAVE use-bfd=yes comment=corerouter
/mpls ldp interface add interface=ether1 comment=corerouter
```

Equivalências, item por item:

| CoreRouter | RouterOS v7 | Nota |
|---|---|---|
| `/routing ospf instance … router-id=` | `/routing ospf instance set … router-id=` | Único no domínio; na loopback |
| template `cost=65535` | `cost=` no interface-template | O custo vale na saída de cada lado |
| `priority=0` | `priority=0` | Só conta em `broadcast`; em `ptp` não há eleição |
| `auth=sha256 auth-id=1 auth-key=…` | `auth=sha256 auth-id=1 auth-key=…` | Mesmo key id dos dois lados (o RouterOS loga "wrong SA ID") |
| `bfd=mikrotik` (perfil 300/300/3) | `use-bfd=yes` + `/routing bfd configuration` | O RouterOS só faz BFD nas portas listadas em `configuration`; sem autenticação nem echo |
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
- [ ] Um cliente de teste pronto para pingar através do CoreRouter.

## Como entrar

1. **Safe Mode** no terminal do CoreRouter: Ctrl+X (o prompt mostra `<SAFE>`). Se a sessão cair,
   tudo o que foi feito nela é desfeito, como no RouterOS.
2. Cole o bloco de partida (um batch atômico, uma revisão). Para revisar antes, use o modo
   transacional: `/config mode set mode=transactional`, cole, `/config diff` mostra o que muda,
   `/routing ospf impact` diz quais adjacências caem (nenhuma, na entrada), `/config commit`.
3. Do lado do MikroTik, o bloco dele (também em Safe Mode: Ctrl+X no Winbox/terminal).
4. Confira (próxima seção) e saia do Safe Mode (Ctrl+X de novo) para manter.

Tempos medidos no laboratório com hello 1 s: Full 1,8–7,6 s depois do commit do CoreRouter; rotas
pelo CoreRouter no CHR 6,6–14,4 s (o CHR fica até ~4 s em Loading); com os blocos acima (hello
10 s) o caso `prod` chegou a Full em 11,8 s. Com o padrão 10/40 s conte até ~40 s
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
rótulo de saída; BFD `up` com 300 ms e detect time 900 ms; no MikroTik, `/ip route print` com a
sub-rede de teste via o CoreRouter e **nenhuma** outra rota mudada.

## Como sair em segundos

| Como | Comando | Medido no laboratório |
|---|---|---|
| OSPF passivo no enlace com o MikroTik | `/routing ospf interface-template print`, depois `set 0 passive=yes` (o número do print, como no RouterOS) | rota trocada no MikroTik em 26 ms, **sem perda**: o BFD avisa AdminDown e o MikroTik derruba o vizinho na hora |
| Desligar a instância | `/routing ospf instance set v2 disabled=yes` | buraco de 0,44–1,4 s |
| Desligar a VM ou cair o enlace | `qm stop <vmid>` no Proxmox | perda de portadora: buraco de 0,70 s |
| O CoreRouter travar (corte silencioso) | — | com BFD 300 ms × 3: o MikroTik derruba a adjacência em 0,8 s, buraco de 1,29 s; **sem BFD**, o dead interval inteiro (40 s no padrão) |
| Pelo lado MikroTik | `/routing ospf interface-template disable [find comment=corerouter]` | igual ao passivo |

O passivo é a saída recomendada: revise com `/routing ospf impact` (diz que a adjacência de ether1
cai e sugere Safe Mode). Como a configuração de partida já não atrai trânsito, sair só tira a
sub-rede de teste do ar. A volta (tirar o passivo, religar a VM) não abriu buraco no laboratório
(< 0,1 s): o MikroTik só passa a usar o CoreRouter depois do Full.

## Como ampliar depois

1. Baixar o custo de um enlace por vez (65535 → o custo real), olhando `/routing ospf route print`
   no MikroTik para ver o que passou a ir pelo CoreRouter.
2. Mais clientes: mais templates passivos ou um `redistribute` com `out_filter_chain` que aceite só
   as redes certas (caso `redistribute` do laboratório).
3. BFD mais rápido só depois de medir: a 100 ms × 3 a sessão nova com RouterOS 7.25 flapa (o
   dampening do perfil segura o pior); trocar 300 → 100 com a sessão já em Up foi estável.
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
  O que fazem melhor: o *stub router* cobre todos os enlaces de uma vez e expira sozinho
  (gap G3.9c); aqui, sem ele, a partida usa custo 65535 por template.
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
