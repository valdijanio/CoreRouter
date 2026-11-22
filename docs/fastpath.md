# Fast path (flowtable) — G2.4

O caminho rápido das conexões já aceitas: o `nf_flowtable` do Linux, que é o FastTrack do RouterOS.
Depois que o firewall aceitou uma conexão TCP ou UDP e ela ficou estabelecida, os pacotes seguintes
pulam as regras de forward e vão direto da porta de entrada à de saída, com o NAT já feito. Com uma
placa que aceita, a própria placa encaminha (offload em hardware).

## 1. Como funciona

### 1.1 A tabela

`crates/firewall/src/fastpath.rs` descreve a tabela como dado (`program::Table`, o mesmo do CGNAT).
O `hal-linux` a envia por nfnetlink num lote atômico, sem o binário `nft` (`docs/architecture.md`
§1.2.1):

```text
table inet corerouter_fastpath {
	flowtable ft {
		hook ingress priority filter;
		devices = { ether1, ether2 }
		flags offload        # só com hardware
		counter
	}
	chain forward {
		type filter hook forward priority filter + 10; policy accept;
		meta l4proto tcp ct state established flow add @ft
		meta l4proto udp ct state established flow add @ft
	}
}
```

- **Depois do firewall.** A cadeia roda com prioridade `filter + 10`, depois da cadeia `forward`
  do firewall (`inet corerouter`, prioridade `filter`). Um pacote descartado pelas regras não chega
  aqui. Só entra no flowtable o que as regras aceitaram, e uma regra de drop sempre vale para
  conexões novas.
- **Firewall mudou, flowtable recriado.** Apagar o flowtable devolve os fluxos dele ao caminho
  normal. As conexões que uma regra nova bloqueia param na hora, sem esperar acabar.
- **`ct state established`:** o primeiro pacote de toda conexão passa pelas regras e pelo NAT.
- **IPv4 e IPv6** (família `inet`), TCP e UDP.

O que o kernel manda sempre pelo caminho normal (doc do kernel, `nf_flowtable.rst`):

- fragmentos;
- pacotes maiores que o MTU (para o ICMP "too big");
- o FIN/RST do TCP (para encerrar a conexão direito).

Uma entrada fica velha se o MAC de destino ou a porta de saída mudam.

### 1.2 Portas

`interfaces` vazio (o padrão) põe todas as portas Ethernet e bonds; os slaves de um bond ficam de
fora, porque o bond entra. Uma porta nomeada que não existe no kernel na hora é pulada (o `status`
mostra).

Nomear uma VLAN é recusado, com a sugestão de nomear a porta: desde o kernel 5.13 o flowtable
encontra sozinho o dispositivo real de uma VLAN ou PPPoE.

### 1.3 Hardware (`hw_offload`)

| valor | o que faz |
|---|---|
| `auto` (padrão) | pede `flags offload`; se o kernel recusar (EOPNOTSUPP), instala em software e o `status` diz por quê |
| `yes` | exige: a mudança é recusada se a placa recusar; o comando já recusa quando nenhuma porta é capaz |
| `no` | só software |

O offload em hardware passa pelo `ndo_setup_tc(TC_SETUP_FT)` do driver. Na NVIDIA/Mellanox ConnectX
(mlx5) isso existe só nos **representors** (o de uplink incluído), com o eSwitch em **switchdev** e
`hw-tc-offload` ligado. É traduzido para o CT offload da placa, que inclui o NAT.

Há relatos de campo em que o offload foi aceito e não usado (VyOS T7747, fórum da NVIDIA). A única
prova é o bit `HW_OFFLOAD` no conntrack, que aparece na coluna Via de Connections e nas contagens
do `status`.

### 1.4 Detecção (`Hal::eswitch`)

Por porta:

- driver e firmware (ethtool e devlink, G1.19);
- `hw-tc-offload` (features do ethtool);
- modo do eSwitch, por `DEVLINK_CMD_ESWITCH_GET` (genetlink, sem o binário `devlink`);
- representor (`phys_port_name` em switchdev).

Com isso o `status` monta, porta a porta, o motivo e a correção:

- **eSwitch em legacy:** `devlink dev eswitch set pci/… mode switchdev`, como root, fora do
  CoreRouter. A placa reinicia e os links caem; trocar o modo por comando é o G2.4c;
- **hw-tc-offload desligado:** o `interface.ethernet.set` que liga.

No lab, ether7 e ether8 simulam portas ConnectX-6 Dx: ether7 em legacy, ether8 como representor
switchdev.

## 2. Comandos

| Comando | O que faz |
|---|---|
| `ip.firewall.fastpath.set {enabled?, interfaces?, hw_offload?, counters?}` | liga, escolhe portas, hardware e contadores |
| `ip.firewall.fastpath.get` | a configuração |
| `ip.firewall.fastpath.status` | instalado ou não, hardware, motivo; portas com placa, eSwitch, motivo e correção; conexões no flowtable |

## 3. Testes

- `crates/firewall/src/fastpath.rs`: a tabela lida como o `nft` escreve; desligado ou sem porta = sem tabela.
- `crates/engine/tests/fastpath.rs`:
  - software e hardware nas portas do lab;
  - portas nomeadas e `hw_offload=no`;
  - validação (VLAN, porta inexistente, `yes` sem placa capaz);
  - rollback.
- `crates/hal-linux/tests/netns_fastpath.rs` (veth + CGNAT, sem root):
  - uma conexão TCP de assinante traduzida e com `OFFLOAD` no conntrack;
  - `auto` cai para software numa veth;
  - `yes` recusado inteiro;
  - desligar remove a tabela;
  - o `nft` lê de volta o que mandamos.
- `crates/ui/src/tests/fastpath.rs`: ligar pelo formulário, selos e correção, recusa explicada.
- **Hardware real:** G2.4b (precisa de uma ConnectX e de root).

## 4. Pesquisa

Fontes lidas em 2026-10-23:

- **MikroTik RouterOS v7**
  ([Packet Flow](https://help.mikrotik.com/docs/spaces/ROS/pages/328227/Packet+Flow+in+RouterOS),
  [Filter](https://help.mikrotik.com/docs/spaces/ROS/pages/48660574/Filter),
  [L3 HW Offloading](https://help.mikrotik.com/docs/spaces/ROS/pages/62390319/L3+Hardware+Offloading)):
  - `action=fasttrack-connection` com `connection-state=established,related` e uma regra `accept`
    igual logo depois, porque parte dos pacotes ainda vai pelo caminho lento;
  - só IPv4, TCP e UDP;
  - pula firewall, conntrack, filas simples, queue tree global, contabilidade, IPsec e a escolha de
    VRF;
  - `hw-offload=yes` (padrão) só vale nos switches Marvell com L3 HW;
  - uma regra fictícia no topo mostra que há tráfego acelerado.
- **VyOS** ([flowtables](https://docs.vyos.io/en/latest/configuration/firewall/flowtables.html)):
  - `set firewall flowtable <n> interface … offload hardware|software` e uma regra
    `action offload offload-target <n>`;
  - IPv4 e IPv6;
  - o melhor diagnóstico: contadores por regra, e as conexões aceleradas aparecem no conntrack.
- **OpenWrt firewall4**
  ([config](https://openwrt.org/docs/guide-user/firewall/firewall_configuration)): `flow_offloading`
  e `flow_offloading_hw` globais (padrão 0); o mais simples de ligar, sem diagnóstico.
- **Kernel**
  ([nf_flowtable](https://docs.kernel.org/networking/nf_flowtable.html)):
  - `flow add` no forward;
  - `counter` desde o 5.7;
  - `flags offload` por workqueue (os primeiros pacotes vão em software);
  - VLAN, PPPoE e bridge desde o 5.13;
  - o que volta ao caminho lento;
  - entradas velhas em mudança de MAC ou saída.
- **mlx5:**
  - TC_SETUP_FT só em representors em switchdev;
  - relatos de offload aceito e não usado:
    [VyOS T7747](https://vyos.dev/T7747),
    [fórum NVIDIA](https://forums.developer.nvidia.com/t/flowtable-nat-hardware-offload-on-connectx-5-cards/255957).

**O que adotamos e o que melhoramos:**

- **Uma opção (OpenWrt) em vez de duas regras (MikroTik).** A cadeia depois do firewall garante o
  que no MikroTik depende da ordem das regras: o que foi descartado não acelera, e não há o `accept`
  gêmeo para esquecer.
- **IPv6 também** (o FastTrack do RouterOS é só IPv4).
- **`auto` com queda para software e o motivo** (o RouterOS e o OpenWrt não dizem por que o
  hardware não pegou), e `yes` para quem precisa de garantia.
- **Diagnóstico por porta:** placa, eSwitch, representor, hw-tc-offload, o comando que falta e as
  conexões em software e hardware, contadas pelo conntrack.
- **Firewall mudou, flowtable recriado:** uma regra nova vale também para as conexões já
  aceleradas.

**Fica para depois:**

- **G2.4b:** teste em ConnectX real (pps, tamanho da tabela da placa, entradas velhas).
- **G2.4c:**
  - exceções por address list ou regra (filas e contabilidade que precisam ver todo pacote);
  - trocar o eSwitch por comando, com Safe Mode.
