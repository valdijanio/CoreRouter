# Gerência numa VRF (G3.4za, G3.4zb)

A rede de gerência fica fora da tabela que o OSPF e o BGP alimentam. Uma rota aprendida não
consegue então levar embora a sessão do operador. Esse foi o corte da fase C: os `/32` OSPF do
gerador sobre a `ether1` do notebook. São três peças:

| Peça | Comando | O que faz |
|---|---|---|
| Guarda da gerência (G3.4z, G3.4za) | `routing.management-guard.add {network, vrf?}` | o zebra recusa, de todos os protocolos, prefixo aprendido dentro da rede e mais longo que ela, **na tabela dela** (main ou a VRF) |
| Serviços na VRF (G3.4zb) | `ip.service.{www-ssl,www,metrics}.set {vrf}` | o ouvinte fica preso ao dispositivo da VRF e só atende lá |
| Porta TLS de controle na VRF (G3.4zb) | `corerouter-daemon --listen … --listen-vrf <vrf>` | o mesmo para o canal de controle da CLI e do MCP (e `--ws-listen`) |

## Como montar

```sh
corerouter-cli run ip.vrf.add '{"name":"mgmt","interfaces":"ether3"}'
corerouter-cli run ip.address.add '{"address":"10.99.0.1/24","interface":"ether3"}'
corerouter-cli run ip.service.www-ssl.set '{"enabled":true,"vrf":"mgmt"}'
corerouter-cli run ip.service.metrics.set '{"enabled":true,"address":"::","vrf":"mgmt"}'
corerouter-daemon --backend linux --listen 0.0.0.0:8729 --listen-vrf mgmt …
```

Faça a mudança pelo console, pela porta de loopback (`--control`, que nunca muda de VRF) ou em
Safe Mode. Mudar o `www-ssl` de VRF pela própria sessão que passa por ele é recusado como
lockout, a menos que se use `force`.

## Como funciona no kernel

O socket recebe `SO_BINDTODEVICE` com o nome da VRF antes do `bind()`, como pede o
`Documentation/networking/vrf.rst` do kernel. Assim:

- ele só aceita conexões que chegam pelas portas da VRF;
- as respostas saem pela tabela da VRF (regra `l3mdev`), nunca pela main;
- a mesma porta pode ser usada em VRFs diferentes;
- o endereço da VRF só é aceito no `bind()` depois que o dispositivo está definido, porque a
  rota local dele fica na tabela da VRF.

O CoreRouter não liga o `net.ipv4.tcp_l3mdev_accept` (o padrão do kernel é 0). Com ele em 0, um
ouvinte na main não atende conexões que chegam por uma VRF. A separação fica nos dois sentidos.

A sessão de gerência é conferida pela guarda na tabela da porta do seu endereço local. A consulta
ao kernel vai com a VRF como interface de saída (`ip route get … vrf <nome>`).

## Primeiro boot e VRF removida

A VRF é da config. No primeiro boot, ou se alguém a remover, ela não existe quando o
`--listen-vrf` tenta abrir a porta. O daemon **não para** por isso: ele registra no log e tenta
de novo a cada 2 s, numa thread própria, até a VRF aparecer. Enquanto isso, o caminho de volta é
a porta de loopback e o console.

Os serviços da config (`www-ssl`, `www`, `metrics`) seguem a regra de sempre: tentam de novo a
cada segundo e mostram o motivo em `last_error`. A VRF de um serviço ou de uma rede da guarda não
pode ser removida enquanto estiver em uso: o commit é recusado.

## Conferido

- `scripts/mgmt-guard-vrf-lab.sh` (VM, FRR 10.7.1): guarda com OSPF na VRF e BGP na main.
- `scripts/mgmt-vrf-services-lab.sh` (VM): serviços e porta de controle na VRF, quem chega e quem
  não chega, rota da main sobre o operador da VRF, caminho de volta e reinício.

## Pesquisa

- **MikroTik RouterOS v7**: `/ip service set <serviço> vrf=<vrf>` (padrão `main`), um serviço
  numa VRF só. Vale para telnet, www, ssh, www-ssl, api, winbox e api-ssl; o `ftp` não muda.
  Pôr uma interface numa VRF não move os serviços.
- **Junos**: `set system management-instance` cria `mgmt_junos`, e a fxp0/em0 vai para ela. NTP,
  RADIUS, TACACS+, syslog etc. apontam para ela um a um. Tudo num commit só, que derruba as
  sessões SSH (por isso o `commit confirmed`).
- **Cisco IOS-XE**: a VRF `Mgmt-intf` é só da GigabitEthernet0. Os serviços usam `vrf Mgmt-intf`
  ou `source-interface`, e a vty usa `access-class … vrf-also`.
- **Arista EOS**: `management ssh` e `management api http-commands` com `vrf <nome>`. O mesmo
  serviço pode rodar em várias VRFs ao mesmo tempo, cada uma com `shutdown` próprio.
- **Linux** (`docs.kernel.org/networking/vrf.html`): `SO_BINDTODEVICE` no dispositivo l3mdev por
  ouvinte, `tcp_l3mdev_accept` (padrão 0) e `ip vrf exec` (cgroup BPF; o CoreRouter não usa).

## Fica para depois

- **Um serviço em várias VRFs ao mesmo tempo** (EOS): hoje é uma VRF por serviço, como no
  RouterOS.
- **SSH**: o daemon ainda não tem servidor SSH (G0.8, pendente). Quando tiver, entra na mesma
  lista de `ip.service`.
- **Clientes da gerência** (NTP, syslog, RADIUS saindo pela VRF): parte já tem `vrf`
  (cliente NTP, RADIUS). O resto é gap à parte.
