# DNS sob carga (G4.1r)

Bateria de carga e estabilidade do servidor DNS do CoreRouter: o encaminhador da LAN (G4.1b), o
resolvedor e o cache (G4.1a), estáticos, zonas e DNS dinâmico (G4.1c), adlist e DoT/DoH de origem
(G4.1d). No mesmo molde da bateria do OSPF (`docs/ospf-stress.md`): um roteiro repetível
(`scripts/dns-stress-lab.sh`), números **medidos**, limites e defeitos, e as gaps que saíram.

## Como rodar

```sh
# Na VM do laboratório, com a raiz da imagem (root só lá dentro):
scripts/dns-stress-lab.sh --host /srv/build/os-out/<build>/build/images [--tests qps,torture,…]
# A mesma bateria com o daemon desta worktree (antes/depois de uma correção):
cargo xtask vm-lab run --lock-timeout 4h -- scripts/dns-stress-lab.sh --daemon build
# Sem a VM, num host sem root (namespaces de usuário; ferramentas dos .deb do Ubuntu):
scripts/dns-stress-lab.sh --userns --tools /srv/build/g41r-tools/root --daemon build
# Fase C: o roteador é outra máquina, ligada por cabo à interface <if> da VM:
scripts/dns-stress-lab.sh --dut remote --iface <if> --target <ip-de-gerência> \
  --mgmt <cidr-na-ponta-da-VM> --dut-iface <porta-do-cabo-no-roteador> --tests qps,torture,soak \
  --soak-secs 43200
```

Os resultados ficam em `$OUT/results.md` (uma tabela por teste), `$OUT/raw/` (a saída de cada
`dnsperf`) e `$OUT/soak.csv`; o código de saída é 1 se uma checagem falhou. `--tests` escolhe os
testes (padrão: todos menos `soak`), `--duration` a duração de cada medição (15 s), `PERF=<regex>`
grava um `perf record -g` do daemon nas medições cujo nome casa.

**Ferramentas** (todas de pacotes do Ubuntu 24.04, instalados pelo roteiro dentro da VM se
faltarem; no host, `apt-get download` e `dpkg -x` numa pasta, sem root):

| Papel | Escolha | Por quê |
|---|---|---|
| Gerador | `dnsperf` 2.14.0 (DNS-OARC) | Em C, vários sockets e threads; o gerador em Python da G3.9h parou em ~1,2 M/s. Latência por histograma (`-O latency-histogram`, baldes de ~3 %): p50/p99/p99,9 pela soma acumulada. |
| Origem | Knot DNS 3.3.4, autoritativo | Mais rápido que o necessário (Knot e NSD passam de 1 M/s; o BIND fica ~10× abaixo), zona curinga (`*.wt.up.lab`: qualquer nome único existe), carga de zona grande em segundos. Nunca um DNS público ou do provedor. |
| Atraso e perda | `tc netem` só nas respostas da origem | Um `prio` com filtro pelo endereço da origem: o tráfego dos clientes nunca atrasa. |
| DoT/DoH de origem | Unbound 1.19.2 na frente do Knot | Serve DoT (853) e DoH (443, só HTTP/2) com um certificado autoassinado. |
| Comparação | Unbound 1.19.2 e dnsmasq 2.91 | Os encaminhadores mais usados em roteadores (OPNsense/pfSense, OpenWrt). |
| Contagem na origem | `nft` (contadores por endereço) | Prova da junção de consultas iguais e de que um cliente de fora não faz o roteador perguntar nada. |

**Topologia.** Um segmento `10.53.0.0/24`: o roteador em `.1` (`ether1`), os clientes em `.2`–`.9`,
um cliente fora do `allowed_from` em `.200`, o Knot em `.53` e `.54` (dois "servidores"), o
Unbound em `.55`, a adlist por HTTP em `.56`. Local: roteador no namespace `crdut` (a raiz da
imagem num chroot, ou o daemon desta worktree), laboratório no namespace `crgen`, ligados por um
veth, cada um preso às suas CPUs (`--dut-cpus`, `--gen-cpus`). O número de threads `dns-udp` segue
as CPUs que o daemon vê (metade, de 1 a 4 por família): `--dut-cpus-list "0-1;0-3"` mede 1 e 2.

**Fase C (o notebook).** `--dut remote`: clientes e origem ficam na VM, na interface ligada pelo
cabo (`--iface`, levada para o `crgen` durante a rodada e devolvida no fim); os comandos vão por
TLS como `admin` (`$COREROUTER_PASSWORD`). A config de teste entra com o roteador anotando a
revisão (`config.history`) e sai com `config.rollback` para ela no fim. A porta do cabo é
`--dut-iface`: **nunca** a porta da rede de casa (o `ether1` do notebook é só cliente). No modo
remoto não há CPU por thread nem `perf` (só o `system.resource.process.print threads=yes`), nem a
comparação com Unbound/dnsmasq. `--selftest-remote` roda o modo remoto contra um DUT local.

## O que cada teste mede
