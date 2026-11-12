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

| Teste | O que faz | O que mede |
|---|---|---|
| `qps` | 10 000 nomes quentes (cache), 1000 estáticos, uma zona de 10 000 registros, nomes únicos com a origem a 0 e a 20 ms, e uma mistura (85 % cache, 5 % estático, 5 % zona, 5 % miss); o cache padrão (2 MiB) à parte | consultas/s na saturação (8 sockets, 500 em voo cada) e p50/p99/p99,9 na metade dela (sem fila); CPU por grupo de threads (`dns-udp`, `dns-query`, as que terminaram) |
| `torture` | nomes únicos a 1000, 5000, 20 000/s e sem limite, com `max_concurrent_queries` 100 e 1000; um cliente legítimo do cache ao lado | respostas e SERVFAIL, consultas/s à origem, pico de threads e de RSS, o p99 e os SERVFAIL do cliente legítimo |
| `torture` (G4.1o) | o mesmo nome com TTL 0 a 500/2000/5000 por segundo, origem a 20 ms | consultas à origem por resposta (1,00 = nenhuma junção) |
| `torture` (flush) | `ip.dns.cache.flush` no meio de 20 000/s de nomes quentes | SERVFAIL e consultas à origem quando todo o cache vira miss junto |
| `origin` | o primeiro servidor some (descarte, sem ICMP); as duas origens somem; perda de 30 %; origem a 200 ms | o tempo da troca de servidor, serve-stale (RFC 8767) e cache de falhas (RFC 9520), pico de threads com tudo fora, a taxa de acerto com perda |
| `tcp` | `dnsperf -m tcp` com 4, 16 e 64 conexões de um endereço; slowloris de 4 endereços que reconecta; DoT e DoH de origem (Unbound) a 100/1000/5000 por segundo | perdas por conexão recusada, o cliente TCP legítimo durante o ataque, descritores; handshakes/s e latência do DoT/DoH |
| `cache` | encher até 1 M de entradas (cache de 1 GiB); `cache.print`, `statistics.print` e `cache.flush` com 20 000/s de nomes quentes ao lado; descarte num cache de 64 MiB cheio | memória por entrada (RSS de um daemon novo), tempo de cada comando e quanto ele segura o lock (p99,9 e máximo da carga ao lado), custo do descarte |
| `adlist` | uma lista de 1 M de nomes por HTTP; consultas quentes e bloqueadas; `ip.dns.adlist.reload` com carga | tempo até `loaded`, memória por nome, custo por consulta, efeito da recarga |
| `ddns` | duas zonas de 50 000 registros; RFC 2136 UPDATE (`dnsperf -u`) a 20/100/500 por segundo para uma delas; 20 000 clientes DHCP com nome (opção 12) a 1000/s; consultas à zona a 5000/s ao lado | UPDATEs/s e p99, bytes gravados em disco por UPDATE e por concessão (`/proc/<pid>/io`), latência das consultas à zona durante as mudanças (G4.1p, G4.1q) |
| `hostile` | lixo a toda velocidade de um endereço, com e sem o limite por cliente; ANY, TXT grande, A com 60 registros; um cliente fora do `allowed_from` | sem queda nem panic, o cliente legítimo ao lado, tamanho e TC das respostas (fator de amplificação), REFUSED sem consulta à origem |
| `ops` | 50 vezes cada: `ip.dns.set`, estático add+remove, `cache.flush`, `statistics.print`, um lote atômico, `ip.dns.get`, por uma conexão MCP aberta, com 20 000/s de nomes quentes ao lado | p50/p99 do comando (alvo < 50 ms) e o efeito na carga |
| `compare` | as mesmas medidas contra Unbound e dnsmasq, nas mesmas CPUs e com a mesma origem | consultas/s, latência, consultas à origem por resposta, memória por entrada |
| `soak` | a mistura a 10 000/s mais 50 nomes únicos/s por `--soak-secs` | por minuto: consultas/s, p99, RSS, threads, descritores, `cache_used` (`soak.csv`) |
