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

## Resultados (**medido**, 2026-11-12)

VM do laboratório: 8 vCPUs AMD EPYC-Genoa (KVM, `host-model`), 16 GiB, kernel 7.0, virtio; o
roteador em 2 ou 4 vCPUs, gerador e origem nas outras 4. Números de VM servem para comparar antes
e depois, não como número de produção (veja "Fase C"). **Antes** = o daemon da imagem G1.6zd (main
`d2a454d2`, raiz da imagem num chroot); **depois** = esta branch (`--daemon build`). Release nos dois.
As tabelas completas de cada rodada (`results.md`) ficam em `/srv/lab/dns-stress/` na VM. Rodada de
confirmação com a imagem e o roteiro final (`--host`, todos os testes menos `soak`, 2026-11-13):
**OK**, com uma linha LIMITE (o DHCP com nome na zona, G4.1p).

### Consultas por segundo (`qps`)

Saturação (8 sockets × 500 em voo, 15 s). Com 4 vCPUs o daemon abre 2 leitores UDP por família;
com 2 vCPUs, 1.

| Cenário | 2 vCPUs antes | 2 vCPUs depois | 4 vCPUs antes | 4 vCPUs depois | Latência a metade da saturação (4 vCPUs, depois): p50 / p99 |
|---|---|---|---|---|---|
| Acerto de cache (64 MiB) | 53,5 mil/s | 56,1 mil/s | 169 mil/s | 174 mil/s | 34 µs / 62 µs |
| Estático (1 de 1000) | 53,4 mil | 63,3 mil | 193 mil | 197 mil | 33 µs / 93 µs |
| Zona (1 de 10 000) | 56,5 mil | 61,4 mil | 184 mil | 168 mil | 34 µs / 287 µs |
| Miss, origem a 0 ms | 10,6 mil | 27,8 mil | 12,2 mil | **47,3 mil** | 175 µs / 479 µs |
| Miss, origem a 20 ms (NOERROR/s) | 4,8 mil | 4,9 mil | 6,2 mil | 5,0 mil | 20 ms (o resto SERVFAIL: o teto, abaixo) |
| Mistura (85 % cache) | 53,5 mil | 53,9 mil | 170 mil | 193 mil | 40 µs / 20 ms (os misses) |
| Acerto com o cache padrão de 2 MiB | 10,5 mil | 28,9 mil | 12,7 mil | 50,6 mil | 10 mil nomes quentes não cabem: viram miss |

- **O acerto de cache escala com os leitores** (~85 mil/s por leitor na VM; CPU das `dns-udp`
  perto de 100 % cada). O miss era o gargalo: **~210 µs de CPU por miss** (CPU do daemon / misses por segundo, VM) com uma
  thread criada por consulta; depois, ~67 µs (perfil: ~60 % em `pthread_create`, pilha, `mprotect`/`munmap` e arena do malloc,
  ~13 % na troca com o servidor). Com os workers reaproveitados: 12,2 → 47,3 mil misses/s.
- **O cache padrão de 2 MiB guarda 3 192 respostas** (o `cache_size` do RouterOS é em KiB; a conta
  é ~690 B por resposta). Um roteador de ISP precisa de dezenas a centenas de MiB.
- **Misses com a origem a 20 ms param em `max_concurrent_queries` / RTT** = 100 / 20 ms = 5 mil/s;
  o que passa disso recebe SERVFAIL na hora (o cliente tenta o outro servidor). Gap G4.1t.

### Tempestade de nomes únicos (`torture`), consultas iguais (G4.1o) e flush

| `max_concurrent_queries` | Ataque | Respostas NOERROR/s antes → depois | Threads (pico) antes → depois | Cliente legítimo: p99 / SERVFAIL em 15 s (depois) |
|---|---|---|---|---|
| 100 | 5000/s | 4,9 mil → 4,9 mil | 167 → 211 | 119 µs / 0 |
| 100 | 20 000/s | 4,8 mil → 4,5 mil | 169 → 211 | 20 ms / 15 399 |
| 1000 | 20 000/s | 8,7 mil (p50 573 ms) → **20 mil** (p50 20 ms) | 560 → 765 | 21 ms / 0 |
| 1000 | sem limite | 9,4 mil → 33 mil | 562 → 1087 | 160 ms / 10 144 |

- Com o teto padrão (100), a tempestade nunca passa de 5 mil/s à origem e o roteador segura; o
  preço é o cliente legítimo: **os nomes únicos despejam os quentes do cache** (25 045 SERVFAIL
  em 15 s para o cliente legítimo a 20 000/s de ataque, antes; 15 399 depois). Gap G4.1x.
- Com 1000, antes o roteador desabava (mil threads criadas e destruídas: 8,7 mil/s e p50 de
  573 ms); depois responde os 20 mil/s com p50 de 20 ms (a própria origem).

| O mesmo nome com TTL 0, origem a 20 ms | 500/s | 2000/s | 5000/s |
|---|---|---|---|
| Consultas à origem por resposta, antes | 1,00 | 1,00 | 0,98 |
| Depois (G4.1o) | 0,08 | 0,02 | 0,01 |
| Unbound 1.19.2 (`compare`) | | 0,09 | |
| dnsmasq 2.91 (rodada 1) | | 0,05 | |

Flush com 20 000/s de nomes quentes e origem a 20 ms: todo o cache vira miss junto; ~15 mil
SERVFAIL em 300 mil (o teto de 100 de novo) e 10 mil consultas à origem (uma por nome).

### Origem lenta, com perda ou fora do ar (`origin`)

| Caso | Resultado (antes e depois iguais) |
|---|---|
| O primeiro servidor some (descarte) | cada nome novo espera **2 s** (`query_server_timeout`) até o servidor ir para o fim da fila: 60 consultas de 2023–2070 ms nos 3 s seguintes, depois 5 ms |
| Resposta vencida, as duas origens fora | serve-stale funciona, mas só depois de todos os servidores falharem: **4,1 s** (a RFC 8767 §5.5 sugere 1,8 s); a segunda vez sai em 0 ms (falha guardada, RFC 9520) |
| Nome nunca visto, origens fora | SERVFAIL em 3,3–4,1 s; de novo: 0 ms, e nada vai à origem enquanto a falha está guardada |
| As duas origens fora, nomes únicos sem limite | só SERVFAIL, rápido (p50 15–21 ms); threads no teto (169 com 100, 1068 com 1000); o cliente legítimo do cache não sofre (p99 21–38 ms com a CPU cheia) |
| 30 % de perda nas respostas, 500/s | **só 24 % respondidas**, p99 4,1 s: cada perda espera 2 s por servidor segurando uma vaga |
| Origem a 200 ms | 1 mil NOERROR/s (100 / 0,2 s), o resto SERVFAIL |

Gaps G4.1u (prazo por servidor adaptativo e nova tentativa) e G4.1v (serve-stale em 1,8 s).

### TCP e DoT/DoH (`tcp`)

- **TCP** (G4.1w, **medido** na VM, 10 s cada): um endereço com 16 conexões perdia **54 %** e com
  64, 91 % (um quarto das 20 vagas: 5). Depois, com as mesmas 20 vagas, 16 conexões perdem 0,8 %
  (metade por endereço: 10); com o padrão novo de 100 (25 por endereço, RFC 9210 §4.5), 0,2 % e
  51 mil/s. 64 conexões de um endereço passam do teto de 25 e o roteador fecha as que sobram: o
  `dnsperf` não reabre e a janela trava (36 % perdidas com 100 vagas, 81 % com 20; antes 91 %).
- **Slowloris** (4 endereços × N conexões que mandam um byte e param, reabertas quando o roteador
  fecha; um cliente legítimo pergunta a cada 250 ms numa conexão nova):

  | Vagas | Por endereço | Antes: respondidas | Depois (G4.1w) | Reaberturas em 30 s, depois | CPU do daemon, depois |
  |---|---|---|---|---|---|
  | 20 | 10 | 0 de 107 | **107 de 107** | 5 312 | 1,2 s em 30 s |
  | 20 | 30 | 1 de 106 | **107 de 107** | 29 095 | 1,2 s |
  | 100 | 10 | 107 de 107 (não enche) | 108 de 108 | 100 | 0,9 s |
  | 100 | 30 | 0 de 107 | **107 de 107** | 6 119 | 1,0 s |

  Cheio, a conexão nova toma a vaga da mais ociosa do endereço com mais vagas (`dns_server/slots.rs`).
  As reaberturas são quase todas conexões recusadas no aceite (o endereço no teto), sem thread: o
  daemon gasta 3–4 % de um núcleo. Pico de 169 threads e 220 descritores com 100 vagas.
- **DoT de origem** (Unbound) a 5000/s: **antes** 26 607 SERVFAIL em 15 s, p99 492 ms e 930
  handshakes/s (com uma thread por miss, as consultas em voo passavam das 4 conexões guardadas);
  **depois** p99 0,77 ms e 22 handshakes/s.
- **DoH de origem**: **antes, 0 % respondido** (o DoH do Unbound só fala HTTP/2; o nosso HTTP/1.1
  levava um handshake por consulta e nenhuma resposta); **depois** (G4.1s, HTTP/2), 5000/s, p99
  0,70 ms, 1 handshake/s.

### Cache cheio (`cache`)

| Medida | Antes | Depois |
|---|---|---|
| Encher 1 M de nomes únicos (origem a 0 ms) | 76 s (13,1 mil/s) | 24 s (41,3 mil/s) |
| Memória por resposta no cache (RSS de um daemon novo) | 644 B | 707 B |
| `cache_used` (a conta do motor) para 1 M | 673 503 KiB | 673 503 KiB |
| `ip.dns.cache.flush` de 1 M: comando / carga ao lado p99,9 | 453 ms / **516 ms** | 661 ms / **21 ms** |
| `ip.dns.cache.print name=…` (1 M): comando / carga ao lado p99,9 | 177 ms / 160 ms | 179 ms / 164 ms |
| `ip.dns.cache.print limit=100000`: comando / p99,9 ao lado | 781 ms / 36 ms | 739 ms / 39 ms |
| `ip.dns.cache.print` (padrão, 1000 linhas) e `statistics.print` | 9–14 ms, nada ao lado | igual |

O flush parava toda consulta enquanto liberava 1 M de entradas sob o lock do resolvedor; agora o
mapa sai sob o lock (troca O(1)) e é liberado depois. O filtro por nome do `cache.print` ainda
varre tudo sob o lock (gap G4.1y). A conta do motor (`cache_size`) bate com a memória real (~690 B
por resposta).

### Adlist de 1 M de nomes (`adlist`)

Carga em 0,7–1,1 s, **55–57 B por nome**; a recarga (`ip.dns.adlist.reload`) com 20 000/s ao lado
não muda nada (p99,9 107 µs). Custo: o acerto de cache cai **14 %** com a lista (194 → 166 mil/s em
4 vCPUs), mais do que os 80–110 ns medidos na busca (gap G4.1z). Nomes bloqueados: 196 mil/s.

### Zonas, UPDATE e DHCP com nome (`ddns`, G4.1p e G4.1q)

As zonas têm no máximo 50 000 registros no total (`model::dns_zone::MAX_RECORDS`): `dyn.lab` com
40 000 (a que muda) e `other.lab` com 9 980 (só está lá). Depois (esta branch; o caminho das zonas
não mudou):

| Carga | Consultas à zona a 5000/s: p50 / p99 / máx. | UPDATEs aceitos/s, p99 | Escrita por UPDATE |
|---|---|---|---|
| Sem UPDATE (saturação) | 188 mil/s; p50 2,7 ms na fila | - | - |
| UPDATE a 20/s | **88 ms / 225 ms / 534 ms** | 6/s, 4,3 s | 10 KiB |
| UPDATE a 100/s | 92 / 180 / 192 ms | 6/s, 4,1 s | 26 KiB |
| UPDATE a 500/s | 92 / 180 / 196 ms | 6/s, 4,1 s | 41 KiB |

Tempestade de DHCP (20 000 clientes com nome a 1000/s, a zona recebendo o A de cada concessão):
**9 447 concessões em 55 s** (~170/s) e as consultas à zona com p99 de 221 ms; ~3 KiB gravados
por concessão. Sem nome na zona, o mesmo servidor ligou 20 000 clientes a 10 000/s em 2 s (G3.9h,
`docs/perf.md`): ~60× mais. Uma mudança
nas zonas custa uma reconstrução de todas elas (G4.1p) e a regravação de todos os registros
dinâmicos (G4.1q), numa thread só, e as consultas à zona esperam por isso. **É o maior limite que
a bateria achou**: um ISP que publica o nome de cada concessão não aguenta uma volta de energia
(todos os clientes renovando juntos). As duas gaps ganharam esses números.

Onde vai o tempo (`PERF=update-100 scripts/dns-stress-lab.sh --tests ddns`, perfil do daemon durante
os UPDATEs): reconstruir e comparar a zona inteira a cada mudança (hash de `String` ~12 %,
codificação dos registros no Hickory ~11 %, ordenação canônica de todos os nomes ~11 %,
`zone::diff` ~4 %). A gravação do JSON dos registros dinâmicos (G4.1q) quase não aparece na CPU:
a correção que muda o quadro é a G4.1p (reconstruir só o que mudou, fora do caminho da consulta).

Carga das zonas por `ip.dns.zone.file.load`: 311 ms para 9 980 registros e 1,07 s para 40 000.

### Entrada hostil (`hostile`)

- Lixo a 60 mil/s (limite padrão de 200 consultas/s por cliente) e a 185 mil/s (sem limite) de um
  endereço: nenhuma queda nem panic; o cliente legítimo ao lado: p99 151 µs com o limite padrão,
  20 ms sem ele (o lixo que parece consulta vira miss). As mensagens acima do limite são descartadas
  e contadas (`limit` no `ip.dns.statistics.print`).
- ANY é respondido com um registro (RFC 8482: resposta mínima), 50–61 bytes; TXT de 3,8 KB vem
  truncado (TC) em 28–39 bytes, também com EDNS de 4096 (o `max_udp_packet_size` padrão é 1232); um A
  com 60 registros cabe em 1000 bytes (fator 25 sobre a pergunta, só para quem está no
  `allowed_from`).
- Fora do `allowed_from`: REFUSED (27–40 bytes) e **nenhuma consulta à origem**: não é resolvedor
  aberto (RFC 5358).

### Operação com carga (`ops`)

50 vezes cada comando por uma conexão MCP aberta, com 20 000/s de nomes quentes ao lado (depois):

| Comando | p50 | p99 (= máx.) |
|---|---|---|
| `ip.dns.set` | 19 ms | 29 ms |
| `ip.dns.static.add` + `remove` | 39 ms | 147 ms |
| `ip.dns.cache.flush` | 12 ms | 18 ms |
| `ip.dns.statistics.print` | 10 ms | 13 ms |
| lote atômico (`static.add` + `ip.dns.set`) | 19 ms | 130 ms |
| `ip.dns.get` | 10 ms | 13 ms |

A carga ao lado não sente nenhum (p99,9 ≤ 17 ms; o flush e o statistics.print repetidos 50 vezes
trocam os acertos por misses, que é o esperado). O alvo de 50 ms (G4.2h) passa no p50 de todos;
os dois comandos que mudam a config tiveram uma amostra acima (130–147 ms) em 50, nas duas rodadas.

### Comparação com Unbound e dnsmasq (`compare`, G4.1g)

Mesmas 4 vCPUs, mesma origem e mesmo gerador; CoreRouter desta branch com `max_concurrent_queries`
1000 e cache de 1 GiB; Unbound 1.19.2 com `num-threads` 4 e `so-reuseport`; dnsmasq 2.91 (uma
thread) com `cache-size` 10 000 (o teto dele) e `dns-forward-max` 1000. Duas rodadas (faixa).

| Medida | CoreRouter | Unbound | dnsmasq |
|---|---|---|---|
| Cache quente, saturação | 193–198 mil/s | 280–344 mil/s | 87–127 mil/s |
| Cache quente a 50 000/s: p50 / p99 | 40 / 59–60 µs | 38–42 / 60–67 µs | 39–367 µs / 0,1–4,2 ms |
| Misses, origem a 20 ms, saturação | 29–45 mil/s (+ SERVFAIL no teto) | 42–45 mil/s | 3,5–4,5 mil/s (17–21 % perdidas) |
| Misses a 5000/s: p50 / p99 | 63–65 µs / 20 ms | 57–81 µs / 20 ms | 55 / 68 ms |
| O mesmo nome TTL 0 a 2000/s: à origem por resposta | **0,02** | 0,07–0,09 | 0,05 |
| Memória por resposta (10 000 nomes, RSS) | ~1,3 KB (inclui pilhas dos workers; ~700 B com 1 M) | ~700 B | pré-alocado |

Antes desta branch (rodada 1, daemon da imagem), o miss na saturação era 10,2 mil/s com p50 de
492 ms e o TTL 0 ia 1,00 à origem por resposta. A decisão do Hickory, revista com esses números,
está em `docs/architecture.md` ("DNS (G4.1)").

### Estabilidade (`soak`)

A mistura a 10 000/s (85 % cache, 5 % estáticos, 5 % zona, 5 % nomes que expiram em 5 min) mais
50 nomes únicos por segundo, origem a 5 ms, cache de 64 MiB, 2 h, uma medida por minuto.

| | VM, 4 vCPUs (esta branch) | Host, namespace de usuário, 4 CPUs |
|---|---|---|
| Minutos | 120 | 120 |
| SERVFAIL / perdidas | 0 / 0 | 0 / 0 |
| p50 / p99 (cada minuto) | 43–131 µs / 5,2–6,4 ms | 10–335 µs / 5,1–7,6 ms (um minuto com 72 ms: outra rodada minha disputando o host) |
| RSS | 111 MiB → 161 MiB quando o cache encheu (30 min) → **166 MiB** no fim | 104 → 158 MiB (cheio) → 97–111 MiB |
| Threads | 120 → 129 (um pico de misses; ficam) | 125 → 163 (idem) |
| Descritores | 20–21 | 20–22 |

O p99 é o dos misses (a origem a 5 ms) e não deriva. O RSS para de crescer com o cache cheio, mas
na VM subiu mais 4 MiB em 90 min (~2,7 MiB/h, **medido**): provavelmente o alocador com o despejo
contínuo; **a observar nas 12 h da fase C** (uma reta de 2,7 MiB/h daria ~32 MiB em 12 h). As threads
a mais são workers criados num pico de misses: com carga contínua cada um é acordado antes de 10 s
ocioso e não termina; o teto é `max_concurrent_queries`.

## Defeitos e limites achados

| Achado (**medido**) | Estado |
|---|---|
| Uma thread criada e destruída por miss: ~210 µs de CPU por miss, 12,2 mil misses/s em 4 vCPUs | **corrigido** (workers reaproveitados): 47,3 mil/s |
| Consultas iguais fora do cache: uma consulta à origem por resposta (G4.1o) | **corrigido**: 0,02 |
| `ip.dns.cache.flush` com 1 M de entradas parava toda consulta por ~0,5 s | **corrigido**: p99,9 ao lado 21 ms |
| DoH contra servidor que só fala HTTP/2 (Unbound): 0 % respondido | **corrigido** (G4.1s): 100 %, p99 0,7 ms a 5000/s |
| UPDATE e DHCP com nome reconstroem todas as zonas: 6 UPDATEs/s, ~170 concessões/s, consultas à zona com p50 ~90 ms | gap G4.1p (com o perfil) e G4.1q |
| Misses limitados a `max_concurrent_queries` / RTT; com 1000, mil threads | gap G4.1t |
| 30 % de perda: 24 % respondidas; troca de servidor custa 2 s por nome novo | gap G4.1u |
| Serve-stale só em 4,1 s (a RFC 8767 sugere 1,8 s) | gap G4.1v |
| Slowloris de 4 endereços derruba o TCP (0–1 de 108); 16 conexões de um endereço perdem 54 % | **corrigido** (G4.1w): 107 de 107; 0,8 % |
| Nomes únicos despejam os quentes: até 25 mil SERVFAIL em 15 s para o cliente legítimo | gap G4.1x |
| `cache.print name=…` com 1 M de entradas para as consultas por 160 ms | gap G4.1y |
| A adlist de 1 M custa 14 % no acerto de cache | gap G4.1z |
| O cache padrão de 2 MiB guarda 3 192 respostas | o padrão do RouterOS; vale dizer no ⓘ do `cache_size` |
| RSS +2,7 MiB/h com o cache cheio (2 h na VM) | a observar nas 12 h da fase C |
| Defeitos do próprio roteiro achados no caminho: `kdig` com opções do `dig`, Unbound barrado pelo AppArmor fora de `/etc/unbound`, teto de 50 000 registros no total das zonas, `$EPOCHREALTIME` com vírgula em pt_BR | corrigidos no roteiro |

## Fase C: o notebook

O roteiro já roda contra um roteador remoto (`--dut remote`); quem o roda é a sessão principal,
depois da fase C do OSPF. Checklist:

1. O cabo do `eno1` do host é macvtap da VM do laboratório; dentro da VM ele aparece como uma
   interface (`ip -br link` na VM); essa é a `--iface`. Do lado do notebook, a porta do cabo é a
   `--dut-iface` (**nunca** o `ether1`, que está na rede de casa e só pode ser cliente: a carga
   nunca entra por ele).
2. O notebook precisa de um endereço de gerência alcançável pelo cabo (`--target`, TLS na 8729) e
   a VM de um endereço na mesma rede (`--mgmt <cidr>`). O roteiro põe `10.53.0.1/24` na porta do
   cabo e a config de DNS do laboratório; anota a revisão antes (`config.history`) e faz
   `config.rollback` para ela no fim, mesmo com falha.
3. O firewall do notebook precisa aceitar UDP/TCP 53 vindo de `10.53.0.0/24` na porta do cabo
   (o `allowed_from` do laboratório é `10.53.0.0/25`).
4. Sugestão de rodada: `--tests qps,torture,origin,tcp,cache,hostile,ops` e depois
   `--tests soak --soak-secs 43200` (12 h). `compare` não roda remoto (só local).
5. Sem CPU por thread pelo `/proc` no remoto: o roteiro usa `system.resource.process.print
   threads=yes` (o instantâneo no fim de cada medição) e o RSS/threads/descritores dele.

Conferido: `--selftest-remote` (o modo remoto contra um DUT local, por TLS) rodou `qps` e `hostile`
inteiros com o rollback no fim.

## Pesquisa

- **MikroTik RouterOS v7** (`/ip dns`, help.mikrotik.com/docs/spaces/ROS/pages/37748767/DNS):
  `max-concurrent-queries` 100, `max-concurrent-tcp-sessions` 20, `cache-size` 2048 **KiB**,
  `query-server-timeout` 2 s, `query-total-timeout` 10 s; a documentação não diz o que acontece ao
  passar dos limites (nós respondemos SERVFAIL na hora e contamos, `busy`). Relato de campo: Chrome
  com 3 conexões TCP/53 simultâneas falhava no 7.19.1 (forum.mikrotik.com, tópico 183935): o nosso
  teto por endereço (5) aceita.
- **Unbound** (unbound.docs.nlnetlabs.nl): consultas iguais juntadas no "mesh" (uma por nome, tipo,
  classe e flags; só no código, `services/mesh.c`); `num-queries-per-thread` 2048 por thread (laço
  de eventos, não thread por consulta); serve-expired no modo da RFC 8767 só é padrão a partir do
  1.23 (`serve-expired-client-timeout` 1800 ms); memória real ~2–2,5× o configurado. O DoH dele só
  fala HTTP/2.
- **dnsmasq** (thekelleys.org.uk): junta consultas iguais desde o 2.83 (CVE-2020-25686, DNSpooq);
  `dns-forward-max` 150; `cache-size` com teto rígido de 10 000 nomes; uma thread.
- **Knot/NSD/BIND como origem**: Knot e NSD passam de 1 M consultas/s em 16 núcleos, o BIND fica
  ~10× abaixo (Lencse, IEEE Access 2020); Knot 3.3 tem pacote no Ubuntu 24.04 e zona curinga.
- **RFCs**: 5452 §5 (consultas iguais pendentes e o ataque do aniversário; a norma está em §9.2:
  porta e id imprevisíveis), 8767 §5 (serve-stale: 1,8 s para responder o vencido, 30 s de TTL),
  9520 §3 (cache de falhas: 1 s a 5 min, não perguntar enquanto guardada, até 3 tentativas), 7766
  §6.2 (TCP: vários pedidos por conexão, idle de segundos, timeout zero sob carga), 9210 (TCP
  obrigatório; §4.5: 25 conexões por endereço, idle 10 s), 8906 §3.1.1 (nunca deixar sem
  resposta), 5358 (não ser resolvedor aberto), 8482 (ANY mínimo), 8484 §5.2 (DoH: HTTP/2
  recomendado), 9113 (HTTP/2) e 7541 (HPACK; os exemplos do Apêndice C viraram testes).
- **Gerador**: dnsperf 2.14.0 (sem saída JSON, que veio no 2.15; o histograma de conexões do 2.14
  repete o de respostas, e o roteiro só lê o primeiro).

O que adotamos: os nomes e padrões do RouterOS ficam; o que o Unbound faz melhor virou correção
(junção de iguais, workers sem criar thread, HTTP/2) ou gap com número (laço de eventos, prazo
adaptativo, serve-stale em 1,8 s, cache protegido, TCP contra slowloris).

## Desempenho e paralelismo

- **Trabalho por item.** Por consulta respondida do cache: ~1 µs na cadeia (G4.1b) mais o socket;
  na VM, ~85–95 mil/s por leitor `dns-udp`, com a CPU de cada leitor perto de 100 %. Por miss:
  antes ~210 µs de CPU na VM (a thread criada e destruída), depois ~67 µs (troca com o servidor, socket
  por consulta para porta imprevisível, RFC 5452). Nada cresce com o total por item, exceto o que
  virou gap: o filtro por nome do `cache.print` (varre o cache inteiro, G4.1y) e a reconstrução de
  todas as zonas a cada UPDATE (G4.1p).
- **Paralelismo.** Os leitores UDP já são vários por socket (o kernel entrega cada datagrama a um
  leitor que espera); o acerto de cache escalou de 1 para 2 leitores (56 → 174 mil/s, 2 → 4
  vCPUs). O lock do resolvedor (cache) é curto e não apareceu como gargalo até 200 mil/s; o
  Unbound faz 1,4–1,8× mais no acerto porque usa todas as CPUs (`SO_REUSEPORT`, uma thread por
  CPU), e nós metade por escolha (G0.31). Os misses esperam a rede em workers paralelos até
  `max_concurrent_queries`; o teto real é esse número sobre o RTT (G4.1t). A junção de iguais tira
  trabalho repetido; o mapa dela tem um lock próprio, tomado duas vezes por miss (+0,24 µs).
- **Filas.** O pool de workers não tem fila sem teto: o portão `max_concurrent_queries` limita os
  jobs (acima dele, SERVFAIL na hora, contado como `busy`); um worker ocioso por 10 s termina.
