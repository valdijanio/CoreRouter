# Desempenho (medições)

Regra em `AGENTS.md`, "Desempenho e escolha de implementação". Cada número diz se é **medido**
(com máquina, build e data) ou **estimado**. Os benchmarks são do G0.9: `cargo xtask bench`
(criterion 0.8, dev-dependency só dos crates medidos; fora do build normal e do wasm).

Medições novas entram pela seção `## perf` do arquivo de mudança do PR (`docs/changes/`), que a
fila de entrada acrescenta no fim deste arquivo; não o edite à mão (conflito entre PRs).

## Como rodar

```sh
cargo xtask bench                  # tudo (~5 min nesta máquina), compara com a rodada anterior
cargo xtask bench --quick          # rodadas curtas (~2 min), para olhar tendência
cargo xtask bench control          # só os benchmarks cujo id contém "control" (regex do criterion)
cargo xtask bench --markdown       # também imprime a tabela abaixo pronta para colar aqui
cargo xtask bench --check          # compila em debug e roda cada benchmark uma vez (sem medir)
```

O xtask compila todos os alvos `benches/` uma vez (`cargo bench --workspace --no-run`), roda cada
binário e no fim imprime **um resumo**: mediana, intervalo de confiança de 95%, tempo por item
(quando o benchmark declara N itens) e a variação contra a referência. Os dados ficam em
`<target>/criterion` no formato do próprio criterion. Alvos `netns_*` (hoje
`hal-linux/benches/netns_apply.rs`) rodam num user + network namespace descartável, sem root,
como o `cargo xtask netns`; onde o `unshare` sem root não é permitido eles viram aviso de
"skipped" e o resto roda.

## Antes e depois (o que vai na seção "Desempenho" do PR)

```sh
git switch main && cargo xtask bench --save-baseline antes   # guarda a referência "antes"
git switch <sua-branch> && cargo xtask bench --baseline antes # compara, sem sobrescrever
```

A coluna `change` do resumo é a variação da mediana contra `antes` (sem `--baseline`, contra a
rodada anterior). `--save-baseline` e `--baseline` aceitam qualquer nome (letras, dígitos, `-_.`).
Cole as linhas que mudaram no PR, com a máquina.

**Ruído:** nesta máquina (desktop, outras sessões rodando) duas rodadas seguidas do mesmo código
variaram até ~16% num benchmark (`engine_execute/ip.address.add`: −15,9% entre a rodada `--quick`
e a completa) e até +26% num de 170 ns (`dhcpv4/raw_options_ack`) — **medido**, 2026-10-22. Trate
variação abaixo de ~15% como ruído, a não ser que se repita em rodadas seguidas; para decidir,
rode antes e depois na mesma máquina, em sequência, sem outra carga. O CI **não** roda nem
reprova por benchmark (máquinas compartilhadas variam mais ainda).

## O que cada benchmark mede

| Prefixo do id | Onde | O que mede |
|---|---|---|
| `control/{tcp,tls}/ping` | `crates/control/benches/control.rs` | Uma requisição numa conexão persistente em loopback: só transporte (TCP com token local; TLS depois do login) |
| `control/{tcp,tls}/interface.list` | idem | `engine.execute interface.list` pelo canal: transporte + autorização + motor + JSON das 8 portas |
| `engine_execute/*` | `crates/engine/benches/execute.rs` | `Session::execute` no lab virtual, sem transporte; os `add` partem de um lab novo a cada iteração (montado fora do tempo) |
| `hal_virtual_apply/{addresses,routes,filter_rules}/N` | `crates/hal/benches/apply.rs` | `VirtualHal::apply` de N itens (N = 100, 1000): diff + render do firewall |
| `hal_linux_apply/{addresses,routes,filter_rules}/N` | `crates/hal-linux/benches/netns_apply.rs` | A mesma mudança no kernel: endereços e rotas por rtnetlink, regras por `nft -f` (uma transação); cada iteração aplica a partir da base e desfaz fora do tempo |
| `dhcpv4/*` | `crates/proto-dhcp/benches/codec.rs` | Encode de um DISCOVER, decode do ACK do servidor do lab (opções 1, 3, 6, 15, 42, 51, 54, 121), leitura crua das opções, recusa de lixo |
| `lldp/*`, `crdp/*`, `mndp/decode` | `crates/proto-{lldp,discovery,mndp}/benches/codec.rs` | Encode/decode de um pacote típico (MNDP só decode: nunca enviamos MNDP) |

SFF (módulos SFP/DOM) ainda não tem codec no workspace; o benchmark entra com ele (G1.20). Os
fixtures de N itens ficam em `crates/hal/benches/common/mod.rs`, incluído pelos dois benchmarks
de apply, para que o lab e o kernel meçam exatamente a mesma mudança.

## Resultados

Máquina A: AMD Ryzen AI MAX+ 395 (32 CPUs lógicas), 62 GiB, Linux 7.0.0-38-generic,
rustc 1.99.1; build release do workspace (`lto = "thin"`, `codegen-units = 1`); `cargo xtask
bench` completo (criterion padrão: 100 amostras, 5 s; apply no kernel: 10 amostras planas);
2026-10-22. Todos **medidos**.

| Benchmark | Mediana | IC 95% | Por item |
|---|---|---|---|
| `control/tcp/ping` | 7.36 µs | 7.28–7.47 µs | — |
| `control/tls/ping` | 8.32 µs | 8.25–8.36 µs | — |
| `control/tcp/interface.list` | 45.3 µs | 45.1–45.8 µs | — |
| `control/tls/interface.list` | 48.1 µs | 47.8–48.5 µs | — |
| `engine_execute/interface.list` | 8.31 µs | 8.29–8.32 µs | — |
| `engine_execute/ip.address.list` | 522 ns | 522–523 ns | — |
| `engine_execute/ip.address.add` | 16.0 µs | 16.0–16.1 µs | — |
| `engine_execute/ip.firewall.filter.add` | 22.7 µs | 22.6–22.7 µs | — |
| `engine_execute/rejected_param` | 779 ns | 769–791 ns | — |
| `engine_execute/virtual_lab_new` | 3.42 µs | 3.41–3.43 µs | — |
| `hal_virtual_apply/addresses/100` | 2.07 µs | 2.06–2.07 µs | 20.7 ns |
| `hal_virtual_apply/addresses/1000` | 17.9 µs | 17.9–17.9 µs | 17.9 ns |
| `hal_virtual_apply/routes/100` | 519 ns | 513–521 ns | 5.19 ns |
| `hal_virtual_apply/routes/1000` | 3.94 µs | 3.92–3.97 µs | 3.94 ns |
| `hal_virtual_apply/filter_rules/100` | 77.4 µs | 77.1–77.7 µs | 774 ns |
| `hal_virtual_apply/filter_rules/1000` | 791 µs | 788–793 µs | 791 ns |
| `hal_linux_apply/addresses/100` | 1.93 ms | 1.92–1.97 ms | 19.3 µs |
| `hal_linux_apply/addresses/1000` | 24.9 ms | 23.9–32.9 ms | 24.9 µs |
| `hal_linux_apply/routes/100` | 2.10 ms | 2.04–2.22 ms | 21.0 µs |
| `hal_linux_apply/routes/1000` | 19.4 ms | 19.2–19.6 ms | 19.4 µs |
| `hal_linux_apply/filter_rules/100` | 21.7 ms | 19.3–23.3 ms | 217 µs |
| `hal_linux_apply/filter_rules/1000` | 33.5 ms | 31.7–34.9 ms | 33.5 µs |
| `dhcpv4/encode_discover` | 314 ns | 313–314 ns | — |
| `dhcpv4/decode_ack` | 572 ns | 568–574 ns | — |
| `dhcpv4/raw_options_ack` | 171 ns | 170–171 ns | — |
| `dhcpv4/decode_junk` | 18.4 ns | 18.3–18.6 ns | — |
| `lldp/encode` | 141 ns | 141–142 ns | — |
| `lldp/decode` | 142 ns | 141–142 ns | — |
| `crdp/encode` | 126 ns | 125–127 ns | — |
| `crdp/decode` | 137 ns | 132–139 ns | — |
| `mndp/decode` | 92.1 ns | 91.0–93.2 ns | — |

### Medições anteriores ao G0.9

| O quê | Resultado | Tipo | Como / onde | Data |
|---|---|---|---|---|
| Canal de controle: uma requisição em conexão persistente (loopback, TCP) antes da correção | ~41 ms (Nagle + ACK atrasado; ~83 ms ida e volta pela CLI) | medido | cliente Python persistente; `corerouter-cli` | 2026-10-22 |
| Canal de controle: idem depois da correção (escrita única + `TCP_NODELAY`) | ~19 µs (build de teste, mediana de 40; em release é o `control/tcp/ping` acima, 7.4 µs) | medido | PR #25 (G0.3), teste de latência em `crates/control` | 2026-10-22 |
| `Session::execute` de um comando simples (motor) | < 1 ms (substituído pelos `engine_execute/*` acima) | medido (grosseiro) | ida e volta no loopback sem rede | 2026-10-22 |

## O que os números dizem (máquina A)

- **Canal de controle:** o transporte custa ~7 µs por requisição; TLS soma ~1 µs. A trava contra
  regressão continua sendo o teste de latência de `crates/control/tests/tcp.rs` (limite folgado
  de 5 ms, 650× o medido).
- **`interface.list` pelo canal (45 µs) custa ~30 µs a mais que transporte (7 µs) + motor
  (8 µs).** Ainda não está decomposto: candidatos são a autorização por token a cada requisição
  e o JSON das 8 portas (servidor serializa, cliente faz parse). Vale medir antes de otimizar.
- **Motor:** um `add` com commit imediato (validação, journal, revisão, apply no lab) fica em
  16–23 µs, ou seja ~45 mil comandos/s numa thread; erro de parâmetro sai em < 1 µs.
- **Kernel, netlink:** ~19–25 µs por endereço ou rota, linear de 100 a 1000 (uma requisição com
  ACK por item). Aplicar 1000 rotas leva ~19 ms.
- **Kernel, nftables:** o `nft -f` tem custo fixo de ~20 ms por apply (processo + parse +
  transação; 100 regras = 21.7 ms) e ~13 µs por regra a mais (1000 regras = 33.5 ms). Até
  milhares de regras o custo fixo domina. É o dado para a futura decisão "binário `nft` × netlink
  de nftables em Rust" (não decidida aqui; ver a regra do AGENTS.md).
- **Codecs:** 0,1–0,6 µs por pacote (1,7–11 milhões de pacotes/s numa thread); lixo é
  recusado em ~18 ns. Muito acima de qualquer taxa real de DHCP, LLDP ou descoberta.

## Decisões tomadas com base nestes números

- Canal de controle síncrono, uma escrita por linha e `TCP_NODELAY` em todo socket (G0.3).
- G0.9: `cargo xtask bench --check` entra no `cargo xtask ci` como passo `bench-check` (ver
  "Custo no CI" abaixo): os benchmarks são compilados **e executados uma vez** em debug, então um
  parâmetro de comando renomeado ou um fixture quebrado falha no CI em vez de apodrecer.

## Custo no CI

Medido na máquina A, 2026-10-22, num target dir vazio, na ordem do `cargo xtask ci`:

| Passo | Tempo |
|---|---|
| `clippy --workspace --all-targets` (já faz o type-check dos benchmarks) | 15.5 s |
| `test --workspace` | 52.2 s |
| `bench-check` = `test --workspace --bench '*'` depois do `test` (compila criterion e os 8 binários em debug, roda cada benchmark uma vez) | 10.5 s, dos quais ~0,2 s de execução |

São ~15% a mais sobre clippy + test (o passo `netns` e o `wasm` vêm depois e não mudam). Entrou,
porque compilar só (o que o clippy já faz) não pega um benchmark que dá panic ao rodar. O
benchmark do kernel (`netns_apply`) só imprime "skipped" no `bench-check`; ele roda de verdade no
`cargo xtask bench`.

## CI e build (processo, 2026-10-22)

**Medido** no GitHub Actions (`ubuntu-latest`), job `xtask ci (linux)`, antes desta mudança:

| Passo | Run de PR | Run da `main` |
|---|---|---|
| Carregar o módulo `vrf` | 416 s (instalou `linux-modules-extra`) | 18 s (`modprobe` direto) |
| Dependências de sistema (`apt`) | 114 s | 14 s |
| Restaurar o cache (`rust-cache`, ~2,5 GB) | 70 s | 68 s |
| `cargo xtask ci` | 160 s | 147 s (test 67 s, netns 57 s) |
| **Total do job** | **775 s** | **264 s** |

Mudanças: o `vrf.ko` sai do `.deb` baixado em vez de instalar o pacote; sem debuginfo no CI
(`CARGO_PROFILE_{DEV,TEST}_DEBUG=0`), para encolher o cache e o link; `cargo nextest` no passo
`test` (os binários rodam em paralelo), com `cargo test --doc` só quando existe doctest (hoje
nenhum: os 20 `rustdoc` custavam 17 s para nada).

**Medido** nesta máquina (32 núcleos, build dev já compilado, 2026-10-22):

| | Antes | Depois |
|---|---|---|
| Testes do workspace | `cargo test` 29,7 s | `cargo xtask test` (nextest) 14,3 s |
| Testes em namespace (11 binários, 38 testes) | um após o outro, 33–36 s | em paralelo, ~9 s |

**`sccache` não foi adotado** (medido, workspace inteiro com testes, pasta de build nova como a
de uma sessão em paralelo): sem `sccache` 27 s; `sccache` frio 34 s; `sccache` quente em outra
pasta 36 s, com 0% de acerto em Rust. Ele não reaproveita entre caminhos de saída diferentes nem
crates com compilação incremental, e o build já é curto. No CI, o `rust-cache` restaura o
`target` inteiro de uma vez. Rever se as builds ficarem longas.

Os testes em namespace (`cargo xtask netns`) compilam uma vez (`cargo test --no-run`) e rodam os
11 binários ao mesmo tempo, cada um no seu namespace descartável, com a saída agrupada por
binário. No CI, os pacotes do `apt` vêm de cache (`cache-apt-pkgs-action`): o `apt-get update`
variava de 14 s a 114 s conforme o espelho.

**Pasta de build por sessão** (**medido**, `cargo xtask ci` do zero numa pasta nova, 32 núcleos,
2026-10-22): com debuginfo completo, 15 GB e 163 s; com `debug = "line-tables-only"` no nosso
código e sem debuginfo nas dependências (`[profile.dev]` do `Cargo.toml`), 6,6 GB e 135 s. Dos
6,6 GB, 2,1 GB são os 87 executáveis de teste (cada arquivo de `tests/` vira um binário com o
workspace inteiro) e 1,7 GB o cache incremental.

**Bateria da fila de entrada** (**medido**, 2026-10-22; 10 features sintéticas, 32 núcleos aqui,
GitHub Actions conta grátis):

| Fase | Resultado |
|---|---|
| 10 `cargo xtask ci` ao mesmo tempo (como 10 sessões; `CARGO_INCREMENTAL=0`) | 346 s no total (uma sozinha: 135 s); 4,6 GB de build por sessão |
| 10 PRs abertos juntos (30 jobs) | job começou 7–101 s depois de aberto (limite de jobs simultâneos) |
| `xtask ci (linux)` por PR | mediana 138 s (antes das melhorias: 264 s; pior caso 775 s), máx. 433 s |
| `build (windows-latest)` / `(macos-latest)` | mediana 87 s / 58 s |
| Fila de entrada, por PR (merge da main + fold + CI + squash) | mediana 148 s (137–180 s); 856 s no PR que pegou o espelho lento do `vrf` |
| 10 PRs integrados, de ponta a ponta | 40 min (com as duas paradas e o espelho lento) |
| Conflito de texto / quebra de integração | parados pela fila em 3 s / 57 s; corrigidos pela dona em 5 s / 10 s |
| Falso negativo local sob carga | 1 em 10 (teste de latência; corrigido) |

**Conflitos da rodada de 7 agentes** (**medido**, 2026-10-22): 6 arquivos em conflito em 3 PRs;
5 eram linha acrescentada no fim de lista compartilhada (`pub mod`, campo do `Session`, `spawn`
do daemon, passo do `ci.yml`), 1 era código de verdade (`hal-linux/src/plan.rs`, drift × bonding).
Simulação dos merges de cada par de PRs nas listas de módulos: acrescentando no fim, 7 de 7 pares
conflitam; em ordem alfabética, 2 de 7; geradas dos arquivos, 0. Com as listas geradas, só 1 dos
7 PRs (o do conflito de código) teria ficado fora do primeiro lote, em vez de 3.

### G4.1a — resolvedor DNS (`proto-dns`, `benches/resolver.rs`)

**Medido** em 2026-10-22, AMD RYZEN AI MAX+ 395 w/ Radeon 8060S, build release (`cargo bench -p corerouter-proto-dns --bench resolver`):

| Caso | Tempo |
|---|---|
| `dns_query_encode` (consulta A com EDNS) | 206 ns |
| `dns_reply_parse` (CNAME + 2 A, conferência de id/pergunta) | 590 ns |
| `dns_cache_hit_10k` (acerto no cache com 10 000 entradas) | 50 ns |

O custo de uma consulta é dominado pela rede (ms); o codec e o cache não pesam no plano de controle.

### G4.1b — encaminhador da LAN (`proto-dns`, `benches/forwarder.rs` e `benches/resolver.rs`)

**Medido** em 2026-10-22, AMD RYZEN AI MAX+ 395 w/ Radeon 8060S, build release (`cargo bench -p corerouter-proto-dns`).
Uma consulta da LAN pela cadeia inteira, bytes da consulta → bytes da resposta, sem o socket:

| Caso | Tempo | Consultas/s por núcleo |
|---|---|---|
| `dns_forward_cache_hit` (cache quente) | 0,80 µs | ~1,25 M |
| `dns_forward_static_1k` (estática entre 1000) | 1,04 µs (3,76 µs antes do índice por nome) | ~0,96 M |
| `dns_forward_cache_miss` (cache frio, upstream falso instantâneo) | 2,35 µs | ~0,43 M (sem a rede) |

O cache passou a guardar registros de qualquer tipo (antes só endereços); antes/depois do
resolvedor do roteador, `main` (504accb) × branch, mesma máquina e build:

| Caso | `main` | branch |
|---|---|---|
| `dns_query_encode` | 214 ns | 203 ns |
| `dns_reply_parse` | 580 ns | 635 ns (+9%: guarda os registros da cadeia) |
| `dns_cache_hit_10k` | 54 ns | 73 ns (+35%: copia os registros para o cliente) |

Os dois aumentos são dezenas de nanossegundos numa consulta que custa milissegundos de rede.

**Rodada 2 de agentes** (**medido**, 2026-10-22, horário de Brasília): 4 features pequenas
(G0.5c, G1.8d, G4.4c, G4.6e) de 13:35 a 13:53 — sessões prontas em 4 a 12 min, dois lotes de
3,4 min (3 PRs) e 5,3 min (1 PR), zero conflito, zero teste instável travando, nenhuma intervenção.

**Fila contínua com lote especulativo** (**medido**, 14:47–14:52): lote de 4 PRs (#93 DNS, #94,
#95, #96) entrou 4,5 min depois de o lote começar; o #97 (log), que ficou pronto com o lote já no
CI, foi testado num lote especulativo em cima dele e entrou **44 s** depois, sem esperar outro CI.
Antes disso, o lote do #94 ficou 20 min parado: o GitHub manteve o check-run do job Linux em
"in_progress" depois de o job terminar verde; a fila passou a ler os runs do Actions.

### G4.1c-1 — zonas na cadeia do encaminhador (**medido**)

AMD Ryzen AI MAX+ 395 (32 threads), build release de `cargo bench -p corerouter-proto-dns`, em
2026-10-22. Antes é a `main` em 692ef7a; depois é a branch.

| caso | antes | depois | diferença |
|---|---|---|---|
| `dns_forward_cache_hit` (sem zonas) | 875 ns | 857 ns | −2,5 % (ruído) |
| `dns_forward_static_1k` | 1,013 µs | 1,022 µs | +1,2 % (ruído) |
| `dns_forward_cache_miss` | 2,448 µs | 2,393 µs | −2,3 % (ruído) |

Bench novo `benches/zones.rs`:

| caso | tempo |
|---|---|
| `dns_zone_answer` (A de uma zona de 1000 registros, AA) | 1,04 µs |
| `dns_zone_nxdomain` (com o SOA na autoridade) | 1,44 µs |
| `dns_forward_cache_hit_100_zones` (nome de fora, 100 zonas configuradas) | 1,17 µs |

Uma resposta de zona custa o mesmo que um acerto de cache. Com 100 zonas configuradas, um nome
de fora paga +0,3 µs para descobrir que não é de nenhuma.

### G4.1d — adlist (**medido**, 2026-10-22)

AMD Ryzen AI MAX+ 395 (32 threads), build release (`cargo bench -p corerouter-proto-dns --bench
adlist`): lista de hosts de 1 000 000 nomes lida e montada em 230 ms; o conjunto ocupa 31,8 MB
(~32 B por nome, arena ordenada + deslocamentos `u32`); consulta 79 ns (listado), 82 ns (abaixo
de um `||domínio^`), 105–120 ns (não listado).

### G4.1d — DoT/DoH upstream (**medido**, 2026-10-22)

Build release, AMD Ryzen AI MAX+ 395, cache vazio, 15 nomes populares pelo 1.1.1.1 (RTT ~48 ms),
tempo do `dig` contra o encaminhador: UDP 48–51 ms, DoT 47–49 ms, DoH (HTTP/1.1) 49–53 ms por
consulta. Com a conexão TLS reaproveitada (até 4 ociosas por servidor, 20 s), cifrar não acrescenta
tempo perceptível.

### G4.1e — custo da etapa de estatísticas (**medido**)

AMD Ryzen AI MAX+ 395, build release (`cargo bench -p corerouter-proto-dns --bench forwarder`),
2026-10-22, antes = `main` 49503e0, depois = a branch:

| caso | antes | depois | diferença |
|---|---|---|---|
| `dns_forward_cache_hit` | 762 ns | 809 ns | +5,6 % |
| `dns_forward_static_1k` | 869 ns | 952 ns | +8,4 % |
| `dns_forward_cache_miss` | 2,16 µs | 2,39 µs | +9,0 % |

Um mutex, a busca do estado do `Forwarder` e alguns mapas pequenos por consulta. A primeira
versão alocava o nome do tipo por consulta (+10 a +15 %); contar pelo código do tipo e dar nome
só no `print` tirou metade disso. Ainda dá ~1,2 milhão de consultas por segundo por núcleo com
o cache quente.

### G4.1c-2 — assinatura DNSSEC (**medido**)

AMD Ryzen AI MAX+ 395 (32 threads), build release,
`cargo bench -p corerouter-proto-dns --features dnssec --bench dnssec`, 2026-10-22:

| caso | tempo |
|---|---|
| `dnssec_sign_1k/ecdsa-p256` (zona de 1000 registros inteira, KSK + ZSK, NSEC3) | 24,2 ms |
| `dnssec_sign_1k/ed25519` | 31,8 ms |
| `dns_zone_signed_answer_do` (A + RRSIG pela cadeia) | 1,56 µs |
| `dns_zone_signed_nxdomain_do` (SOA, RRSIG, prova NSEC3 com hashes por consulta) | 6,59 µs |

Sem DO, a resposta de uma zona assinada custa o mesmo que a de uma não assinada (1,04 µs, G4.1c-1).

### Servidor DHCP: tempestade (G4.2a)

**Medido** em 2026-10-22, AMD Ryzen AI MAX+ 395 (32 threads), build release, `cargo bench -p
corerouter-proto-dhcp --bench server_storm` (o servidor puro: N clientes DISCOVER → OFFER →
REQUEST → ACK, linhas de diário serializadas como no engine; sem disco) e `cargo run --release -p
corerouter-proto-dhcp --example storm` (p50/p99 de cada mensagem com `Instant`):

| Caso | Tempo por tempestade | leases/s | p50 / p99 por mensagem |
|---|---|---|---|
| `dhcp_server_storm/dora/1000` | 4,66 ms | 214 k | — |
| `dhcp_server_storm/probed/1000` (sonda ARP, ofertas estacionadas) | 5,35 ms | 187 k | — |
| `dhcp_server_storm/dora/10000` | 53,2 ms | 188 k | 2,2 µs / 3,5 µs |
| `dhcp_server_storm/probed/10000` | 58,5 ms | 171 k | 2,2 µs / 4,6 µs |

Antes de trocar a busca linear de ofertas estacionadas por um conjunto, `probed/10000` dava 20 k
leases/s e p99 de 64 µs (O(n²) numa tempestade). No daemon soma-se uma `fdatasync` do diário por
rodada (todas as concessões da rodada juntas, antes dos ACKs).

### Auditoria do canal de controle (2026-10-22, **medido**)

`cargo bench -p corerouter-control --bench control`, release, AMD Ryzen AI MAX+ 395 (32 CPUs),
`--save-baseline antes` na `origin/main` (19b550e) e `--baseline antes` na branch
`stream/audit-control` (envelope com `RawValue`, `Sock` com prazo/ociosidade, keepalive):

| Benchmark | antes | depois | variação |
|---|---|---|---|
| `control/tcp/ping` | 8,20 µs | 8,13 µs | −1,8 % |
| `control/tcp/interface.list` | 54,9 µs | 55,2 µs | sem mudança (p = 0,25) |
| `control/tls/ping` | 9,20 µs | 9,07 µs | −1,4 % |
| `control/tls/interface.list` | 55,3 µs | 51,0 µs | −7,9 % |

Sem regressão: o `setsockopt` do timeout de leitura só roda quando o valor muda (depois do login
não muda mais), e o `ping` não confere token.

**Medido** (AMD Ryzen AI MAX+ 395, 32 CPUs, build release, 2026-10-22; criterion, `antes` = código
da `origin/main` 19b550e com os mesmos benchmarks, `depois` = este PR):

| Benchmark | Antes | Depois | Mudança |
|---|---|---|---|
| `engine_dhcp_round/mem` (1 rodada: 128 vinculações + 128 ofertas, histórico, zona DNS + reversa, address list; 2.560 concessões antes) | 220,7 ms | 14,1 ms | −93,6 % |
| `engine_dhcp_round/fsync` (idem, arquivos sincronizados no NVMe; 640 concessões antes) | 844 ms | 8,1 ms | −99,0 % |
| escritas por rodada de tempestade (appends / saves de estado) | 129 / 256 | 2 / 1 | |
| `dhcp_attack/exhausted_pool_random_mac/16k` (1.000 DISCOVERs, pool cheio de ofertas) | 18,4 ms | 1,95 ms | −89 % |
| `dhcp_attack/statics_dora/0` (200 DORAs) | 0,90 ms | 1,02 ms | +29 % (índices novos da tabela) |
| `dhcp_attack/statics_dora/10000` | 37,9 ms | 1,30 ms | −96,6 % |
| `dhcp_attack/statics_dora/65536` | 351 ms | 3,05 ms | −99,2 % |
| `dhcp_attack/arp_spoof_probe_replies/4096` (200 DISCOVERs, cada sonda respondida 3×) | 0,93 ms | 0,51 ms | −45 % |
| `dhcp_attack/history_open_at_cap/500k` (100 vinculações com o histórico no teto, inclui soltar a cópia) | 520 ms | 14,1 ms | −97,3 % |
| `dhcp6_attack/solicit_flood_ia_na/100k` (tempo; a memória agora tem teto de 131.072 registros e as ofertas somem após 120 s) | 122 ms | 150 ms | +19 % |
| `dhcp6_attack/solicit_pd_exhausted/65536` (100 SOLICITs, pool PD cheio) | 639 ms | 0,052 ms | −99,99 % |

O lock da sessão fica com o DHCP no máximo ~20 ms de leitura por rodada (`ROUND_BUDGET_US`) e é
solto por ≥ 1 ms entre rodadas; numa rodada de tempestade o tempo total sob o lock caiu de 220–844 ms
para 8–14 ms (linhas acima).

### audit-dns — cache do DNS cheio (2026-10-22, **medido**)

AMD Ryzen AI MAX+ 395 (32 CPUs), build release, criterion (`--warm-up-time 1 --measurement-time 3`),
`antes` = `origin/main` (dbbd394), depois = `stream/audit-dns`:

| benchmark | antes | depois |
|---|---|---|
| `dns_cache_put_full` (inserir num cache de 16 MiB cheio, ~60 000 entradas) | 298,9 µs | 0,611 µs (−99,8 %) |
| `dns_forward_cache_miss_full` (cadeia inteira, miss que despeja num cache de 8 MiB cheio) | 151,2 µs | 3,89 µs (−97,4 %) |
| `dns_forward_cache_hit_full` (acerto com o cache cheio) | 945 ns | 959 ns (ruído) |
| `dns_forward_cache_hit` (quente, cache pequeno) | 915 ns | 964 ns (ruído: `dns_query_encode`, código não tocado, variou o mesmo +5 %) |
| `dns_forward_cache_miss` (frio, upstream instantâneo, TTL 0) | 2,45 µs | 2,59 µs (ruído) |

Memória por entrada (uma resposta A, 200 000 entradas, RSS de `/proc/self/statm` antes e depois
num teste release): **690 bytes**. A estimativa que o cache usa contra o `cache_size` dava 352
(o `cache_size` permitia ~2× a memória configurada); com o índice por expiração e os overheads
corrigidos ela dá 672. Efeito: o mesmo `cache_size` guarda cerca de metade das entradas de
antes, mas agora corresponde à memória de verdade.

### audit-net: validação, listagem e remoção com tabelas grandes (2026-10-23, **medido**)

AMD Ryzen AI MAX+ 395 (32 CPUs), build release (`cargo bench`), criterion. Bench novo
`crates/engine/benches/scale.rs` (config grande já em vigor, restaurada do armazenamento):
`validate_all/<tipo>/N` é a validação do commit; `commit/<tipo>/N` é um `interface.set comment`
(não toca a lista grande); antes = `main` dbbd394, depois = esta branch.

| Bench | Antes | Depois |
|---|---|---|
| `engine_scale/validate_all/filter_rules/1000` | 54,9 ms | 73 µs |
| `engine_scale/validate_all/filter_rules/3000` | 562 ms | 0,22 ms |
| `engine_scale/commit/filter_rules/1000` | 77 ms | 16,9 ms |
| `engine_scale/commit/filter_rules/3000` | 584 ms | 48,9 ms |
| `engine_scale/validate_all/routes/1000` | 499 µs | 103 µs |
| `engine_scale/validate_all/routes/10000` | 48,2 ms | 1,21 ms |
| `engine_scale/ip.route.list/1000` | 1,37 ms | 1,05 ms |
| `engine_scale/ip.route.list/10000` | 64,6 ms | 14,0 ms |
| `engine_scale/commit/routes/10000` | 344 ms | 364 ms (gravação; G1.23) |
| `engine_scale/commit/address_lists/20000` | 355 ms | 328 ms (gravação; G1.23) |

Kernel (netns sem root, `hal-linux/benches/netns_apply.rs`; antes = 63116ed):

| Bench | Antes | Depois |
|---|---|---|
| `hal_linux_apply/addresses_remove/100` (novo: remover N endereços) | 4,85 ms | 2,82 ms |
| `hal_linux_apply/addresses_remove/1000` | 260 ms | 31,6 ms |

`hal_virtual_apply/*` ficou igual (±5%: o `carry` só ganha em commit que não muda rotas nem
endereços; esse bench aplica N itens novos). `engine_execute/*` igual (±1%), exceto
`rejected_param` (1,17 → 1,60 µs) e `virtual_lab_new` (7,0 → 7,5 µs), caminhos que este PR não
toca: o "antes" foi medido em 63116ed, antes do merge do #123.

### audit-persist: tamanho do arquivo de config e latência de commit (2026-10-22, **medido**)

AMD Ryzen AI MAX+ 395 (32 CPUs), build release, `cargo test --release -p corerouter-engine
--test persistence a_big_config_with_a_full_history_still_boots`.

| Medida | Antes | Depois |
|---|---|---|
| Uma cópia da config (4000 entradas de address-list com comentário de 200 caracteres) | 1,47 MB (indentado) | 1,16 MB (compacto, −21%) |
| Arquivo com a running + 65 revisões | ~97 MB (recusado no boot: limite 64 MiB) | 32,4 MB (27 revisões mais novas; boot ok) |
| Teste inteiro (4000 adds, 65 commits, gravação, boot) | — | 1,1 s |
| Commit de `system.identity.set` com 3000 regras de filtro | 0,87 s (`validate_all` → `corerouter_firewall::validate`) | igual (gap G0.14) |

### audit-services: tabela de vizinhos por datagrama recebido (**medido**)

AMD Ryzen AI MAX+ 395 (32 CPUs), build release (`cargo bench`), 2026-10-22,
`cargo bench -p corerouter-engine --bench neighbors` (tabela cheia: 4096 entradas em 16
interfaces; inclui montar a entrada):

| caso | antes | depois |
|---|---|---|
| vizinho novo (expulsa um) | 121 µs | 0,84 µs |
| refresh de vizinho conhecido | 52 µs | 0,24 µs |

"Antes" é o caminho do receptor na `main`: varrer a tabela clonando chaves para saber se é novo
e depois `record` (outra varredura para expulsar). Com o lock da sessão ocupado ~120 µs por
datagrama, ~8 000 anúncios/s bastavam para segurá-lo o tempo todo; agora seriam ~1,2 M/s, e o
limite de 200/s corta antes disso.
