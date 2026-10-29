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

### audit-e2e — import grande ponta a ponta (**medido**)

AMD Ryzen AI MAX+ 395 (32 CPUs), build release, 2026-10-22. `cargo bench -p corerouter-engine
--bench batch_import` (N entradas de address-list num `Session::batch` atômico, lab novo), antes
= `main` anterior ao #130, depois = `main` com o `AtomicBatch` do #130:

| N | antes | depois | mudança |
|---|---|---|---|
| 1000 | 16,4 ms | 3,49 ms | −78,7% |
| 4000 | 237 ms | 29,4 ms | −87,6% |

No daemon real (release, um `engine.batch` por bloco), antes → depois do #130: 4000 regras
1,02 s → 0,06 s; 20 000 entradas de address-list 22,8 s → 0,54 s; 10 000 rotas 18,3 s → 0,17 s;
10 000 concessões fixas 64,0 s → 17,0 s (resto: G0.18). Commit com essa config: p50 110 ms →
36 ms, máx. 297 ms → 55 ms.

Memória do daemon (VmRSS/VmHWM de `/proc/<pid>/status`, release, backend virtual, medido antes
do #130): ocioso
10,8 MiB; + 4000 regras 47 MiB; + 20 000 entradas de address-list 137 MiB; + 10 000 rotas
150 MiB (pico 257 MiB durante os commits seguintes, que serializavam o arquivo de 32 MiB; com o
#130: 118 MiB depois das rotas, 220 MiB após 20 commits);
+ 10 000 concessões fixas 244 MiB (pico 310 MiB); cache DNS com 50 000 nomes distintos
(encaminhador em loopback, upstream DoH local) 289 MiB, pico 354 MiB. Concessões dinâmicas não
foram medidas (o lab virtual não tem caminho de DHCP sem namespace). 16 clientes × 60 s de
escritas mistas (antes do #130): 4665 commits, 77/s, p50 208 ms, p99 450 ms, 0 erros; RSS 217 MiB.

### audit-gui: um quadro da GUI com listas grandes (2026-10-22, **medido**)

AMD Ryzen AI MAX+ 395 (32 CPUs), build release (`cargo bench`), criterion. Bench novo
`crates/ui/benches/frames.rs`: um quadro 1400×900 da UI real, com a janela aberta e a lista posta
no cache (sem refresh entre quadros). "antes" = código da `main` (237ea9b) com os mesmos ganchos.

| Bench | antes | depois |
|---|---|---|
| `ui_frame/addresses_10k` | 208 ms | 16,1 ms |
| `ui_frame/addresses_10k_all_selected` (Ctrl+A) | 15,15 s | 28,0 ms |
| `ui_frame/addresses_1k_4kB_comments` | 94,4 ms | 1,78 ms |
| `ui_frame/firewall_5k_shadowed` | 155 ms | 21,0 ms |
| `ui_frame/terminal_5000_lines` (200 caracteres) | 8,47 ms | 0,090 ms |

### audit-perf — commit, execute e canal de controle sob carga

Máquina A: AMD Ryzen AI MAX+ 395 (32 CPUs lógicas), Linux 7.0.0-38-generic; build release
(bench); 2026-10-22. Todos **medidos**; antes = `main` c5db148 (mesmo bench, código da `main`).

| Benchmark | Antes | Depois |
|---|---|---|
| `storage_fs/commit/routes_history64/1000` (arquivo, fsync, 64 revisões) | 23,7 ms | 4,47 ms |
| `storage_fs/commit/routes_history64/10000` | 396 ms | 11,0 ms |
| `engine_scale/commit/filter_rules/3000` | 51,2 ms | 2,07 ms |
| `engine_scale/commit/routes/1000` | 17,6 ms | 0,65 ms |
| `engine_scale/commit/routes/10000` | 380 ms | 6,29 ms |
| `engine_scale/commit/addresses/10000` | 288 ms | 3,46 ms |
| `engine_scale/commit/address_lists/20000` | 347 ms | 6,60 ms |
| `engine_scale/import/address_lists/1000` (batch atômico) | 19,1 ms | 3,65 ms |
| `engine_scale/import/address_lists/5000` | 423 ms | 60,8 ms |
| `engine_execute/interface.list` | 10,3 µs | 8,15 µs |
| `engine_execute/ip.address.list` | 1,39 µs | 0,223 µs |
| `engine_execute/ip.address.add` | 29,6 µs | 19,9 µs |
| `engine_execute/ip.firewall.filter.add` | 38,0 µs | 26,8 µs |
| `engine_execute/rejected_param` | 1,21 µs | 0,815 µs |
| `engine_execute/virtual_lab_new` | 8,04 µs | 7,36 µs |

Canal de controle sob carga (`control_load/tcp/interface.list/N`, bench novo, TCP com token
local, N conexões pedindo sem parar; latência de cada pedido):

| Conexões | Vazão | p50 | p99 |
|---|---|---|---|
| 1 | 17,6 mil/s | 51,6 µs | 113 µs |
| 4 | 61,5 mil/s | 62,6 µs | 106 µs |
| 16 (`MAX_CONNECTIONS`) | 77,1 mil/s | 201 µs | 578 µs |

A vazão satura em ~77 mil pedidos/s (~13 µs cada, o tempo com o lock da sessão).

### G0.16 — comando sem cópia da config inteira (2026-10-23)

**Medido** em AMD Ryzen AI MAX+ 395 (32 CPUs), build release (`cargo bench`), 2026-10-23, máquina
compartilhada com outras sessões (load ~6). Antes = `origin/main` d682d4a; depois = esta branch.

| Bench | Antes | Depois | Mudança |
|---|---|---|---|
| `engine_txn/single/interface.set/routes_10000` | 89,7 µs | 4,4 µs | −95 % |
| `engine_txn/single/address_list_add_remove/60000` (2 comandos) | 2,70 ms | 1,23 ms | −53 % |
| `engine_txn/build/2000` | 49,4 ms | 18,4 ms | −63 % |
| `engine_txn/build/8000` | 665 ms | 235 ms | −65 % |
| `engine_execute/ip.address.add` | 20,1 µs | 14,5 µs | −28 % |
| `engine_execute/ip.firewall.filter.add` | 25,9 µs | 22,3 µs | −14 % |
| `engine_execute/virtual_lab_new` | 7,52 µs | 5,22 µs | −31 % |
| `engine_scale/commit/filter_rules/3000` | 2,02 ms | 1,05 ms | −47 % |
| `engine_scale/commit/routes/10000` | 6,57 ms | 6,04 ms | −11 % |
| `engine_scale/commit/addresses/10000` | 3,63 ms | 3,15 ms | −15 % |
| `engine_scale/commit/address_lists/20000` | 6,62 ms | 4,91 ms | −28 % |
| `engine_scale/import/address_lists/5000` | 39,4 ms | 32,7 ms | −18 % |
| `engine_scale/ip.route.list/10000` | 14,9 ms | 17,4 ms | +15 % (ruído entre +15 e +44 % em duas rodadas; um `Arc` a mais por acesso a `cfg.ip`) |

`build/N`: o lab montado com N comandos (65 % address list, 30 % rotas, 5 % filtro), o caso de
323 s com 10 MiB em escala menor. Por comando: antes 25 → 83 µs de N = 2000 para 8000; depois
9 → 29 µs. Continua crescendo com a lista tocada (veja acima), mas ~3× abaixo.

G1.26a — encaminhamento de UDP de 64 bytes num namespace (`netns_forward`: `AF_PACKET` → veth →
rota → dummy, uma CPU), antes e depois dos parâmetros por namespace do perfil de alto desempenho.
AMD Ryzen AI MAX+ 395 (32 CPUs), 62 GiB, Linux 7.0.0-38, build release (bench), 2026-10-23,
**medido**:

| Benchmark | Antes (`rp_filter` estrito) | Depois (perfil alto desempenho) |
|---|---|---|
| `netns_forward/udp64` | 1,60 Mpps (12,5 ms por 20 000 quadros) | 1,78 Mpps (11,2 ms), +11 % |

Os parâmetros do host (`netdev_budget`, `netdev_max_backlog`) não existem num namespace: G1.26f.

### audit-history: histórico de 64 revisões com config grande (2026-10-23, **medido**)

AMD Ryzen AI MAX+ 395 (32 CPUs), build release, `cargo bench -p corerouter-storage-fs --bench
commit` (`storage_fs/history64/*`, novo): `FileStorage` em disco de verdade (fsync) sob o tmp do
target, 64 revisões, commit pequeno (`interface.set` comment). Config de 5 MiB = 4000 regras de
filtro, 20 000 entradas de address-list, 10 000 rotas, 10 000 leases estáticos; 10 MiB = 4000
regras, 65 536 entradas, 30 000 rotas. Antes = `main` (cópia inteira por revisão); depois =
diferença para a revisão seguinte.

| medida | 5 MiB antes | 5 MiB depois | 10 MiB antes | 10 MiB depois |
|---|---|---|---|---|
| revisões restauradas no reboot | 6 de 64 | 64 de 64 | 3 de 64 | 64 de 64 |
| bytes em disco (total) | 50,9 MiB | 20,4 MiB | 68,1 MiB | 38,9 MiB |
| bytes nos arquivos de revisão | ~30 MiB (6 cópias) | 0,01 MiB (63 deltas) | ~29 MiB (3 cópias) | 0,01 MiB |
| commit (mediana) | 39,8 ms | 47,4 ms (49,0 na 2ª rodada) | 70,1 ms | 85,8 ms (104,7, rodada ruidosa) |
| boot (`Session::with_storage`) | 265 ms | 1,46 s | 329 ms | 1,21 s |
| `storage_fs/commit/routes_history64/10000` | 11,6 ms | 15,5 ms | | |

O commit fica ~7–16 ms mais caro (comparar os textos das duas configs) e grava menos (2× a config
no slot, antes 3×). O boot cresce com o número de revisões montadas (~20 ms cada com 5 MiB):
restaura 64 em vez de 3–6; G0.20 trata disso.

G1.26b — `netns_forward` com um terceiro caso: o perfil de alto desempenho mais `fq_codel` como qdisc
raiz da porta de saída (um dummy, que tem `noqueue`). AMD Ryzen AI MAX+ 395, Linux 7.0.0-38, build
release, 2026-10-23, **medido** (mesma rodada):

| Caso | Encaminhamento |
|---|---|
| Antes (`rp_filter` estrito) | 1,61 Mpps |
| Perfil de alto desempenho (parâmetros por namespace) | 1,82 Mpps (+13 %) |
| O mesmo, com `fq_codel` na porta de saída virtual | 1,70 Mpps (−7 % contra `noqueue`) |

Por isso o perfil mantém `noqueue` em porta virtual e só põe `fq_codel` em placa de fila única.

### audit-history-share: boot e RAM com 64 revisões de config grande (2026-10-23, **medido**)

AMD Ryzen AI MAX+ 395 (32 CPUs), build release, `storage_fs/history64/*`: `FileStorage` em disco
de verdade (fsync), 64 revisões, commit pequeno (`interface.set` comment). O pico de RSS é o
`VmHWM` de um processo que só faz o boot. As configs são as do audit-history:

- 5 MiB: 4000 regras, 20 000 entradas de address-list, 10 000 rotas, 10 000 leases;
- 10 MiB: 4000 regras, 65 536 entradas, 30 000 rotas.

As três versões comparadas:

- **G0.16**: a `main` antes do #141, com uma cópia inteira por revisão;
- **#141**: diferenças em disco, mas cada revisão desserializada inteira no boot;
- **agora**: este PR.

| medida | 5 MiB G0.16 | 5 MiB #141 | 5 MiB agora | 10 MiB G0.16 | 10 MiB #141 | 10 MiB agora |
|---|---|---|---|---|---|---|
| revisões restauradas | 6 | 64 | 64 | 3 | 64 | 64 |
| boot | 260 ms | 1,46 s | 149 ms | 297 ms | 1,21 s | 208 ms |
| pico de RSS do boot | 79 MiB | — | 79 MiB | 147 MiB | — | 149 MiB |
| RSS depois do boot | 75 MiB | — | 63 MiB | 117 MiB | — | 117 MiB |
| commit (mediana) | 28,7 ms | 40,2 ms | 26,6 ms | 44,1 ms | 69,4 ms | 42,9 ms |

De onde vêm os números da coluna #141:

- O boot foi medido no próprio #141, antes do G0.16.
- O commit foi medido nesta rodada, com G0.16: é a comparação dos textos inteiros que o #141 fazia.
- O RSS não foi medido, porque o bench de RSS veio com este PR.

### G1.27a — IP › Routes (estado, motivo, ECMP)

**Medido** em 2026-10-23, AMD Ryzen AI MAX+ 395 (32 CPUs), Linux 7.0, build release:
`cargo xtask bench --save-baseline antes 'ip.route.list|apply/routes'` na `main` (6485e6e) e
`--baseline antes` na branch.

| benchmark | antes | depois | mudança |
|---|---|---|---|
| `engine_scale/ip.route.list/1000` | 1,12 ms | 2,19 ms | +95% |
| `engine_scale/ip.route.list/10000` | 18,7 ms | 45,9 ms | +146% |
| `hal_linux_apply/routes/100` | 2,04 ms | 2,05 ms | +0,7% |
| `hal_linux_apply/routes/1000` | 20,2 ms | 19,3 ms | −4% |
| `hal_virtual_apply/routes/1000` | 130 µs | 120 µs | −7% |

O `ip.route.list` ficou ~2× mais caro por causa do JSON: cada linha passou de 15 para ~30 campos.
O cálculo em si (estado, motivo, ECMP, watch) custa 0,40 ms por 1000 rotas e 4,2 ms por 10 000
(**medido** com a linha JSON trocada por `{key}`); o resto é montar o `serde_json::Value`. A G1.27c
(tabela cheia) pagina e resume no engine para não mandar a lista inteira.

O primeiro rascunho do multipath clonava o cache de caminhos do kernel a cada op de rota
(`hal_linux_apply/routes/1000` em 35,4 ms, +75%, **medido**); com o cache agrupado por
(tabela, prefixo, métrica) voltou a 19,3 ms.

### CGNAT: carga da tabela, netlink × `nft` (G2.3b, **medido**)

AMD Ryzen AI MAX+ 395 (32 threads), kernel 7.0.0, nft 1.0.9, build release, netns sem root,
2026-10-23, `cargo bench -p corerouter-hal-linux --bench netns_cgnat`. Pool de 1000 portas por
assinante (64 por IP), a tabela inteira trocada num lote.

| Operação | netlink (`nfnl`) | `nft -f` |
|---|---|---|
| 1 Ki assinantes | 17,5 ms | 23,7 ms |
| 16 Ki assinantes | 26,5 ms | 90,0 ms |
| 64 Ki assinantes | 66,0 ms | 303 ms |
| um assinante a mais em 64 Ki (diff incluído) | 0,155 ms | 2,40 ms |

### G6.8a — notas do "Why this answer" na cadeia e linha de origem na adlist (2026-10-23, **medido**)

AMD Ryzen AI MAX+ 395 (32 threads), build de bench (release), com a máquina carregada (load ~7):
`main` e branch rodados em seguida, duas vezes; valores de cada rodada.

| benchmark | main | branch |
|---|---|---|
| `dns_adlist/parse_and_build_1m` | 214 / 228 ms | 281 / 315 ms |
| `dns_adlist_lookup_hit` | 80 / 83 ns | 77 / 87 ns |
| `dns_forward_cache_hit` | 1,06 / 1,25 µs | 1,12 / 1,11 µs |
| `dns_forward_cache_miss` | 2,49 / 3,29 µs | 2,50 / 2,65 µs |

A consulta (cadeia e lookup na adlist) não mudou além do ruído: sem `explain`, cada etapa paga um
teste de `Option`. Carregar uma lista de 1 milhão de nomes ficou ~30% mais lento (linha e forma
de cada nome, ordenadas junto): ~0,3 s na thread do carregador, a cada 4 h, nunca na consulta.
Memória: 36,8 MB contra 31,8 MB para 1 milhão de nomes (+5 bytes por nome).

### G1.27c — IP › Routes com 1 milhão de rotas

**Medido** em 2026-10-23, AMD Ryzen AI MAX+ 395 (32 CPUs), Linux 7.0, build release. Antes = a branch
da G1.27b (`--save-baseline antes_c`), depois = G1.27c. Tabela de `corerouter_engine::perf::full_table`:
1 000 000 de rotas (IPv4 /24 e um /16 a cada 256, IPv6 /48 a cada 20).

| benchmark | antes | depois |
|---|---|---|
| `routes_1m/ip.route.list` (a lista inteira em JSON) | 4,83 s | 3,83 s (−21%) |
| `routes_1m/ip.route.page/cold` (linhas refeitas) | — | 786 ms |
| `routes_1m/ip.route.page/first` (linhas guardadas) | — | 4,56 ms |
| `routes_1m/ip.route.page/last` | — | 4,41 ms |
| `routes_1m/ip.route.page/prefix` (`12.0.0.0/8` contido) | — | 12,3 ms |
| `routes_1m/ip.route.page/inactive` | — | 6,00 ms |
| `routes_1m/ip.route.page/aggregate` (por /16) | — | 10,6 ms |
| `ui_frame/routes_1m` (um quadro com a janela aberta) | 4,47 s | 796 µs |

Antes, a janela recebia a lista inteira e remontava 1 M de linhas a cada quadro (4,47 s); depois
recebe uma página de 500 e monta as linhas uma vez por resposta. O `ip.route.list` ficou 21% mais
rápido porque as linhas vêm do cache; o resto é o JSON de 1 M de linhas (~30 campos cada).

### G4.4b: codec de fluxos (medido)

AMD Ryzen AI MAX+ 395 (32 threads), build release (bench do criterion), 2026-10-23,
`cargo bench -p corerouter-proto-flow --bench flow_codec`:

| Operação | Tempo | Vazão |
|---|---|---|
| medidor: 10 mil conexões NAT, `NEW` + `DESTROY` (20 mil eventos, 30 mil registros) | 2,60 ms | 7,7 M eventos/s |
| IPFIX: 30 mil registros (10 mil conexões) em mensagens de 1400 bytes | 1,88 ms | 16 M registros/s |
| NetFlow v9: o mesmo | 2,09 ms | 14 M registros/s |

Um CGNAT com 50 mil conexões novas por segundo gasta menos de 2 % de um núcleo no medidor e no
codec juntos (**estimado** a partir destes números).

### G4.4b: Traffic Flow ponta a ponta (medido)

AMD Ryzen AI MAX+ 395, kernel 7.0, netns sem root, daemon em build de teste (sem otimização),
2026-10-23. Comando: `COREROUTER_FLOW_BURST=<n> … cargo test -p corerouter-daemon --test
netns_traffic_flow -- --nocapture`. As conexões são UDP com SNAT; depois de abertas, são apagadas de
uma vez pelo ctnetlink. O coletor é IPFIX por TCP.

| Rajada | Creates exportados | Deletes e fluxos exportados | Registros/s | CPU do daemon | RSS | Perdas |
|---|---|---|---|---|---|---|
| 20 mil conexões (abertas em 0,09 s) | 20 000 em 0,19 s | 40 000 em 0,24 s | ~160 mil | 4,7 µs/registro | 59 MB | 0 na fila, 0 no kernel |
| 100 mil conexões (abertas em 0,35 s) | 81 545 (2 estouros do kernel) | 200 000 em 1,0 s | ~200 mil | (inclui 60 s de leituras da tabela) | 137 MB | 0 na fila; 18 % dos `NEW` perdidos no kernel |

Em user namespace o buffer do socket fica no `rmem_max` (8 MiB efetivos). No roteador o daemon é
root e pede 32 MiB com `SO_RCVBUFFORCE`. Mesmo com estouro, todo delete leva o início da sessão:
nenhuma sessão some do registro.

### G2.3e — CGNAT: pps, conexões novas, "Quem era?" (**medido**, 2026-10-23)

Ryzen AI MAX+ 395 (32 threads), kernel 7.0, build release, netns sem root, carga 8–16 na máquina (CIs
de outras sessões). Valores em mediana, num núcleo (veth).

| Medida | Valor |
|---|---|
| UDP 64 B, só roteamento (sem conntrack) | ~830 mil pps |
| UDP 64 B, CGNAT | ~650 mil pps |
| UDP 64 B, CGNAT + fast path em software | ~1,04 milhão pps |
| conexões novas/s, só conntrack | ~551 mil |
| conexões novas/s, CGNAT sem EIM | ~274 mil |
| conexões novas/s, CGNAT (EIM, padrão) | ~255 mil |
| conexões novas/s, CGNAT com o slot quase cheio | ~13 mil |
| "Quem era?", 64 Ki assinantes, 1 época | 1,4 µs |
| "Quem era?", 64 Ki assinantes, 365 épocas | 3,0 µs |

- 2026-10-23 — G2.5a, XDP (**medido**, runner do GitHub Actions ubuntu-latest, 4 vCPUs, kernel do
  runner; objeto XDP release; `cargo xtask xdp-root`). `BPF_PROG_TEST_RUN`, 2 milhões de
  repetições, UDP 64 bytes, ns por pacote (inclui o custo fixo do test run):

  | prefixos na LPM | carga | passa | bloqueado | passa com taxa |
  |---:|---:|---:|---:|---:|
  | 0 | 208 ms | 159 | — | 216 |
  | 1 000 | 202 ms | 176 | 285 | 234 |
  | 10 000 | 215 ms | 175 | 322 | 233 |
  | 100 000 | 441 ms | 170 | 339 | 229 |
  | 1 000 000 | 2 682 ms | 173 | 347 | 231 |

  LPM: ~17 ns, plano de mil a um milhão de prefixos. Remetente AF_PACKET em veth (2 s, 64 bytes,
  um núcleo para envio e recepção): sem filtro 450 kpps, nftables raw drop 471 kpps, XDP generic
  drop 402 kpps, XDP native (veth) drop 409 kpps. Em veth o XDP não ganha (o veth já entrega um
  `skb`); o ganho exige o modo native numa placa real (roteiro em `docs/xdp.md`). Host, mesma
  decisão sem mapas (`benches/filter.rs`, AMD Ryzen AI Max+ 395, release): parse 9,4 ns,
  decisão com taxa 18,4 ns, bloqueado 13,2 ns.

### G4.5 — histórico de tráfego (**medido**, 2026-10-23, AMD Ryzen AI MAX+ 395, 32 threads, build release, ext4 em NVMe)

Coleta e consulta, do `cargo bench -p corerouter-engine --bench graph` (criterion, mediana):

| | 8 interfaces | 64 interfaces | 512 interfaces |
|---|---|---|---|
| um segundo de coleta (no tick, sob o lock da sessão) | 1,9 µs | 20,0 µs | 355 µs |
| tirar as mudanças de um store de 5 min (sob o lock) | 4,7 µs | 32,7 µs | 547 µs |

Consulta de uma interface com o histórico cheio: hora 294 µs, dia 299 µs, semana 542 µs, mês
279 µs, **ano 1,36 ms**.

Daemon de lab (`--backend virtual`, VLANs para chegar a 64 e 512, `vlans=yes`):

| | 8 | 64 | 512 |
|---|---|---|---|
| histórico (memória = disco) | 5,72 MB | 43,4 MB | 344,9 MB |
| RSS do daemon | 18,5 MB | 56,9 MB | 359,4 MB |
| CPU do daemon inteiro (60 s, ticks de 10 ms) | 12 | 14 | 24 |
| store de 1 min: bytes, tempo (fora do lock) | 696 B, 16 ms | 5.176 B, 94 ms | 41.016 B, 511 ms |
| store final com o anel de 1 s | 26 KB, 8 ms | 199 KB, 64 ms | 1,57 MB, 491 ms |

- Uma série de interface ocupa 672.984 bytes e a do sistema 336.600, fixos.
- Com 512 VLANs e o graphing desligado, o daemon fica com 24,9 MB de RSS e 18 ticks em 60 s. O
  histórico de 512 interfaces custa então 6 ticks a cada 60 s (0,1 % de um núcleo) e 334 MB.
- O store custa ~80 B por série por minuto de histórico. No padrão de 5 min, a flash recebe
  ~115 KB por interface por dia (**estimado** a partir do medido). O tempo do store é o
  `fsync` de cada arquivo.
- **Restart:** com 8, 64 e 512 interfaces, a consulta da última hora de `ether1` antes do
  SIGTERM e depois de subir de novo deu os mesmos totais e a mesma média. O teste
  `a_restart_reads_back_what_was_stored` confere os pontos.

### G6.4b — Bandwidth Test (2026-10-23, **medido**)

Máquina de desenvolvimento (32 CPUs) **carregada por outras sessões** (load average 26–39
durante as medições: os números de CPU incluem essa carga), daemon e CLI em release, cliente e
servidor do próprio daemon em loopback (`127.0.0.1:5299`), 5 s por teste. CPU = o roteador inteiro.

| Teste | Recebido | Perda | Jitter | CPU média (máx.) |
|---|---|---|---|---|
| TCP, 1 stream | 86,7 Gbit/s | – | – | 25 % (34 %) |
| TCP, 4 streams | 310 Gbit/s | – | – | 40 % (45 %) |
| UDP 1 Gbit/s, 1 stream | 1,00 Gbit/s | 0,0 % | 0,002 ms | 23 % (26 %) |
| UDP 2 Gbit/s, 1 stream | 2,0 Gbit/s | 0,0 % (148 de ~180 mil) | 0,001 ms | 69 % (90 %) |
| UDP receive, 4 × 500 Mbit/s | 1,9 Gbit/s | 0,0 % | 0,001 ms | 57 % (78 %) |

Antes de dar 4 MiB de buffer de recepção aos sockets UDP (o padrão do kernel é ~208 KiB), o UDP
a 1 Gbit/s perdia 29,7 % em loopback; depois, 0,0 %. Loopback mede o software dos dois lados, não
uma NIC; o número que importa num ISP é o do enlace real, que esta ferramenta passa a medir.

### G6.4a — Torch e Packet Sniffer (2026-10-23, **medido**)

Máquina de desenvolvimento (32 CPUs), build release (`cargo bench`), veth num namespace sem root.
`COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- cargo bench -p
corerouter-hal-linux --bench netns_capture`: emissores escrevem quadros UDP de 64 bytes (256
fluxos) por `AF_PACKET` em `cpa`; a captura do Torch (`HostCapture`) lê e decodifica em `cpb`.
"Coberto" = lidos × N ÷ o contador da interface.

| Caso | Oferecido | Lido | Coberto | CPU da thread de captura |
|---|---|---|---|---|
| 1 emissor, tudo | 1717 kpps | 1717 kpps | 100 % | 99 % |
| 1 emissor, 1:8 no kernel | 1289 kpps | 162 kpps | 100 % | 26 % |
| 6 emissores, tudo | 8318 kpps | 2059 kpps | 25 % | 100 % |
| 6 emissores, 1:8 no kernel | 11257 kpps | 1406 kpps | 100 % | 87 % |
| 6 emissores, 1:64 no kernel | 12787 kpps | 200 kpps | 100 % | 35 % |

`cargo bench -p corerouter-engine --bench torch` (agregar um lote de 1024 quadros):
`torch_ingest/src_dst` 75,4 µs (13,6 M quadros/s), `torch_ingest/five_tuple` 83,2 µs
(12,3 M quadros/s). Conclusão: ~0,5 µs por quadro é o socket (`recvmsg`), não a agregação; o
`sampling: auto` (500 kpps → ~30 % de um núcleo; acima, ~250 kpps lidos) mantém o custo
limitado, e o próximo salto é XDP (G6.10).

### Exportador ClickHouse (G4.4f), 2026-10-23

**Medido** num AMD Ryzen AI MAX+ 395 (32 threads, 62 GB), Linux 7.0, rustc 1.99.1, ClickHouse
26.9.25.15 na mesma máquina (loopback), build release, 3 rodadas (iguais a ±2 %):
`cargo test --release -p corerouter-daemon --bin corerouter-daemon bench_analytics -- --ignored --nocapture`.

| Etapa | Resultado |
|---|---|
| Logs: codificar (JSONEachRow) + fila + gzip nível 1, 500 000 linhas | ~510 000 linhas/s num núcleo, 1,9 µs de CPU por linha; 340 B/linha crua, 13 B/linha com gzip (texto sintético repetitivo: log real comprime menos) |
| Métricas: texto Prometheus → linhas + gzip, 500 000 linhas | ~1,1 milhão de linhas/s; 9,4 B/linha com gzip |
| Envio ao ClickHouse, 50 lotes de 10 000 linhas (6,3 MiB) | ~665 000 linhas/s; CPU do roteador no envio desprezível (< 0,01 s); 500 000 linhas gravadas |

**Destino fora do ar por 10 minutos** (**medido**, daemon em debug com o lab virtual,
`queue_size` 1 MiB, `disk_queue` 64 MiB, `metrics_interval` 10 s, `flush_interval` 2 s; ClickHouse
parado e religado):

- só métricas (12,7 linhas/s): fila chegou a 7 621 linhas em 74 KB; RSS do daemon estável em
  35 MB; 0 descartadas; voltou 36 s depois de o servidor subir (a espera do reenvio, até 60 s) e
  esvaziou num tique;
- métricas + 19 eventos de log/s (31 linhas/s): fila chegou a 18 999 linhas em 347 KB (≈ 18 B
  por linha comprimida, nada foi para o disco); RSS entre 40 e 47 MB (o crescimento vem das 12 000
  revisões de configuração da carga, não da fila); 0 descartadas; esvaziou 56 s depois de o
  servidor subir; o ClickHouse ficou com exatamente as 31 960 linhas que o roteador contou como
  enviadas, sem duplicata (10 878 logs, 10 878 `seq` distintos);
- reenvio: espera de 1 s dobrando até 60 s com 75–100 % de sorteio (34 tentativas em 10 min).

Com a fila de 16 MiB padrão e ~18 B por linha, cabem ~900 000 linhas (**estimado**): 8 horas de
fora do ar a 31 linhas/s antes do primeiro descarte, mais o disco se ligado.

- 2026-10-24 — G2.5b, caminho rápido do CGNAT em XDP (**medido**, runner do GitHub Actions
  ubuntu-latest, 4 vCPUs, kernel do runner; objeto XDP release; `cargo xtask xdp-root`, run
  40063157232). `BPF_PROG_TEST_RUN` em `la` (UDP 64 bytes, fluxo conhecido, FIB resolvida):
  **331 ns** por pacote traduzido e redirecionado, contra 159 ns de um pacote sem fluxo (só o
  filtro). Encaminhamento UDP de 64 bytes por 2 s através do roteador (três namespaces, veth,
  remetente UDP no namespace do assinante, mesma CPU para tudo): NAT do kernel (SNAT nftables +
  conntrack + roteamento) **186 kpps** entregues; caminho rápido XDP (generic) **207 kpps**
  (+11%), 414 976 de 414 976 pelo XDP. Em veth o ganho é pequeno porque o remetente e o `skb`
  do veth dominam; o ganho real (não alocar o `skb`, não passar por conntrack nem por rotas)
  só aparece numa placa em modo native (roteiro em `docs/xdp.md`, G2.5e).
- 2026-10-24 — G2.5b, a mesma bateria na máquina do usuário (**medido**, AMD Ryzen AI Max+ 395,
  kernel 7.0.0-38, objeto do prebuilt, `cargo xtask xdp-root` com root, HEAD 43026ee):
  `BPF_PROG_TEST_RUN` **106 ns** por pacote traduzido e redirecionado contra 54 ns sem fluxo;
  encaminhamento UDP 64 bytes em veth: NAT do kernel **700 kpps**, caminho rápido XDP (generic)
  **792 kpps** (+13%), 1 583 360 de 1 583 361 pelo XDP. De ponta a ponta com conntrack: o fluxo
  entrou no mapa quando ficou `ASSURED` (status 0x19e), 74 pacotes pelo XDP sem nenhum ir ao
  kernel, contadores do conntrack parados (6 antes, 6 depois), renovação aceita, `Destroy` tirou
  o fluxo do mapa.

- 2026-10-24 — G4.3b, RADIUS (`cargo bench -p corerouter-proto-radius --bench radius`,
  **medido**, AMD Ryzen AI MAX+ 395, build release, Linux 7.0):

  | Benchmark | Mediana | Por segundo |
  |---|---|---|
  | `radius/decode_access_request` (13 atributos + VSAs, percorrer tudo) | 26,3 ns | 38 M |
  | `radius/decode_dictionary` | 334 ns | 3,0 M |
  | `radius/encode_access_request` (PAP + Message-Authenticator) | 757 ns | 1,3 M |
  | `radius/verify_accept` (MD5 + HMAC-MD5 + ler Rate-Limit) | 758 ns | 1,3 M |
  | `radius/rate_limit_parse` | 57 ns | 17,5 M |
  | `radius/coa_handle_and_ack` | 1,85 µs | 541 k |
  | `radius_client/access_round_trip_1000` (cliente + servidor de teste, uma thread) | 2,72 ms / 1000 | 368 k pedidos/s |

Primeira rodada local do `xdp-root` (**medido**, AMD Ryzen AI Max+ 395, 32 threads, kernel
7.0.0-38, objeto XDP do prebuilt, 2026-10-24). Custo por pacote (`BPF_PROG_TEST_RUN`): liberado
42 ns (134 no runner do CI), bloqueado com 1 milhão de prefixos 126–134 ns (271 no runner),
carga de 1 milhão de prefixos 698–702 ms. Envio em veth, em kpps: sem filtro 2027, nftables
raw 2116–2171, XDP generic 1855–1889, XDP native 1785–1811 (duas rodadas).

### G4.3a — `proto-pppoe` (**medido**, 2026-10-24)

AMD Ryzen AI Max+ 395 (32 threads, SHA-NI), Linux 7.0, rustc 1.99.1, `cargo bench -p
corerouter-proto-pppoe --bench pppoe` (release, `lto = "thin"`), máquina compartilhada (carga
≈ 2–3).

| Benchmark | Mediana | Por segundo, um núcleo |
|---|---|---|
| `decode_padi` (Ethernet + VLAN + todas as tags, com TR-101) | 24,6 ns | 40,6 M |
| `decode_lcp_request` (sessão + controle + 3 opções tipadas) | 26,2 ns | 38,2 M |
| `server_padi_to_pado` (tags, AC-Cookie HMAC-SHA-256, PADO) | 175,5 ns | 5,7 M |
| `server_lcp_echo` (Echo-Request → Echo-Reply numa sessão aberta) | 31,4 ns | 31,8 M |
| `session_setup_1000_chap` (PADI → IPCP Opened, servidor + cliente + rede do laboratório) | 6,27 µs por sessão | 159 mil sessões/s |

Memória: 50 000 sessões em Opened somam ≈ 1549 B por sessão de RSS no laboratório (servidor,
cliente e rede juntos, **medido**); a `Session` do servidor tem 624 B (`size_of`, **medido**), e com
a caixa no slab, as duas entradas de índice e o nome do usuário fica em ≈ 750 B por sessão no
servidor (**estimado**): 100 mil assinantes ≈ 75 MiB no plano de controle.

A simulação de 100 mil sessões (`hundred_thousand_sessions_reach_opened_on_a_lossy_network`)
leva ≈ 39 s em debug no `cargo test` (**medido**), 12,3 milhões de quadros simulados.

- 2026-10-24 — G4.3c, PPPoE no XDP, **medido** na máquina do usuário (AMD Ryzen AI Max+ 395,
  kernel 7.0.0-38, objeto release): `BPF_PROG_TEST_RUN` uma execução por chamada, média de
  20 000; piso (passa) 87 ns, descida encapsulando 123 ns, subida decapsulando 139 ns com 1
  sessão; 86–90, 124–127 e 137–139 ns com 100 000 sessões (plano). Incluir 100 000 sessões:
  527 ms (5,3 µs cada); remover: 414 ms. Encaminhamento em veth (generic, UDP 64 B): kernel IPv4
  sem PPPoE 1410 kpps, XDP decap + FIB 913 kpps, XDP decap + kernel 816 kpps. Policer, pior erro
  em 3 s: 1 × 1 Gbit/s −0,00%, 100 × 20 Mbit/s −0,02%, 10 000 × 0,2 Mbit/s −1,53%.

### G4.3j — autenticações por segundo pelo serviço RADIUS (**medido**, 2026-10-24, AMD Ryzen AI MAX+ 395, build release)

`cargo bench -p corerouter-daemon --bench radius_aaa`: o caminho inteiro de um login (fila do serviço, Access-Request com PAP e Message-Authenticator, UDP em 127.0.0.1 até o servidor de teste numa thread, resposta conferida e decodificada, callback).

| Benchmark | Mediana | Por segundo |
|---|---|---|
| `radius_aaa/authenticate_1_concurrent` | 13,9 µs | 72 k |
| `radius_aaa/authenticate_1000_concurrent` | 5,15 ms por lote | 194 k |

Com o buffer de recepção padrão (~200 KiB) a rajada de 1000 respostas transbordava e o lote levava 6,6 s; com 4 MiB no socket (limitado por `net.core.rmem_max`), 5,15 ms.

- G4.8a — custo de uma leitura de System › Resources (**medido**, 2026-10-24, AMD Ryzen AI Max+ 395, 32 CPUs, 881 processos, build release, `cargo bench -p corerouter-hal-linux --bench resource`): leitura sem processos 512 µs; sensores 30 ms (NVMe ~4 ms por sensor e wifi mt7925 ~3,5 ms consultam o dispositivo; por isso são lidos a cada 10 s e reaproveitados entre leituras); com os 881 processos 5,2 ms (só sob demanda, com a aba Processes aberta).

- G4.8a — trabalho do serviço `health` sob o lock da sessão por leitura (entregar a leitura + julgar as 12 verificações): 3,7 µs (**medido**, 2026-10-24, AMD Ryzen AI Max+ 395, build release, `cargo bench -p corerouter-engine --bench health`, laboratório de 16 CPUs e 8 portas). A leitura em si (~0,5 ms) fica fora do lock.

- G4.8a — um quadro da GUI com System › Resources aberta (aba Overview: quatro cartões com sparkline, 8 interfaces, 12 verificações), tela 1400×900: 203 µs (**medido**, 2026-10-24, AMD Ryzen AI Max+ 395, build release, `cargo bench -p corerouter-ui --bench frames -- resources`), ~1,2 % dos 16 ms de um quadro a 60 fps.

### G4.8b — OS Log (**medido**, 2026-10-24, AMD Ryzen AI Max+ 395, Linux 7.0)

| O quê | Resultado |
|---|---|
| `OsLogBook::push`, 100 000 linhas (metade repetida), release | 339 ns/linha; `since` de 500: 1,5 µs |
| GUI, 100 000 linhas em respostas de 2000 (20 000 guardadas), debug | 2,6 ms por quadro (tabela virtualizada); refiltrar 20 000: 14 ms, só quando filtro ou linhas mudam |
| libFuzzer, alvo `oslog` (nightly, 1 núcleo) | 5,2 milhões de execuções em 121 s, nenhuma falha |
| `journalctl --after-cursor` num journal de 2,0 GB | ≤ 10 ms por chamada (a cada 2 s); backfill de 500 linhas: 60 ms; pico de RSS 46 MB |

### G0.26: rodadas na VM do laboratório (**medido**, 2026-10-25)

Host AMD Ryzen AI Max+ 395 (32 threads, 64 GB), VM `corerouter-lab` 8 vCPUs / 8 GiB, kernel 7.0.0-38, build dev.

| Etapa | Tempo |
|---|---|
| `create` com a imagem já baixada (cloud-init + pacotes + reboot no HWE + rustup + snapshot) | 156 s |
| download da imagem (~600 MB) | 28 s |
| `run -- env COREROUTER_REQUIRE_XDP=1 cargo xtask xdp-root`, cache frio (compila xtask + teste: 17,8 s) | 102,8 s |
| a mesma rodada, cache quente (compilação 0,09 s; o resto são os 13 testes) | 76,3 s |
| só `COREROUTER_XDP_TESTS=loads_attaches_and_counts`, quente | 4,9 s |
| `sync` sem mudanças | 0,1–0,2 s |
| `reset` (volta ao snapshot `clean` e espera o SSH) | 8,6 s |
| `xdp-root` quente com `host-model`, 16 GiB e `spec_rstack_overflow=off` | 74,5 s (PERF iguais) |
| o mesmo com `host-model` sem `spec_rstack_overflow=off` (SRSO Safe RET) | 108,4 s; veth sem filtro 558 kpps, LPM 1M pass 156 ns |

PERF do `xdp-root` na VM (virtio/veth, não placa física): LPM com 1 000 000 prefixos carrega em 1 283 ms, passa a 51 ns/pkt e bloqueia a 142 ns/pkt; veth blast: sem filtro 1 783 kpps, nftables raw drop 1 837 kpps, XDP generic drop 1 613 kpps, XDP native drop 1 583 kpps; fast-nat redirect 113 ns/pkt; forward kernel NAT 500 kpps × XDP fast path (generic, veth) 450 kpps; PPPoE 100k sessões: insere em 921 ms (9,2 µs/sessão), encap 145–151 ns, decap 170–183 ns, remove em 540 ms; policer 10 000 assinantes com erro pior de −1,50 %; forward PPPoE: kernel sem PPPoE 1 159 kpps, XDP decap + FIB redirect 714 kpps, XDP decap + forward do kernel 658 kpps.

### G4.3d — BNG: sessões por segundo e memória por sessão (**medido**, AMD Ryzen AI Max+ 395, 2026-10-24)

| Medida | Build | Resultado |
|---|---|---|
| `cargo bench -p corerouter-daemon --bench pppoe_bng`: 1000 sessões do PADI ao IPCP Opened (BNG + clientes `proto-pppoe` em memória, MS-CHAPv2 local, pool, mapa XDP, histórico) | release | 10,5 ms = **≈ 94 mil sessões/s** num núcleo |
| Memória do BNG com 50 mil sessões ativas (RSS; inclui o servidor `proto-pppoe`, a tabela ativa, o histórico e o "Why?") | release | **≈ 3,9 KB/sessão** (eram 4,9 KB antes de enxugar o "Why?") |
| `netns_pppoe`: 10 mil CPEs reais por veth até Opened, daemon com caminho lento | debug | 6,5 s = 1531 sessões/s |
| `netns_pppoe`: reconexão em massa de 10 mil CPEs com `new_session_rate=1000` | debug | 34 s (o limite e o recuo dos CPEs, RFC 2516 §5) |

- 2026-10-25 — G4.3e (**medido**, Ryzen AI Max+ 395, release, `cargo bench -p corerouter-proto-pppoe --bench pppoe -- pppoe_ipv6` e `cargo bench -p corerouter-proto-dhcp --bench codec -- dhcp6_session`): classificar um RS 8,7 ns; montar o RA da sessão (PIO, MTU, RDNSS ×2, DNSSL) 72 ns; identificador estável do IPv6CP 70 ns; DHCPv6 da sessão responder Solicit com Rapid Commit (IA_NA + IA_PD + DNS) 444 ns.

- 2026-10-25 — G4.3e (**medido**, Ryzen AI Max+ 395, build de debug, veth em namespace sem root, `netns_pppoe6`): 10 000 CPEs dual-stack (IPv4 + /64 pelo RA + /56 pelo DHCPv6-PD com Rapid Commit) de PADI a PD ligado em 17,6 s = 569 sessões/s.

- 2026-10-25, G4.3f, **medido** (32 CPUs, release, `cargo bench -p corerouter-proto-dhcp --bench server_storm -- dhcp_server_ipoe`): DORA pelo servidor DHCP puro, por lease: 10 000 clientes 7,0 µs (sem autorização) e 8,3 µs (IPoE, veredito na hora); 100 000 clientes 8,8 µs e 11,8 µs. Antes da correção do limitador, 100 000 clientes: 62 µs/lease e só 65 536 ACKs.

- 2026-10-25, G4.3f, **medido** na VM `corerouter-lab` (kernel 7.0, 8 vCPUs, XDP genérico em veth, `xdp-root`): IPoE `BPF_PROG_TEST_RUN` com 300 sessões, subida 94 ns/pacote e descida 85 ns/pacote. O caminho do PPPoE antes × depois (duas rodadas cada): XDP decap + FIB 732/746 × 743/729 kpps, CGNAT rápido redirect 116/115 × 119/117 ns/pacote: dentro do ruído.

- 2026-10-25, G4.3f, **medido** (32 CPUs, build debug, veth sem XDP, `apps/corerouter-daemon/tests/netns_ipoe.rs`): 10 000 assinantes IPoE autorizados pelo RADIUS de teste (Access-Request + Accounting-Start cada) com endereço em 3,0 s = 3 300 sessões/s; o daemon cresce ~4,3 kB/sessão.
- 2026-10-25, G4.3f, **medido** (32 CPUs, release, `cargo bench -p corerouter-daemon --bench ipoe_bng`): decisão local + sessão (linha ativa, histórico, mapa XDP) + fim, por assinante: 6,6–9,9 µs com 10 000 já conectados e 6,6 µs com 100 000 (1000 por iteração).

### G4.3g-a — custo por sessão com muitas no ar (**medido**, AMD Ryzen AI Max+ 395, release, 2026-10-25)

`cargo bench -p corerouter-daemon --bench pppoe_bng`: 60 mil sessões (um servidor: SESSION_ID
de 16 bits) em lotes de 10 mil sobre o mesmo BNG, CHAP, 100 mil secrets, µs por sessão em cada
lote:

| Lote (sessões já no ar) | 0 | 10 mil | 20 mil | 30 mil | 40 mil | 50 mil |
|---|---:|---:|---:|---:|---:|---:|
| Antes (`Ppp::secret` linear, varreduras de `subs`) | 19,0 | 38,5 | 75,8 | 110,4 | 143,5 | 180,9 |
| Depois (índice de secrets + `SubIndex`) | 12,1 | 13,9 | 16,0 | 14,9 | 15,2 | 23,9 |

O último lote cruza as 100 mil chaves do "Why?" (duas por assinante), que hoje apaga tudo e
recomeça: corrigido no PR seguinte da G4.3g.

### G4.3g — BNG Blaster contra o daemon, primeira rodada (**medido**, AMD Ryzen AI Max+ 395, 32 CPUs, kernel 7.0.0-38, daemon release, BNG Blaster 1.0.1, 2026-10-25, root com XDP)

Antes da correção do O(n) (G4.3g-a); os números depois dela vêm na rodada final e no
`docs/pppoe-relatorio.md`.

| Medida | 1 mil | 10 mil | 100 mil |
|---|---:|---:|---:|
| Setup, proteções desligadas | 9210/s | 9838/s | 3243/s (30,8 s) |
| CPU do daemon por sessão no setup | 50 µs | 39 µs | 267 µs |
| Memória por sessão | — | 1995 B | 3023 B |
| CPU em regime (LCP echo a cada 10 s) | 0,7 % | 1,5 % | 12,9 % de um núcleo |
| Reconexão em massa com as proteções padrão | 0,10 s | 6,8 s | 57,2 s (new-session-rate 2000) |
| Encerramento (PADT de todas) | 0,30 s | 1,30 s | 10,3 s |

- RADIUS (100 assinantes): 981 sessões/s.
- Policer a 2× a taxa: 1,000–1,010 do limite nos dois sentidos.
- CoA: 10/10 ACK, ida e volta média 0,04 ms; só os 10 mudaram de taxa (1,000×), os outros
  ficaram em 1,002×.
- Disconnect: 10/10 ACK em 1 ms, de volta em 1,02 s; os outros seguiram em 1,008×.
- `pppd`: sessão em 3,06 s, CHAP, MTU 1480, ping pelo BNG, derrubada pelo BNG em 0,11 s,
  PADT do cliente visto.

### G4.3g-c — `ppp.secret.add` em lote (**medido**, AMD Ryzen AI Max+ 395, release, 2026-10-25)

`cargo bench -p corerouter-engine --bench batch_import -- ppp_secret`: um `engine.batch` atômico
num laboratório novo.

| Lote | Antes | Depois |
|---|---:|---:|
| 1 000 secrets | 9,8 ms | 3,9 ms |
| 10 000 secrets | 165 ms | 55 ms |

Com 100 mil em lotes de 10 mil na mesma sessão, cada passo custa o mesmo (~6 µs, dos quais ~4
são o journal). O que cresce é o commit no fim de cada lote, que trata o config inteiro: de 6 µs
para 33 µs por secret no décimo lote, ≈ 1,5 s no total para importar 100 mil.

### G4.3g-d — workers do BNG (**medido**, AMD Ryzen AI Max+ 395, 32 CPUs, release, 2026-10-25)

`cargo bench -p corerouter-daemon --bench pppoe_bng`. São 40 mil sessões do PADI ao IPCP
Opened, CHAP e mapa XDP, divididas pelo MAC entre os workers, cada um numa thread com os seus
clientes (`proto-pppoe`). Compartilham a tabela ativa, o histórico e os pools.

| Workers | 1 | 2 | 4 | 8 |
|---|---:|---:|---:|---:|
| Sessões/s | 58 066 | 114 725 | 201 878 | 303 161 |

Com o "Why?" e os contadores ainda no lock compartilhado, 8 workers davam 135 103/s (sete locks
por sessão); separá-los dobrou o ganho. Memória com 50 mil sessões no ar: ≈ 5,0 KB/sessão, com
os campos IPv6 da G4.3e.

### G4.3g-d — onda de reconexão contra um RADIUS de capacidade fixa, simulada (**medido**, release, 2026-10-25)

`mass_reconnect_against_a_slow_radius` (relógio do laboratório): 6000 CPEs ligando em até 5 s
após uma queda, um RADIUS de 300 pedidos/s com autenticação e accounting na mesma fila (no
máximo 150 logins/s: ideal ≈ 40 s), CPEs que tentam de novo 1–3 s depois de falhar.

| `new_session_rate` | Todas no ar em | Logins abandonados pelo cliente (8 s) |
|---|---:|---:|
| desligado | 56,3 s | 11 220 |
| fixo 200 (acima da capacidade) | 44,1 s | 389 |
| fixo 100 (abaixo) | 92,1 s | 0 |
| auto, AIMD pela latência (antes) | 76,4 s | 0 |
| auto, BBR + fila de logins (depois) | 46,4 s | 106 |

Depois, com a autenticação na frente do accounting e a janela pelo BDP (o ideal passa a
6000/300 = 20 s, porque os logins têm o servidor inteiro):

| `new_session_rate` | Todas no ar em | Logins abandonados pelo cliente (8 s) |
|---|---:|---:|
| desligado | 27,1 s | 5547 |
| fixo 200 | 44,7 s | 386 |
| fixo 100 | 92,1 s | 0 |
| auto | **20,2 s** | **0** |

Com os parâmetros da terceira rodada da VM (`wave_of_the_vm_round`, RADIUS de 3000/s): são 60 mil
CPEs, porque uma porta do modelo tem no máximo 65 mil SESSION_IDs e endereços.

| Variante | desligado | fixo 2000 | auto |
|---|---:|---:|---:|
| prioridade + janela pelo BDP | 27,1 s / 55 011 | 44,5 s / 3488 | **20,1 s / 0** |
| prioridade + janela antiga (2 × ritmo × base) | 27,1 s / 55 011 | 44,5 s / 3488 | 20,1 s / 0 |
| janela pelo BDP, sem prioridade | 56,1 s / 111 561 | 44,1 s / 3900 | 39,9 s / 0 |

(tempo até todas no ar / logins abandonados). No modelo, quem resolve é a prioridade. A janela
pelo BDP não muda o resultado aqui: o modelo não tem as retransmissões do cliente RADIUS nem as
do CPE, que na VM multiplicam o que um excesso de pedidos em voo custa.

### G4.3g-d — onda com o cliente RADIUS de verdade, simulada (**medido**, release, 2026-10-25)

`wave_with_the_real_client`: 60 mil CPEs contra 3000/s, com o `proto_radius::Client` (RTO
adaptativo, retransmissão, MRD) e o `TestServer` atrás de uma fila de capacidade fixa (2 s de
trabalho no máximo, cópia de pedido já na fila descartada). O modelo simples não tinha
retransmissões e não mostrava o auto pior da VM; este mostra.

| `new_session_rate` | Antes da correção dos timers | Depois (e janela inicial de 64) |
|---|---:|---:|
| desligado | 20,1 s / 0 / 55 808 | 20,1 s / 0 / 55 550 |
| fixo 2000 | 44,1 s / 24 / 46 844 | 44,1 s / 0 / 19 008 |
| auto | 25,3 s / 429 / 66 205 | **20,6 s / 0 / 0** |

(todas no ar / timeouts / retransmissões). O `load_sim` do proto-radius (100 mil pedidos com 3%
de perda e failover) foi de 24 810 para 22 823 retransmissões, e de 10 190 para 6223 cópias que
caíram no cache de duplicatas do servidor.

### G4.3g-d — onda de 100 mil com o BNG Blaster, quarta rodada (**medido**, VM corerouter-lab, 8 vCPUs, 16 GiB, kernel 7.0, release, 2026-10-25)

Com a prioridade da autenticação e a janela pelo BDP; antes da fila por worker, da correção dos
timers do cliente e da janela inicial.

| `new_session_rate` | Todas no ar em | Timeouts | Retransmissões | Pico do limite |
|---|---:|---:|---:|---:|
| desligado | 42,1 s | 1 | 59 354 | — |
| fixo 2000 | 36,5 s | 1 | 93 555 | — |
| auto | 62,4 s | 5741 | 91 524 | 3693/s |

Workers na mesma rodada (socket por worker sem fila): 1 worker 10,5 mil/s, 6 workers 22,4 mil/s,
com o BNG Blaster a 90% de um núcleo.

### G4.3g-d — onda de 100 mil com o BNG Blaster, terceira rodada (**medido**, VM corerouter-lab, 8 vCPUs, 16 GiB, kernel 7.0, release, 2026-10-25)

`cargo xtask bng-lab --root --only wave --wave 100000 --radius-cap 3000`, antes da prioridade
da autenticação e da janela pelo BDP. O teto era de ~1500 logins/s, porque o accounting dividia
o servidor (ideal ≈ 67 s).

| `new_session_rate` | Todas no ar em | Sessões/s | Timeouts | Retransmissões | Pico do limite |
|---|---:|---:|---:|---:|---:|
| desligado | 69,4 s | 1440 | 2607 | 170 043 | — |
| fixo 2000 | 94,6 s | 1057 | 3923 | 236 473 | — |
| auto | 106,7 s | 937 | 4428 | 204 502 | 5503/s |

Workers na mesma VM, 100 mil sessões: 1 worker deu 15,2 mil/s e 6 deram 57,9 mil/s, ainda
com o leitor único (`svc-pppoe` a 51%). O socket por worker, testado nas rodadas 4 e 5, foi descartado.

### G4.3g-d — recepção por socket de cada worker, descartada (**medido**, AMD Ryzen AI Max+ 395, release, 2026-10-25)

`tests/netns_pppoe_lanes.rs` (commit 8c3859f; saiu com o código descartado): 200 mil PADIs de MACs diferentes num veth, CPU por quadro da thread
receptora mais ocupada (a parte serial, que limita a taxa), duas rodadas.

| Workers | Leitor + canal (fica) | Socket próprio por worker (descartado) |
|---|---:|---:|
| 1 | 600 ns | 550 ns |
| 2 | 550–650 ns | 350 ns |
| 4 | 800–1050 ns | 350 ns |
| 6 | 550–750 ns | 150 ns |

Cada quadro chegou a exatamente um worker, o que o `lane_of` indica. A parte serial cai, mas
na VM o conjunto ficou abaixo do leitor (rodadas 4 e 5).

### G4.3g-d — workers e onda, quinta rodada (**medido**, VM corerouter-lab, 8 vCPUs, 16 GiB, kernel 7.0, release, 2026-10-25)

Com o cliente RADIUS corrigido, a janela inicial e o socket por worker com fila (depois
descartado). São 100 mil sessões; a onda é contra um RADIUS de 3000/s.

| `new_session_rate` | Todas no ar em | Sessões/s | Timeouts | Retransmissões |
|---|---:|---:|---:|---:|
| **auto** | **33,6 s** | **2978** | **0** | **0** (pico do limite 2990/s) |
| desligado | 36,1 s | 2774 | 2 | 90 161 |
| fixo 2000 | 39,8 s | 2510 | 5 | 64 574 |

Workers com socket próprio e fila: 1 worker 14,3 mil/s (46 234 quadros perdidos antes do BNG), 6
workers 24,0 mil/s (0 perdidos, BNG Blaster a 91%). Com o leitor único, na rodada 3, eram 15,2
mil/s e 57,9 mil/s: o leitor voltou.

### G4.3g-d — workers, sexta rodada (**medido**, VM corerouter-lab, 8 vCPUs, 16 GiB, kernel 7.0, release, 2026-10-25)

O leitor único de volta, com o filtro das cópias de saída e o `rx_dropped`. São 100 mil sessões,
com o BNG Blaster a 65 535/s.

| Workers | Sessões/s | Tempo | CPU | Quadros perdidos antes do BNG |
|---|---:|---:|---|---:|
| 1 | 14 530 | 6,9 s | worker 43%, leitor 11% | 30 967 |
| 6 (`auto`) | **57 733** | 1,7 s | workers 216%, leitor 49%, BNG Blaster 67% | 0 |

Contra os 57 889 da rodada 3, a diferença é ruído: o filtro e o contador não custam nada que se
meça.

Com 1 worker, a rajada de 100 mil PADIs em 1,5 s enche o canal (65 536) e o socket. O que sobra
se perde, e o CPE repete o PADI (RFC 2516 §5): todas sobem. O operador deve deixar
`workers=auto`; um `rx_dropped` crescendo fora de uma volta de energia quer dizer workers
de menos.

### G4.3g-d — rajada contra workers ocupados (**medido**, AMD Ryzen AI Max+ 395, release, 2026-10-25)

`a_burst_against_busy_workers` (`tests/netns_pppoe_lanes.rs`, commit 8c3859f): 100 mil PADIs escritos na
velocidade máxima num veth, 5 µs de trabalho por quadro, quadros que os workers receberam. Um
socket de 4 MiB guarda 8739 PADIs (`a_busy_worker_socket_holds_a_burst`).

| Workers | Leitor + canal | Socket lido entre quadros (rodada 4) | Socket + fila do worker |
|---|---:|---:|---:|
| 1 | 77 169 (0,66 s) | 18 756 (kernel: 81 236 perdidos) | **100 000** (0,67 s) |
| 4 | 100 000 (0,36 s) | 95 285 (4714 perdidos) | **100 000** (0,37 s) |

No netns o socket com fila empata com o leitor; na VM, com o BNG Blaster, ficou abaixo (rodada
5). Vale o número da VM.

G4.3cd, **medido** na VM `corerouter-lab` (virtio/veth, XDP generic, objeto release, 2026-10-26):
10 000 sessões com 1–4 blocos (25 000): incluir 92 ms (3,7 µs/bloco; a primeira versão contava os
blocos a cada inclusão e levava 11,2 s), remover 41 ms; por pacote, piso 120–133 ns, próprio /32
150–168 ns, host de /29 roteado 182–232 ns, de /56 191–241 ns, com uma tag no uplink 193–240 ns,
duas 200–246 ns. A/B com o objeto da `main` (100 mil sessões, mesmo teste alternado): descida ao
próprio endereço 156–168 → 165–190 ns, subida e piso iguais no ruído. Userspace
(`--bench framed_routes`, Ryzen AI Max+ 395, release): login com 4 rotas + logout 0,64 µs (vazia) e
1,64 µs (10 000 sessões, 25 000 blocos), busca do caminho lento 11 → 33 ns, encher com 10 000
sessões 12,1 ms.

### G4.3h — sync do BNG em alta disponibilidade (`proto-ha`), **medido** 2026-10-26, Ryzen AI Max+ 395, release

| Benchmark | Mediana | Observação |
|---|---|---|
| `ha_record/encode` | 48 ns | registro de 161 B |
| `ha_record/decode` | 99 ns | |
| `ha_delta/2048_changes_through_the_codec` | 2,06 ms | ≈ 1 µs por mudança (montagem do registro incluída) |
| `ha_snapshot/100k_sessions` | 55 ms | 216 B por sessão no fio (21 MiB) |
| `ha_access_hello/encode+decode` | 372 ns | HMAC-SHA-256 |

Memória: réplica 400 B por sessão, publicador (tabela + log) 389 B por sessão (RSS, 100 mil).

- 2026-10-26, G4.3k (**medido**, Ryzen AI Max+ 395, release, criterion): PADI → PADO sem nomes
  191 → 196–198 ns, +1 % (no ruído). Com 512 nomes, pedindo o último: 1,04 µs com a busca
  linear e **209 ns** com o índice por hash (−80 %). Simulação em memória: 20 000 assinantes, 40
  nomes e 5000 VLANs QinQ em 0,67 s.

### G4.3h — sessão PPPoE de um servidor para outro, **medido** 2026-10-26, Ryzen AI Max+ 395, release

| Benchmark | Mediana | Por sessão |
|---|---|---|
| `pppoe_ha/export_20k` | 1,48 ms | 74 ns |
| `pppoe_ha/import_20k` | 4,84 ms | 242 ns (com o `Server::new`) |

### Filas: shaper EDT, policer GCRA, EDT × HTB (G4.9b, 2026-10-26, **medido**)

VM do laboratório (8 vCPUs EPYC-Genoa host-model, 16 GiB, kernel 7.0), objeto release, testes em
build de teste, veth.

- Precisão do shaper (cada alvo a ≥ 11× a taxa): 1 alvo a 344 Mbit/s +0,66%; 100 a 6,6 Mbit/s
  +0,67%; 10 000 a 10 kbit/s +0,69% a +1,33% (duas rodadas).
- TCP 50 Mbit/s, 20 ms de RTT, 10 s: shaper fq-codel 49,7 Mbit/s e 536 retransmissões (sem GSO:
  47,9 e 35); policer balde 0,1 s 49,3 e 852 (sem GSO: 1663); policer balde 0,05 s (o antigo) 47,5
  e 715; pfifo 10 49,4 e 1783.
- Policer de um assinante, 1/4/8/16 remetentes presos a CPUs, 200 Mbit/s: antes +4,87% (4),
  +14,87% (8), +14,97% (16); depois −0,22% a −0,42%.
- EDT × HTB, 1,5× da taxa total em pacotes de 128 B, 4 filas de transmissão, RPS/XPS: 1 000 alvos
  EDT +0,0% com 28,7–31,6% de CPU e 1,0 s para montar; HTB uma raiz −9,9%, 30–32%, 0,06 s; HTB
  por CPU +14–16%, 35–37%, 0,4 s. 10 000 alvos: EDT +7,1%, 28,5%, 0,9 s; HTB uma raiz −10,3%,
  36–39%, 7,4–9,2 s; HTB por CPU não terminou de montar em 23 min.
- Subida PPPoE (`BPF_PROG_TEST_RUN`, um pacote por chamada): 164–169 ns na `main`, 172–176 ns com
  o GCRA atômico.

### G4.3gb / G0.21 / G0.22 — linha de base (**medido**, AMD Ryzen AI Max+ 395, 32 CPUs, release, 2026-10-26, `main` 626c0c25, máquina compartilhada, load ~10)

`cargo bench -p corerouter-engine --bench config_store -- --save-baseline antes` (e `transactional`,
`scale`, `storage-fs commit`). Lote = 100 `ppp.secret.add`; o tempo é do lote inteiro.

| Benchmark | 1 mil | 10 mil | 100 mil |
|---|---:|---:|---:|
| `config_store/ppp_secret_add/single` | 1,51 ms | 17,3 ms | 219 ms |
| `config_store/ppp_secret_set/single` | 1,54 ms | 17,6 ms | 220 ms |
| `config_store/ppp_secret_add/batch_step` (100 passos, commit por passo) | 157 ms | 1,69 s | 20,9 s |
| `config_store/ppp_secret_add/atomic_step` (100 passos, um commit) | 2,38 ms | 24,0 ms | 219 ms |
| `storage_fs/commit/ppp_secret_add` (disco, fsync) | — | 20,0 ms | 219 ms |

| Benchmark | Antes |
|---|---:|
| `engine_txn/single/address_list_add/60000` | 717 µs |
| `engine_txn/single/address_list_add_remove/60000` | 1,40 ms |
| `engine_txn/single/interface.set/routes_10000` | 4,3 µs |
| `engine_txn/build/2000` | 21,7 ms |
| `engine_txn/build/8000` | 244 ms |
| `engine_scale/validate_all/routes/10000` | 1,31 ms |
| `engine_scale/commit/routes/10000` | 6,01 ms |
| `engine_scale/commit/filter_rules/3000` | 1,15 ms |
| `engine_scale/commit/addresses/10000` | 3,19 ms |
| `engine_scale/commit/address_lists/20000` | 3,97 ms |
| `storage_fs/commit/routes_history64/10000` | 11,2 ms |

### G0.21 — `CowList` × `CowArc<Vec>` (**medido**, AMD Ryzen AI Max+ 395, release, 2026-10-26, `cargo bench -p corerouter-model --bench cow_list`)

100 000 `PppSecret`, a lista compartilhada com outra cópia (o ponto de rollback, a config em
execução), uma escrita. Tamanho do bloco escolhido pela medição:

| Benchmark | `CowArc<Vec>` | blocos de 32 | 64 | **128** | 256 |
|---|---:|---:|---:|---:|---:|
| `set_shared` (um item no meio) | 5,84 ms | 27,1 µs | 16,2 µs | **13,3 µs** | 17,6 µs |
| `push_shared` | — | 26,2 µs | 14,7 µs | **8,5 µs** | 12,8 µs |
| `remove_shared` (no meio) | — | 28,2 µs | 17,2 µs | **13,8 µs** | 18,2 µs |
| `walk` (filtro nos 100 mil) | 66–73 µs | 97 µs | 78 µs | **74 µs** | 81 µs |
| `get` (posição) | — | 10 ns | 9,6 ns | **7,9 ns** | 7,0 ns |

`CowMap` com 100 mil nomes: inserir numa cópia compartilhada 1,6 µs; consultar 9,9 ns.
Memória: o espinho custa 16 bytes por bloco (0,13 byte por item com blocos de 128); cada revisão
do histórico que mudou a lista guarda o seu espinho (12,5 KB com 100 mil itens) e os blocos que
mudou.

### G0.21 — listas em blocos nas seções (**medido**, AMD Ryzen AI Max+ 395, release, 2026-10-26, contra a linha de base `antes` da parte a)

| Benchmark | Antes | Depois |
|---|---:|---:|
| `engine_txn/single/address_list_add/60000` | 717 µs | **10,9 µs** |
| `engine_txn/single/address_list_add_remove/60000` | 1,40 ms | 21,1 µs |
| `engine_txn/build/2000` (por comando) | 21,7 ms (10,8 µs) | 12,1 ms (6,0 µs) |
| `engine_txn/build/8000` (por comando) | 244 ms (30,5 µs) | 60,8 ms (7,6 µs) |
| `config_store/ppp_secret_add/single/1000` | 1,51 ms | 290 µs |
| `config_store/ppp_secret_add/single/10000` | 17,3 ms | 1,14 ms |
| `config_store/ppp_secret_add/single/100000` | 219 ms | 16,2 ms |
| `config_store/ppp_secret_set/single/100000` | 220 ms | 13,1 ms |
| `config_store/ppp_secret_add/batch_step/100000` (100 passos) | 20,9 s | 1,59 s |
| `config_store/ppp_secret_add/atomic_step/100000` (100 passos) | 219 ms | 19,5 ms |
| `storage_fs/commit/ppp_secret_add/100000` (disco, fsync) | 219 ms | 24,8 ms |
| `storage_fs/commit/ppp_secret_add/10000` | 20,0 ms | 5,5 ms |
| `engine_scale/commit/address_lists/20000` | 3,97 ms | 3,26 ms |
| `engine_scale/commit/routes/10000` | 6,01 ms | 5,80 ms |

O que sobra no `ppp.secret.add` com 100 mil (instrumentação temporária): o comando ~70 µs,
`persist::encode_config` da config inteira 9,8 ms (o limite de tamanho e o texto do slot) e o
`save` 2,2 ms (o slot com a config inteira). Isso é a G0.22 (commit incremental), o PR seguinte.

### G0.21 parte d — 10 mil filas (**medido**, AMD Ryzen AI Max+ 395, release, 2026-10-26)

`config_store/identity_set/queues/10000` (novo): `system.identity.set` com 10 mil `queue.simple`
(criadas por `queue.simple.add` num lote atômico), um commit que não toca nas filas. Antes = esta
branch com `queue.simple` ainda em `Vec` (já com a G0.22); a sessão da G4.9 mediu ~41 ms na
`main` em outra rodada.

| Benchmark | Antes | Depois | Meta |
|---|---:|---:|---|
| `config_store/identity_set/queues/10000` | 71,3 ms | **71,8 µs** | < 1 ms |

De onde vinham os 71 ms (instrumentação temporária): detectar seções alteradas e validar 6–7 ms
(as filas comparadas por valor), o delta da revisão 28 ms e a gravação 34 ms (a seção `queue`
inteira em JSON duas vezes), o `apply` do laboratório 3,6 ms.

### G0.22 — validação e plano incrementais (**medido**, AMD Ryzen AI Max+ 395, release, 2026-10-26, contra a linha de base `antes` da parte a da G0.21)

| Benchmark | Antes | Depois |
|---|---:|---:|
| `engine_scale/commit/routes/10000` (comentário numa interface) | 6,01 ms | 2,63 ms |
| `engine_scale/commit/routes/1000` | 0,66 ms | 0,33 ms |
| `engine_scale/commit/filter_rules/3000` | 1,15 ms | 0,76 ms |
| `engine_scale/commit/addresses/10000` | 3,19 ms | 1,64 ms |
| `storage_fs/commit/routes_history64/10000` (disco) | 11,2 ms | 6,7 ms |
| `config_store/ppp_secret_add/single/100000` | 219 ms | 14,3 ms |

Com 10 mil rotas, um `interface.set comment` gastava 1,12 ms validando e 1,47 ms no `apply`
do laboratório (as rotas do kernel recalculadas porque a interface "mudou"); agora as duas
partes somam ~10 µs (instrumentação temporária). Os 2,2 ms que sobram são a serialização da
config inteira (`persist::encode_config`), assunto da parte b.

Paralelismo (**medido**, `engine_scale/validate_unit/*/routes/10000`, novo): com 10 mil rotas a
unidade de rotas leva 1,39 ms e cada uma das outras 11 menos de 0,1 µs. Dividir as unidades entre
threads não ganharia nada; só dividir a própria unidade de rotas (por tabela e destino, que ela já
agrupa) ajudaria, e só na validação inteira (boot, config restaurada), não no commit. O engine
compila para WASM, sem threads; fica anotado, sem gap (custo pequeno e fora do caminho do commit).

### G4.3gb / G0.21 / G0.22 — depois (**medido**, AMD Ryzen AI Max+ 395, 32 CPUs, release, 2026-10-26, contra a linha de base `antes` da parte a; máquina compartilhada)

| Benchmark | Antes | Depois |
|---|---:|---:|
| `config_store/ppp_secret_add/single/1000` | 1,51 ms | 102 µs |
| `config_store/ppp_secret_add/single/10000` | 17,3 ms | 83 µs |
| `config_store/ppp_secret_add/single/100000` | **219 ms** | **134 µs** |
| `config_store/ppp_secret_set/single/100000` | 220 ms | 209 µs |
| `config_store/ppp_secret_add/batch_step` 1 mil / 10 mil / 100 mil (por passo, commit por passo) | 1,57 / 16,9 / 209 ms | **90 / 101 / 153 µs** |
| `config_store/ppp_secret_add/atomic_step` 1 mil / 10 mil / 100 mil (lote de 100) | 2,38 / 24,0 / 219 ms | 0,89 / 0,91 / 1,36 ms |
| `engine_txn/single/address_list_add/60000` | 717 µs | **9,8 µs** |
| `engine_txn/build/2000` / `8000` (por comando) | 10,8 / 30,5 µs | 5,1 / 6,3 µs |
| `engine_scale/commit/routes/10000` (comentário numa interface) | **6,01 ms** | **0,16 ms** |
| `engine_scale/commit/filter_rules/3000` | 1,15 ms | 0,20 ms |
| `engine_scale/commit/addresses/10000` | 3,19 ms | 0,13 ms |
| `engine_scale/commit/address_lists/20000` | 3,97 ms | 0,11 ms |
| `storage_fs/commit/ppp_secret_add/100000` (disco, fsync) | 219 ms | 2,7 ms |
| `storage_fs/commit/routes_history64/10000` (disco) | 11,2 ms | 2,9 ms |
| `storage_fs/history64/commit/10mib` (disco) | 44,8 ms | 3,0 ms |

Em disco o que sobra (~2,5 ms) é o `fdatasync` do append do journal e do arquivo de revisão;
sem disco, o commit de um secret com 100 mil custa ~0,1 ms. O checkpoint (a cada até 1024
commits) custa o que um commit custava antes: 4 ms com 1 mil secrets, 19 ms com 100 mil
(**medido**, sonda temporária, máximo de 2000 adds).

Boot com journal (`storage_fs/history64/boot`): 5 MiB 164 ms e 10 MiB 262 ms, contra 149 e 208 ms
medidos na `main` antes do G0.22 (`docs/perf.md`, G0.20; rodadas diferentes, máquina carregada): o
replay de até 1024 linhas. A G0.27 (checkpoint no desligamento) zera esse custo no boot normal.

Memória (**medido**, RSS, 1 milhão de `PppSecret`): 256 B por item em `Vec` e em `CowList` (o
espinho é 0,13 B por item); o índice de nomes, 82 B por secret. Cada revisão do histórico que
mudou uma lista guarda o seu espinho (12,5 KB com 100 mil itens) e os blocos que mudou.

Paralelismo: o commit é sequencial por desenho (uma transação por vez, sob o lock da sessão). O
que era O(n) por commit saiu do caminho (validação, plano, serialização, gravação); o que sobra é
O(seções pequenas + blocos alterados) e o fsync, que não se divide. As cópias da config continuam
lidas sem lock pelas threads dos serviços (PPPoE, IPoE).

### G4.3h: hot standby no serviço `pppoe` (2026-10-26)

**Medido** com `cargo bench -p corerouter-daemon --bench pppoe_bng`: release, Ryzen AI Max+ 395,
load 14–19 de outras sessões, mediana de 3 execuções.

40 mil logins em rodadas de 256, com o lock do par preso 8 ms a cada 10 ms:

| | 1 worker | 8 workers |
|---|---:|---:|
| sem HA | 67 570/s | 331 743/s |
| hot standby, o worker espera o lock | 23 854/s | 179 141/s |
| hot standby, `try_lock` + fila do worker | 63 469/s | 302 470/s |

Os contadores para o standby, a cada 10 s:

| | 50 mil sessões, um worker |
|---|---:|
| varredura própria debaixo do lock compartilhado (antes) | 22 ms |
| na passada do `tick` (agora) | ≈ 1 ms a mais |

Montar 1000 sessões custa 15–18 ms com e sem hot standby (dentro do ruído).

- 2026-10-26, G4.3l (**medido**, Ryzen AI Max+ 395, kernel 7.0, veth em namespace): cada socket
  `AF_PACKET` de VLAN custa 35–58 ns por quadro da porta (quadro enviado e recebido em 0,60 /
  0,65 / 2,8 / 30,5 µs com 0 / 1 / 64 / 512 sockets). e2e: 400 linhas QinQ abertas em 0,03 s
  (debug, caminho lento).

- 2026-10-26, G4.3l (**medido**, Ryzen AI Max+ 395, release, criterion): consulta IPv6 do caminho
  lento do PPPoE por maior prefixo, ~16 ns com 200 000 prefixos (100 000 sessões com /64 e /56);
  `cargo bench -p corerouter-daemon --bench pppoe_bng -- pppoe_slow6`.

### Filas com 10 000 entradas fixas (G4.9c) — **medido**, release, 1 CPU, 2026-10-26

| operação | antes | depois |
|---|---:|---:|
| lote de 10 000 `queue.simple.add` | 297 s | 26 s |
| um `queue.simple.add` | 133 ms | 44 ms (o `system.identity.set` custa 41 ms) |
| `queue.simple.preview` | 113 ms | 19 ms |

`free_name` deixou de ser O(n²) e o `add`/`set` deixou de montar o plano inteiro para ler os
avisos de uma fila (`queue::fixed_warnings`). O resto (~41 ms por escrita) é o commit genérico da
config, que a sessão do `CowList` está trocando.

### Filas no BNG Blaster (G4.9d) — **medido**, VM 8 vCPUs, kernel 7.0, release, 2026-10-26

| sessões | plano | shaper: descida/limite (mín–máx) | fila média | policer: descida/limite | CPU shaper / policer |
|---:|---|---|---:|---|---|
| 100 | 1M/2M | 1,002 (0,994–1,011) | 50 ms | 1,000 | 3,4% / 2,3% |
| 1 000 | 100k/200k | 1,015 (0,970–1,041) | 120 ms | 0,987 | 6,5% / 3,2% |
| 10 000 | 10k/20k | 1,023 (0,961–1,058) | 808 ms | 1,077 | 8,3% / 4,6% |

### CI do lote em jobs paralelos (processo, 2026-10-26)

**Medido** no GitHub Actions (`ubuntu-latest`, 4 vCPU), lote da fila (`workflow_dispatch`).

Antes: um job, passos em série. Os últimos 8 lotes verdes levaram de 18,2 a 26 min no job
`xtask ci (linux)` (mediana ~23 min). Um deles por passo (run 40395078035, 21,8 min): fmt 2 s,
clippy 35 s, test 4 min 49 s (compilação 91 s, execução 198 s), bench-check 9 min 55 s
(compilação 21 s, execução ~9,5 min), netns 1 min 42 s, xdp-root 3 min 25 s,
docs/layers/agents-sync/wasm ~20 s, preparação ~1 min.

Depois (runs 40406439545, cache frio, e 40407532159, cache quente):

| Job | Frio | Quente | Onde vai o tempo (quente) |
|---|---|---|---|
| `lint` | 3 min 8 s | 86 s | clippy 34 s, wasm 17 s |
| `test` | 7 min 9 s | 6 min 6 s | compilação 96 s, execução 235 s |
| `bench-check` | 5 min 33 s | 4 min 51 s | compilação (opt-level 1) 2 min 40 s, execução 104 s |
| `netns` | 2 min 54 s | 2 min 55 s | compilação 24 s, execução 70 s |
| `xdp-root` | 4 min 27 s | 4 min 33 s | compilação 16 s, execução ~3 min 54 s |
| build macOS / Windows | 1 min 54 s / 2 min 18 s | 90 s / 187 s | (não mudou) |
| **run inteiro** | **7 min 29 s** | **6 min 25 s** | o caminho crítico é o `test` |

`bench-check` local (AMD Ryzen AI MAX+ 395, 32 CPUs), só a execução: debug em série 353 s
(`ui frames` 126 s); perfil `bench-check` em série 108 s (`frames` 57 s); perfil
`bench-check` em paralelo ~61 s (limitado pelo `frames`). A montagem de 1M de rotas do
`ui_frame/routes_1m` é o que sobra: ~100 s no CI mesmo otimizado.

Paralelismo: os passos não dependem um do outro, então cada job compila o que precisa no
próprio runner (4 vCPU cada) em vez de dividir um runner. O que fica em série é o `test`
(compilação + 2613 testes no nextest); próximo passo, se precisar: dividir o `test` em duas
partições do nextest (`--partition count:i/2`), ~1,5 min a menos **estimado**.

### G0.21 parte e — índice do IPoE (**medido**, AMD Ryzen AI Max+ 395, release, 2026-10-26)

`config_store/ipoe_index/*` (novo): o que a rodada do DHCP paga para seguir uma config com N
secrets IPoE e N concessões fixas com `rate_limit`, depois de um `ppp.secret.add`
(`secret_add`) ou da troca do `rate_limit` de uma concessão (`lease_set`). Antes =
`IpoeIndex::of` (refeito do zero); depois = `IpoeIndex::refresh`.

| Benchmark | Antes | Depois |
|---|---:|---:|
| `config_store/ipoe_index/secret_add/1000` | 104 µs | 22 ns |
| `config_store/ipoe_index/secret_add/10000` | 1,01 ms | 20 ns |
| `config_store/ipoe_index/secret_add/100000` | **22,5 ms** | **20 ns** |
| `config_store/ipoe_index/lease_set/1000` | 104 µs | 4,7 µs |
| `config_store/ipoe_index/lease_set/10000` | 995 µs | 9,2 µs |
| `config_store/ipoe_index/lease_set/100000` | **22,5 ms** | **35 µs** |

O que sobra no `lease_set` cresce com N/128: o `shared_blocks` monta um mapa dos blocos da
lista antiga (782 com 100 mil) para achar os que mudaram.

### G0.21 parte f — filas simples (**medido**, AMD Ryzen AI Max+ 395, release, 2026-10-26)

`config_store/queue_simple_add/*` e `config_store/queue_sync/idle/*` (novos). Antes = `main` em
`ee8b1b05` (com a G4.9c); depois = esta branch. `batch_step`/`atomic_step`: lote de 100 adds.

| Benchmark | Antes | Depois |
|---|---:|---:|
| `queue_simple_add/single/1000` | 593 µs | 108 µs |
| `queue_simple_add/single/10000` | 4,81 ms | 87 µs |
| `queue_simple_add/single/80000` | **39,5 ms** | **142 µs** |
| `queue_simple_add/unnamed/80000` | 41,3 ms | 140 µs |
| `queue_simple_add/batch_step/10000` | 483 ms | 11,0 ms |
| `queue_simple_add/batch_step/80000` | **5,34 s** | **16,5 ms** |
| `queue_simple_add/atomic_step/80000` | 4,64 s | 2,48 ms |
| `queue_sync/idle/1000` | 917 µs | 82 ns |
| `queue_sync/idle/10000` | 8,67 ms | 80 ns |
| `queue_sync/idle/80000` | **99,1 ms** | **83 ns** |

Numa transação (pedido da sessão do CI: o `config_store` levava 104–211 s no `bench-check` desde
o #268, quase tudo montando as 10 mil filas do `identity_set/queues`), medido com um teste
temporário em release, 10 mil `queue.simple.add`:

| Caso | `main` | Depois |
|---|---:|---:|
| lote atômico de 1 000 | 237 ms | 9,2 ms |
| lote atômico de 10 000 | **22,2 s** | **92 ms** |
| modo transacional, 10 000 adds + `config.commit` | 22,2 s | 192 ms |
| modo transacional, 50 000 adds + `config.commit` | — | 1,12 s |

`cargo bench -p corerouter-engine --bench config_store -- --test` (o modo do `bench-check`) roda
inteiro em 1,1 s nesta branch. O caso não foi encolhido: ele é o que um provisionamento faz.

O que sobra num add (~0,1 ms) é o commit (journal, validação incremental, aplicar). O `queue_sync`
ainda lê as concessões do DHCP com `rate_limit` a cada rodada (`dhcp_dynamic`, O(concessões));
sem concessões com velocidade isso é nada.

### G0.22 parte c — prefixos do XDP (**medido**, AMD Ryzen AI Max+ 395, release, 2026-10-26)

`xdp_prefixes/*` (novo): N entradas numa block list. `plan_of` = o caminho antigo
(`XdpPlan::of` + diferença por `BTreeMap`); `follow` = `XdpPrefixes`. Só a parte em espaço de
usuário; as escritas nos mapas são uma chamada por prefixo mudado nos dois.

| Mudança | N | Antes (`plan_of`) | Depois (`follow`) |
|---|---:|---:|---:|
| commit sem relação | 1 000 | 63 µs | 47 ns |
| commit sem relação | 10 000 | 928 µs | 76 ns |
| commit sem relação | 100 000 | **11,5 ms** | **0,30 µs** |
| um `address-list.add` | 1 000 | 64 µs | 15,8 µs |
| um `address-list.add` | 10 000 | 954 µs | 5,6 µs |
| um `address-list.add` | 100 000 | **11,2 ms** | **43 µs** |
| uma entrada dinâmica | 1 000 | 62 µs | 118 ns |
| uma entrada dinâmica | 10 000 | 949 µs | 168 ns |
| uma entrada dinâmica | 100 000 | **11,4 ms** | **0,82 µs** |

O `address-list.add` cresce com N/128 (o mapa de blocos do `shared_blocks`).

### G0.27 — boot depois do checkpoint de desligamento (**medido**, AMD Ryzen AI Max+ 395, release, disco, 2026-10-26)

`storage_fs/history64/boot` com o journal perto do máximo (1 000 linhas pequenas, um
`interface.set` cada) e `…/boot_after_checkpoint` (novo): o mesmo diretório depois de
`Session::checkpoint()`.

| Config | Boot com 1 000 linhas | Checkpoint | Boot depois |
|---|---:|---:|---:|
| 5 MiB | 144 ms | 20–24 ms | 134 ms |
| 10 MiB | 213 ms | 35,6 ms | 204 ms |

O ganho no boot é pequeno com linhas pequenas (o replay de 1 000 deltas de uma interface custa
~10 ms; quase todo o boot é ler o slot). Ler a revisão pela cabeça da linha para pular sem
analisar as que o slot já tem foi medido e não mudou nada (135 e 204 ms): ficou de fora. O valor
da G0.27 é a volta de versão sem perda; o custo é um checkpoint (20–36 ms) por parada limpa.

- 2026-10-26, G4.3l (**medido**, VM `corerouter-lab`, 8 vCPUs, kernel 7.0, release, BNG Blaster
  1.0.1): 4000 linhas QinQ 1:1 (4 S-tags × 1000 C-tags) com Service-Name e TR-101 sobem a 7843–7894
  sessões/s com XDP e 7794 sessões/s no caminho lento; 8000 de 8000 fluxos verificados nos dois.

### G4.3n: importação de secrets do RouterOS (2026-10-26)

**Medido** (build release, laptop de desenvolvimento compartilhado, 2026-10-26; `cargo test --release
-p corerouter-engine --test ppp_import -- --ignored --nocapture`), 100 mil secrets com caller-id,
comentário e endereço fixo (17,0 MB de export): leitura 125–133 ms (750–800 mil linhas/s), `dry_run`
0,44–0,58 s, importação 0,47–0,64 s (~5 µs/secret, com a selagem), commit dos 100 mil 63–65 ms (214 ms antes do CowList), 40 mil
no modo imediato 0,19–0,20 s; pico 367–372 MB (VmHWM). Config: 21,8 MB em claro, 26,5 MB selada (+22 %).
Abrir uma senha: XChaCha20-Poly1305 1,33 µs, ChaCha20-Poly1305 0,98 µs, AES-256-GCM 0,094 µs (só a
cifra); 0,5 µs de ponta a ponta. `pppoe_bng/setup_1000_sessions`: em claro 12,23–15,19 ms, selado 12,51–15,39 ms
(+1 a +5 %; com XChaCha20-Poly1305 era +13 %).

### CI do lote: partes do `test` e do `xdp-root` (processo, 2026-10-26)

**Medido** no GitHub Actions (`ubuntu-latest`, 4 vCPU por runner), lote via `workflow_dispatch`.
Runs 40410630612, 40411738352 e 40413648189, cache quente:

| Configuração | `test` (maior parte) | `xdp-root` (maior parte) | `bench-check` | Run inteiro |
|---|---|---|---|---|
| test 1 job, xdp-root 1 job | 366 s | 273 s | 291 s | 6 min 25 s |
| test 2 partes `count`, xdp-root 2 | 304 s (outra: 161 s) | 134 s | 249 s ¹ | **5 min 24 s** |
| test 2 partes `hash` + lentos primeiro | 267 s (outra: 174 s) | 142 s | 429 s ¹ | 7 min 28 s ¹ |
| test 3 partes `hash` | 237 s (outras: 231, 188 s) | 164 s | 397 s ¹ | 6 min 53 s ¹ |

¹ Desde o #268 (mesclado da `main` antes das três medições com partes), o `config_store` do
`bench-check` leva de 104 s a 211 s no CI, contra 12 s antes: montar 10 mil filas
`queue.simple` numa transação leva 117 s localmente, mesmo otimizado. A variação entre runners
(104 s contra ~210 s) decide se o caminho crítico é o `test` ou o `bench-check`. Corrigida
essa montagem, o `bench-check` volta a ~4,3 min e o lote fica em ~5 min 30 s (**estimado**).

Escolha: 2 partes. Com a contagem (`count`), os três testes longos (97, 64 e 62 s) caíram
todos na mesma parte, e o de 97 s começou por último (parte 1 em 174 s de execução, parte 2 em
55 s). Por hash, com os lentos primeiro, a execução das partes ficou em 141 s e 66 s: o limite é
o teste de ~100 s do `proto-pppoe::sim`. Uma terceira parte tirou só 30 s do maior job (237 s
contra 267 s), num job que já não é o caminho crítico, e custa mais uma compilação inteira
(~100 s de runner). Compilar uma vez e distribuir os binários (`cargo nextest archive` +
artifact) não ganha tempo de relógio: o job de build ainda compila 96 s, e soma compactar,
enviar e baixar os binários de teste, antes de as partes começarem (**estimado** ≥ 5 min, contra
~4,5 min compilando em cada parte).

### G4.9g — uma fila ao vivo e o histórico por fila (medido, notebook de desenvolvimento, build `bench`, 2026-10-26)

`cargo bench -p corerouter-engine --bench queue_live`:

| | 10 000 filas | 100 000 filas |
|---|---:|---:|
| `queue.simple.stats`, fila já resolvida (o 1 Hz da janela) | 2,2 µs | 2,2 µs |
| primeira chamada (índice de nomes + id) | 3,6 µs | 3,7 µs |
| primeira chamada com ids fora de ordem (depois de um `move`) | 3,8 µs | 3,8 µs |

Histórico: 448 728 bytes (438 KiB) por fila; 10 000 marcadas = 4,18 GiB.

Um segundo de histórico das filas (`queue_graph`, serviço `queue`, sob o lock da sessão):

| filas fixas (guardadas) | teto | antes | depois |
|---|---|---:|---:|
| 1 000 (1 000) | 4096 MiB | 387 µs | 105 µs |
| 4 000 (4 000) | 4096 MiB | 2,29 ms | 0,75 ms |
| 10 000 (136, 9 864 recusadas) | 64 MiB (padrão) | 1,83 ms | 0,41 ms |
| 10 000 (4 087, 5 913 recusadas) | 4096 MiB | 4,16 ms | 1,25 ms |

"Antes" é a primeira versão desta mesma parte, que alocava por fila a cada segundo (o conjunto
de nomes recusados, as chaves clonadas, um mapa de descartes); "depois", sem alocar por fila
(−68% a −77%).

Um quadro da UI (1400×900, `cargo bench -p corerouter-ui --bench frames`):

| | antes | depois |
|---|---:|---:|
| janela Queues sozinha | — | 0,10 ms |
| + "Queue <nome>" em Traffic (900 pontos, 15 min) | 2,21 ms | 0,20 ms |
| + "Queue <nome>" em Statistics | 2,17 ms | 0,18 ms |

O "antes" era o modal de lista montando o texto dos comandos (o registro inteiro) a cada quadro,
mesmo numa aba que não o mostra; nas abas ao vivo ele não é mais montado (−91%). As abas de
formulário (General/Advanced) continuam pagando ~2 ms por quadro, como todo modal de edição hoje.

### G4.10b — avisos ao assinante com 100 mil assinantes listados (**medido**, 2026-10-26)

AMD Ryzen AI MAX+ 395 (32 threads), kernel 7.0.0, build release, namespace sem root.

`cargo bench -p corerouter-hal-linux --bench netns_notice` (UDP de 64 B de um não membro, um núcleo, veth → dummy):

| Caso | pps | Carga da tabela |
|---|---|---|
| sem firewall | 1,63 M | — |
| 100 mil na lista, sem perfil | 1,64 M | 198 ms |
| 100 mil, perfil `block` (cadeias com 5 lookups por regra, antes do salto) | 0,94 M | 235 ms |
| 100 mil, perfil `block` com salto por perfil (o que entrou) | 1,24 M | 236 ms |
| 100 mil + masquerade (conntrack ligado, a base justa de um provedor) | 1,40 M | 201 ms |
| 100 mil + masquerade + perfil `block` | 1,24 M (−11%) | 227 ms |

- **Por pacote:** a cadeia nat do perfil liga o conntrack sozinha. Contra uma base com
  conntrack, o custo é −11% de pps: um lookup no conjunto e o gancho a mais, ~90 ns por pacote.
- **Atualização:** um assinante entrar e sair da lista com 100 mil já nela leva 20,3 ms ida e
  volta, isto é, dois processos `nft` de ~10 ms cada. Esse custo independe do tamanho do
  conjunto.

`cargo bench -p corerouter-engine --bench notice` (100 mil membros estáticos):

| Medida | Antes | Depois |
|---|---|---|
| `notice_tick`, nada mudou | 50,7 ms | 0,38 µs |
| `notice_tick`, todos novos | 56 ms | 26 ms |
| `throttle_queues`, 100 mil membros | 97 ms | 90 ms, e agora só quando o plano é refeito (antes, todo segundo no `queue_sync`) |
| `notice_profile_of`, membro | — | 59 ns |
| `notice_profile_of`, não membro (varre prefixos) | — | 0,91 ms |

`notice_profile_of` com não membro só roda em comando (`test`, `seen`); o portal lê o retrato
da G4.10c.

G2.1c — tabela raw, `crates/hal-linux/benches/netns_raw.rs` (**medido**): AMD Ryzen AI MAX+ 395
(32 threads), kernel 7.0.0, nft 1.0.9, build release, netns sem root, 2026-10-27,
`COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- cargo bench -p
corerouter-hal-linux --bench netns_raw`. UDP de 64 bytes por `AF_PACKET` → veth → `ip_forward` →
dummy, 4096 fluxos (256 destinos × 16 portas de origem), 20 000 quadros por amostra, regras
aplicadas por `LinuxHal::apply`; um núcleo faz tudo (o veth entrega no backlog da CPU que envia).

| Caso | Tempo por 20 000 | Taxa |
|---|---|---|
| `udp64/conntrack` (filter forward `ct state new,established,untracked accept`) | 17,0 ms | 1,17 Mpps |
| `udp64/raw notrack` (o mesmo + raw prerouting `notrack` UDP) | 16,2 ms | 1,24 Mpps (+5 %) |
| `udp64/filter drop (after conntrack)` | 17,0 ms | 1,17 Mpps |
| `udp64/raw drop (before conntrack)` | 12,9 ms | 1,55 Mpps (+32 %) |

Os casos de drop medem até o contador da regra parar de subir (lido por `nft -j` a cada 0,5 ms,
igual nos dois). O ganho do drop na raw é a entrada de conntrack que nunca é criada (no filter
ela é criada e jogada fora a cada pacote, porque nunca é confirmada).

### G2.7 — CGNAT sem portas (2026-10-27, **medido**)

Ryzen AI MAX+ 395, kernel 7.0, build release, netns sem root, carga 15–40 de outras sessões. Bench
`netns_cgnat_pps` (`COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- cargo bench -p
corerouter-hal-linux --bench netns_cgnat_pps`).

| Medida | Valor |
|---|---|
| conexões novas/s sem a chain × chain vazia × 4096 outros no conjunto (alternado, mediana de 9) | 280 557 × 285 774 × 261 922 |
| pps estabelecidos, idem | 746 648 × 756 634 × 759 061 |
| frame recusado → ICMP de volta | 125 µs |
| tempestade de recusas atendida (uma fila) | 188 mil/s, sem perda |
| ICMP em 20 mil recusas de um assinante em 0,39 s | 14 |

### G3.1 — FRR: socket vty em Rust × frr-reload.py × vtysh -f (**medido**, 2026-10-27)

Máquina: VM `corerouter-lab` (8 vCPUs host-model EPYC, 16 GiB, kernel 7.0), FRR 10.7.1 do
deb.frrouting.org, `frr_compare` em release (`scripts/frr-compare.sh`).
- Cada mudança parte da mesma config; o resultado é conferido no bgpd, no zebra e no mgmtd.
- Os prefix-lists são digitados no mgmtd e no bgpd.
- A memória é o pico de RSS do processo que aplica: o nosso, ou o `python3`/`vtysh` filho,
  amostrado em /proc.
- Os dois valores de cada célula são duas rodadas.
- O `frr.conf` volta ao do pacote antes de cada rodada (o `frr-reload.py` grava o dele), e as
  rotas são carregadas só depois das medidas de apply.

| Medida | (b) vty Rust, daemons em paralelo | (b) em série (antes) | (c) diff Rust + `vtysh -f` | (a) `frr-reload.py` |
|---|---|---|---|---|
| mudança pequena (router-id) | 1,4 / 1,1 ms; 4,4 MiB | 1,5 / 2,0 ms | 13,4 / 13,7 ms; 22,6 MiB | 144 / 152 ms; 18,5 MiB |
| mudança pequena (100 descrições) | 7,2 / 6,7 ms; 4,7 MiB | 8,3 / 35,8 ms | 21,6 / 19,8 ms; 22,6 MiB | 940 / 980 ms; 18,5 MiB |
| +10 mil entradas de prefix-list | 1766 / 1653 ms; 15,5 MiB | 5229 / 3324 ms | 1626 / 2946 ms; 22,7 MiB | 3693 / 4058 ms; 36,1 MiB |
| −5 mil entradas de prefix-list | 2494 / 2729 ms; 15,6 MiB | 5507 / 4930 ms | 2555 / 2754 ms; 22,7 MiB | 3652 / 3984 ms; 31,9 MiB |
| ler 100 sessões (`neighbors json` + parse) | 2,3 / 2,6 ms | 3,1 / 3,1 ms | — | 10,2 / 12,0 ms (`vtysh -c`); 22,8 MiB |

1 M de rotas no zebra (rotas do kernel importadas; `ip -batch` levou 6–23 s):

| Medida | (b) vty Rust | (a) `vtysh -c` |
|---|---|---|
| `show ip route json` (537 MiB de JSON) | 13,2 / 13,2 s; 540 MiB (guarda tudo) | 13,4 / 13,2 s; 22,7 MiB (vai para o pipe) |
| interpretar como `serde_json::Value` | 5,7 / 5,7 s; pico de 5,2 GiB | — |
| `show ip route summary json` | 122 / 130 ms | 138 / 138 ms |

Parse e diff do `frr.conf` sem FRR (criterion, `cargo bench -p corerouter-hal-frr`; desktop do
usuário, release):

| Medida | Tempo |
|---|---|
| parse de 10 mil entradas + 100 vizinhos | 345 µs |
| diff com 1 linha mudada | 1,09 ms |
| diff removendo 5 mil de 10 mil | 1,01 ms |
| diff de tudo, a partir do vazio | 444 µs |
| render de volta para texto | 40 µs |

O tempo que sobra no apply é do FRR (~170–270 µs por linha em cada daemon). O parse e o diff em
Rust são menos de 0,1 % disso.

### G1.6a — imagem do sistema: build, boot e memória (**medido**, AMD Ryzen AI Max+ 395, 32 threads, 62 GiB, NVMe, 2026-10-27)

#### Build

| Situação | Tempo de parede | Observação |
|---|---|---|
| Primeiro build, tudo frio (downloads de ~360 MB, ccache vazio, sem `-j` de topo) | 15 min 02 s | CPU somada 85 min (paralelismo médio ~5,7×) |
| Build limpo (`os/out/build` apagado), ccache quente, **sem** `-j` de topo | 447 s | Rust frio 154 s (38%), kernel 64 s, ferramentas de host o resto |
| Build limpo, ccache quente, **`--top-jobs 33`** | 207–219 s (3 rodadas) | **2,1×** do paralelismo entre pacotes (`BR2_PER_PACKAGE_DIRECTORIES`) |
| Mudou o fragmento do kernel (`linux-reconfigure`) | 169 s | |
| Sem mudança (quente) | 24–26 s | cargo sem trabalho, rootfs e disco regravados |

Desde a medição do build limpo, o cache do Rust fica em `os/out/cargo-target`, fora do `O=`: um
build limpo do Buildroot não recompila mais o Rust (o build seguinte levou 165 s sem `-j` de
topo, com o cargo frio numa pasta nova).

**Reprodutível:** dois builds limpos do mesmo commit, um terceiro com outro nível de `-j` e um
quarto com o cache do cargo em outra pasta deram o **mesmo** `bzImage` (`40e26533…`), o mesmo
`rootfs.squashfs` (`f8580cbe…`), a mesma ESP e o mesmo daemon. O `disk.img` ficou igual entre
builds depois da correção do ext4.

#### Tamanho

| Peça | Tamanho |
|---|---|
| `rootfs.squashfs` (zstd) | **14,4 MiB** (38 MiB descomprimido) |
| └ `corerouter-daemon` (sem símbolos) | 27 MiB |
| └ glibc e bibliotecas (`/lib`, `/usr/lib`) | 9,2 MiB |
| └ busybox / `corerouter-init` / `nft` | 0,7 MiB / 0,5 MiB / 24 KiB (+ libnftables) |
| `bzImage` (com BTF, tudo `=y`) | 19,1 MiB |
| `disk.img` | 609 MiB, quase todo partições vazias (rootfs-b e folga); 33 MiB com `zstd` |

#### Boot (QEMU, 2 vCPUs, 1 GiB, virtio)

| Modo | Kernel → daemon responde `ping` | Partida do QEMU → `ready` | Memória ociosa |
|---|---|---|---|
| KVM, `-kernel` (10 rodadas) | 0,69–1,20 s (mediana 0,74 s) | 0,98–1,87 s | 47–58 MiB |
| KVM, UEFI (OVMF → EFI stub, disco inteiro) | 0,73 s | 3,74 s (o firmware leva ~3 s) | 49 MiB |
| TCG (sem KVM) | 2,89 s | 3,78 s | 48 MiB |

Dentro desse tempo: o init leva 7–23 ms (montagens, `lo`, `/config`), e o daemon, 52–126 ms
da partida até o primeiro `pong`. O resto é o kernel até o PID 1 (~0,6 s, probe das placas e
dos discos). O ping TLS do host, pelo encaminhamento de porta do QEMU, respondeu em 14–17 ms.

G2.1c — diagnóstico do firewall (**medido**): AMD Ryzen AI MAX+ 395 (32 threads), kernel 7.0.0,
nft 1.0.9, build release, 2026-10-27.

| Benchmark | Resultado |
|---|---|
| `firewall_test/path/1000 rules` (`cargo bench -p corerouter-firewall --bench path`) | 12,1 µs |
| `firewall_test/path/10000 rules` | 122,7 µs (~12 ns por regra, linear) |
| `netns_fw_counters/10000 rules/nfnetlink dump` (`hal-linux/benches/netns_fw_counters.rs`, netns sem root) | 10,7 ms (931 mil regras/s) |
| `netns_fw_counters/10000 rules/nft -j + JSON` | 190 ms (52 mil regras/s): 17,7× mais lento |

O `path` percorre a tabela inteira por chain cruzada (10 000 regras no forward que não casam e a
última que aceita). O dump inclui o kernel serializando as 10 000 regras; o `nft -j` soma criar o
processo, montar o JSON e o parse.

### G2.7b — capacidade do CGNAT (2026-10-27, **medido**)

Ryzen AI MAX+ 395, build release, carga 4–9. Bench `cargo bench -p corerouter-engine --bench
cgnat_capacity`; 65 536 assinantes × 20 conexões.

| Medida | Valor |
|---|---|
| uso de 1,3 M conexões, vetor ordenado (fora do lock) | 51 ms |
| o mesmo com conjuntos por assinante (antes, dentro do lock) | 75 ms |
| entregar ao engine (lock segurado) | 5,6 ms |
| `ip.firewall.cgnat.capacity.get` | 4,1 ms |
| memória dos picos de 7 dias | 2,8 MiB |

### G1.6b — atualização A/B (**medido**, 2026-10-27, AMD Ryzen AI Max+ 395, build release do bench / KVM no QEMU)

| Medida | Resultado |
|---|---|
| `verity_tree` 16 MiB, 1 / 4 / 8 threads | 7,7 / 7,7 / 7,8 ms (abaixo de 64 MiB não divide) |
| `verity_tree` 256 MiB, 1 / 4 / 8 threads | 126 / 33 / 18 ms (7,1× com 8) |
| `package_copy` 64 MiB para arquivo, sequencial × pipeline | 51,8 ms (1,21 GiB/s) × 48,0 ms (1,30 GiB/s), +8% |
| QEMU: gravar slot B (34,1 MiB) / reler + árvore | 36–53 ms / 12–17 ms |
| QEMU: kernel → daemon pronto, sem × com dm-verity | 0,72 s × 0,70–0,73 s (sem diferença medível) |

### G2.8 — firewall por nfnetlink × `nft` (**medido**)

AMD Ryzen AI MAX+ 395 (32 threads), kernel 7.0, nft 1.0.9, build release, netns sem root,
2026-10-27, `cargo bench -p corerouter-hal-linux --bench netns_firewall`. "Antes" = `nft -j list`
+ `nft -f` do ruleset inteiro, com o texto antigo (sets anônimos por regra).

| Operação | nfnetlink | antes (`nft`) |
|---|---|---|
| carregar 100 regras | 17,4 ms | 22,8 ms |
| carregar 1 000 regras | 24,6 ms | 49,3 ms |
| carregar 10 000 regras | 112 ms | 4,09 s |
| mudar 1 regra em 100 | 15,8 ms | 26,7 ms |
| mudar 1 regra em 1 000 | 22,3 ms | 99,4 ms |
| mudar 1 regra em 10 000 | 109 ms | 6,91 s |
| 1 000 entradas dinâmicas | 0,92 ms | 2,37 s (um `nft` por entrada); 8,9 ms (script) |
| 100 000 entradas dinâmicas | 116 ms | script por linha: "Message too long"; `add element` único: 383 ms |
| ler 1 000 entradas dinâmicas | 0,24 ms | 3,3 ms (`nft -j`) |
| ler 100 000 entradas dinâmicas | 246 ms | 636 ms (`nft -j`) |

- 10 000 regras com um set anônimo cada: 22 s (`th dport { … }`) e 3,2 s (`ct state { … }`), no
  `nft` e em nós; com sets compartilhados e máscara, 77 ms e 63 ms.
- Remover qualquer coisa num lote custa 12–28 ms de kernel (RCU), também no `nft delete rule`;
  acrescentar ~0,5 ms.
- Commit de 10 000 regras, por partes: programa antigo 15 ms, novo 15 ms, dump do kernel 38 ms
  (25–28 ms só de kernel, 6,3 MB) — os três em paralelo —, comparação 9 ms, kernel ~23 ms.
- 100 000 entradas: kernel ~97 ms, merge 2,5 ms (era 10 ms com `Vec<u8>`), codificação 5 ms;
  4 threads/4 sockets ≈ 1 lote (o nfnetlink serializa o lote no mutex do nf_tables).

### G3.2a — BGP: engine, render e FRR real (**medido**, 2026-10-27)

Host: AMD Ryzen AI Max+ 395 (32 threads), build release, criterion. VM do laboratório: 8 vCPUs,
FRR 10.7.1 (pacote oficial), o nosso lado em debug (`CARGO_PROFILE_DEV_DEBUG=0`).

| Medida | Antes | Depois |
|---|---|---|
| `engine.batch` com 1 template + 1 000 conexões (uma transação) | 10,6 ms | 7,8 ms |
| `routing.bgp.connection.set` de uma entre 1 000 (commit inteiro) | 8,1 ms | 1,5 ms |
| `routing.bgp.connection.list` com 1 000 | — | 2,5 ms |
| `routing.bgp.session.list` com 1 000 (sob o lock) | — | 1,25–1,48 ms |
| `proto_bgp::validate` com 1 000 | — | 145 µs |
| render de 1 000 conexões (`render_all`) | — | 357–462 µs |
| parse do `running-config` de 1 000 conexões | — | 156 µs |
| diff com uma conexão mudada entre 1 000 | — | 590 µs |
| FRR real: aplicar 1 000 conexões | — | 329 ms (5 006 comandos) |
| FRR real: mudar uma entre 1 000 | — | 28 ms (3 comandos) |
| FRR real: remover 1 000 | — | 197 ms |
| FRR real: ler 1 000 sessões (fora do lock) | — | 135 ms |

O "antes" do commit: a seção `routing` não era `CowArc` e entrava inteira no delta do
histórico duas vezes por commit (~2 ms cada com 1 000 conexões). Montar a resposta de
`session.list` (1 000 linhas) custa 1,2 ms; clonar um `Value` pronto custaria 0,84 ms, então a
resposta continua sendo montada na hora. O clone da amostra no serviço `frr` (126 µs) saiu de
dentro do lock.

G1.27d, AMD Ryzen AI MAX+ 395 (32 threads), build `bench` (release), 2026-10-27, **medido**:

- Tabela do motor, 100 mil vizinhos em 8 portas (`cargo bench -p corerouter-engine --bench
  neigh_table`): aplicar um evento 110 ns; carregar um dump 9,1 ms; memória residente ~123 B por
  entrada (12,4 MB para 100 mil). Página de `ip.arp.list`: primeira página 7,26 → 2,70 ms
  (contagem por vetor/ponteiro em vez de mapa por nome e ordenação sem alocar `String`), última
  página 4,5 ms, CIDR /20 2,6 ms, prefixo de MAC 3,0 ms, estado 2,2 ms, texto 21,3 → 3,5 ms
  (comparação sem alocar por linha).
- Kernel, 100 mil entradas num namespace sem root (`netns_neigh`): dump `RTM_GETNEIGH` 25,0 ms
  (4,0 M entradas/s) contra 161 ms do `ip -j neigh show` + JSON (6,4×).
- Rajada de 20 mil mudanças sem root: o socket de eventos fica no `rmem_max` (o
  `SO_RCVBUFFORCE` de 16 MiB exige root), o kernel descarta (`ENOBUFS`, 1 vez) e o serviço relê
  a tabela (25 ms): nada se perde para a lista. Como root o buffer de 16 MiB comporta ~150 mil
  eventos (**estimado**).
- Paralelismo: o kernel serializa a tabela num socket (dump e eventos em ordem); aplicar um
  evento custa 110 ns, então uma thread aplica ~9 M eventos/s, muito acima do que o kernel
  entrega. Dividir em threads só acrescentaria lock na tabela. A lista é O(n) por consulta
  (filtro) + O(k log k) da página; 100 mil linhas em 2–4 ms não justificam índice extra.

### G4.4j: log de NAT do CGNAT em IPFIX (**medido**, 2026-10-27)

AMD Ryzen AI MAX+ 395, kernel 7.0.

- `cargo bench -p corerouter-engine --bench cgnat_pba_storm` (release): `allocate_10k_blocks`
  109,5 ms → 43,7 ms (−60 %, 229 mil blocos/s); `drain_10k_records` 139 µs (14 ns por registro).
- `cargo bench -p corerouter-proto-flow --bench flow_codec`: `encode_port_blocks_10k` (IPFIX,
  `userName` variável) no grupo `flow`.
- `netns_nat_ipfix` (release): 20 000 blocos por SCTP e TLS, 24 µs de CPU do daemon por bloco,
  `nat_log_dropped` 0. Build de teste: 632 → 3 411 blocos/s com o lote do journal (313 → 147 µs
  de CPU por bloco).
- `netns_traffic_flow` (release, `COREROUTER_FLOW_BURST=100000`): 100 000 criações NAT pelo TCP
  (thread de envio) 0,38 s após o início; 300 000 registros, 1,6 µs de CPU por registro, RSS
  133 MB, sem descarte na fila nem no kernel.

G1.27d OUI, AMD Ryzen AI MAX+ 395, build `bench`, 2026-10-27, **medido** (máquina com load 7–10 de
outras sessões): uma busca de fabricante 75 ns (busca binária em 40 410 registros, nada
alocado até achar); conferir a tabela inteira 0,76 ms (uma vez, no primeiro uso, ou ao instalar uma
baixada); tabela embutida 709 KB (o CSV tem 3,9 MB). Página de `ip.arp.list` com 100 mil vizinhos
e o nome do fabricante nas 500 linhas: 3,4 ms (a mesma carga dava 4,3 ms à busca por interface).

- G1.6c (**medido**, 2026-10-27, AMD Ryzen AI Max+ 395, release, máquina compartilhada, ±10%):
  bench `install` (`crates/sysupdate/benches/sysupdate.rs`), ISO em memória → arquivo, 109 MiB
  gravados: sequencial + releitura serial 158 ms; em fluxo + serial 127 ms; sequencial +
  releitura paralela 109 ms; em fluxo + paralela 121 ms. No QEMU (KVM, virtio): instalação
  inteira 0,1–0,3 s.

### G3.2c — RPKI, tabelas BGP e "Por que essa rota?" (**medido**, 2026-10-27)

Host: AMD Ryzen AI Max+ 395 (32 threads), build release, criterion
(`cargo bench -p corerouter-proto-bgp --bench rpki`, `cargo bench -p corerouter-hal-frr --bench
frr_rib`). Dados sintéticos com a forma da tabela real: 1 M de rotas (90 % IPv4, 60 % /24),
551 mil VRPs (496 mil IPv4, 55 mil IPv6), ~150 mil AS paths distintos.

| Medida | Tempo |
|---|---|
| construir a árvore de VRPs (551 mil) | 54 ms |
| validar 1 M de rotas, ordem aleatória, 1 thread | 746 ms |
| validar 1 M de rotas, **ordem de prefixo**, 1 thread | 81 ms |
| validar 1 M, ordem aleatória, 2 / 4 / 8 threads | 309 / 134 / 68 ms |
| indexar uma tabela de 1 M (cópia + ordenar + validar) | 152 ms |
| uma página de 500 por prefixo (/8, orlonger) | 0,14 µs |
| página no deslocamento 900 mil, sem filtro | 1,4 ms |
| busca por AS path em 1 M (conta todas) | 9,1 ms |
| busca por community + inválidas em 1 M (conta todas) | 6,4 ms |
| "Por que essa rota?" com 10 caminhos | 0,94 µs |
| ler 1 M de rotas do JSON do bgpd (203 MiB), streaming | 1,78 s (114 MiB/s) |
| o mesmo com o texto inteiro na memória (`from_slice`) | 1,52 s (134 MiB/s) |

- A validação RFC 6811 em ordem de prefixo é 9× mais rápida que em ordem aleatória: rotas
  vizinhas percorrem o mesmo caminho da árvore, que fica no cache. O `Indexed` ordena antes de
  validar, então uma tabela inteira custa 81 ms numa thread, mais que as 8 threads em ordem
  aleatória (68 ms) sem nenhuma thread. Dividir a validação já ordenada em threads salvaria
  ~70 ms numa leitura que o bgpd leva segundos para imprimir; o `proto-bgp` também compila para
  WASM, onde não há threads. Fica numa thread.
- O parse em streaming lê a 114 MiB/s; o bgpd imprime a ~40 MiB/s (o `show ip route json` de 1 M
  de rotas da G3.1: 537 MiB em 13 s). Como o parse corre enquanto o bgpd escreve, o tempo de
  parede é o do bgpd. Ler tudo para a memória antes (`from_slice`) ganha 15 % de CPU e custa os
  ~200 MiB do texto; tirar as alocações de endereços e origem ganhou 5 % (1,88 → 1,78 s).
- Memória: 24 B por rota (teste `a_route_is_small`) mais os atributos internados; até 4 tabelas
  guardadas no engine, ~100 MiB com quatro tabelas completas (**estimado**).

### G3.2b — `/routing filter` (**medido**, 2026-10-27, 32 núcleos, `cargo bench` release)

| Medida | 1 thread | 2 | 4 | 8 | 16 |
|---|---|---|---|---|---|
| Prévia de 1 M rotas, política de trânsito (bogons, tamanho, AS privado, blackhole, preferência) | 311 ms | 176 ms | 90 ms | 48 ms | 30 ms |
| Prévia comparada com a política em vigor (cada rota duas vezes) | 605 ms | | | 98 ms | |

Escala quase linear até 8 threads (6,5×): cada rota é independente, a política é compartilhada
só para leitura, sem lock; o padrão usa até 8 (abaixo de 20 000 rotas, uma).

| 10 000 regras em 100 chains | antes | depois |
|---|---|---|
| Compilar (validação de todo commit) | 146 ms | 30 ms (regex só checada na sintaxe pelo parser e compilada uma vez; parse e regex em 8 threads) |
| Render para o FRR | 98 ms | 15 ms (uma chain por thread; listas com nome pelo conteúdo se juntam sem conflito) |
| Parse do running-config do FRR (hal-frr) | | 6,5 ms |
| Diff com uma regra mudada (hal-frr) | | 14,6 ms (serial: custo pequeno) |

FRR 10.7.1 real (VM do laboratório, debug): mudar uma regra digita 14 linhas em 2,7 ms.

### G3.4a — configuração OSPF (**medido**, 2026-10-27, 32 núcleos, build de bench)

`cargo bench -p corerouter-proto-ospf --bench ospf_config`, 4 000 interfaces, 4 000 endereços,
1 000 templates (900 por nome, 100 por rede):

| Medida | Antes (cada interface × cada template) | Depois (índice por nome) |
|---|---|---|
| `bindings` | 145,7 ms | 10,9 ms |
| render FRR | 148,1 ms | 12,7 ms |
| impacto do commit | 284,8 ms | 32,8 ms |
| validação | 0,30 ms | 0,31 ms |

### G3.4b — LSDB e layout da topologia (**medido**, 2026-10-27, 32 núcleos, build de bench)

| Medida | Resultado |
|---|---|
| LSDB de 10 000 LSAs (4,0 MiB de JSON) lida em fluxo | 9,1 ms, 612 KiB |
| a mesma como `serde_json::Value` | 17,0 ms, +34 MiB de RSS |
| layout de 500 roteadores, 1 / 4 / 16 threads | 66,8 / 27,1 / 29,1 ms |

`cargo bench -p corerouter-hal-frr --bench frr_ospf`, `cargo bench -p corerouter-proto-ospf
--bench ospf_topology`.

### BFD: motor próprio (G3.6a, 2026-10-27)

AMD Ryzen AI MAX+ 395, build release, dois motores no loopback de um namespace, 50 ms × 3, 15 s por caso (`service/bfd/tests.rs`, `load`), **medido**:

| sessions | threads | CPU %/thread avg | CPU %/thread max | tx jitter p99 worst (µs) | tx jitter p99 median (µs) | rx gap p99 worst (µs) | false downs | handed over |
|---|---|---|---|---|---|---|---|---|
| 100 | 1 | 1.6 | 8.0 | 87 | 69 | 50708 | 0 | 0 |
| 100 | 2 | 0.9 | 4.0 | 3081 | 1578 | 56052 | 0 | 26 |
| 100 | 4 | 0.4 | 4.0 | 87 | 69 | 51384 | 0 | 48 |
| 100 | 8 | 0.5 | 4.0 | 136 | 69 | 50073 | 0 | 76 |
| 500 | 1 | 5.9 | 8.0 | 265 | 69 | 50712 | 0 | 0 |
| 500 | 2 | 4.5 | 12.0 | 1578 | 108 | 54477 | 0 | 199 |
| 500 | 4 | 3.5 | 8.0 | 4815 | 1972 | 56052 | 0 | 318 |
| 500 | 8 | 1.7 | 8.0 | 108 | 69 | 51647 | 0 | 351 |
| 1000 | 1 | 10.1 | 16.0 | 517 | 69 | 53205 | 0 | 0 |
| 1000 | 2 | 6.9 | 12.0 | 1262 | 108 | 54480 | 0 | 506 |
| 1000 | 4 | 4.4 | 8.0 | 136 | 69 | 52314 | 0 | 619 |
| 1000 | 8 | 2.9 | 8.0 | 6019 | 1972 | 56052 | 0 | 729 |

Com `poll` em ms (antes do `ppoll`): jitter p99 mediano 1 050 µs em todos os casos, CPU de 1000 sessões numa thread 5,6 %. `proto-bfd` (criterion): decode 6,7 ns, SHA1 assinar 43 ns, conferir 39 ns, receber 5,5 ns; 1 s de 1000 sessões no timer wheel 0,30 ms.

### G3.4c — quadro da topologia (**medido**, 2026-10-27, build de debug)

500 roteadores e 500 enlaces, com um caminho destacado: pintura + tesselação do quadro 3,2 ms
(mediana de 20, `tests::ospf::five_hundred_routers_paint_within_a_frame`), contra 16,7 ms de um
quadro a 60 fps. A resposta do engine vira vetores planos uma vez, ao chegar; o quadro não lê JSON
nem aloca por nó.

### G3.7 simulador de rede (**medido**, 2026-10-27, 32 CPUs, build release, máquina compartilhada com outras sessões: load 15–30)

`cargo run --release -p corerouter-netsim --example measure -- 10 100 500`: grade com OSPF em
todo enlace e eBGP entre vizinhos (cada roteador no seu AS, um /24 cada), 60 s virtuais desde o
boot.

| Roteadores (enlaces) | 1 thread | 4 | 8 | 16 | janelas (paralelas) | eventos | estado do simulador por roteador |
|---|---|---|---|---|---|---|---|
| 10 (13) | 0,6 ms | 0,5 ms | 0,5 ms | 0,5 ms | 676 (0) | 1 124 | 9 KB |
| 100 (180) | 102 ms | 106 ms | 122 ms | 127 ms | 9 109 (642) | 51 723 | 88 KB |
| 500 (955) | 5,65 s | 3,93 s | 3,12 s | 3,96 s | 25 937 (6 588) | 957 457 | 447 KB |

- Tempo por passo (janela): 0,8 µs (10), 11 µs (100) e 218 µs (500) com 1 thread; 120 µs com 8
  threads em 500. A barreira (entrega serial) custa 145–280 ms dos 3–6 s em 500 roteadores.
- Convergência de 100 roteadores: a última mudança de protocolo acontece em 10,7 s virtuais
  (hellos com fase aleatória de até 10 s + MinLSInterval de 5 s). Simular isso custa 102 ms de
  parede. 10 minutos virtuais de regime custam 39 ms.
- Corte de um enlace no meio + 30 s: 9 ms (100 roteadores), 225 ms (500, 1 thread), 109–284 ms
  (500, com threads).
- 16 threads não ganham de 8: as janelas com trabalho em paralelo são curtas (lookahead = 1 ms
  de latência) e a máquina estava ocupada.

Antes e depois das otimizações deste PR (500 roteadores, 1 thread, 60 s virtuais):
- primeira versão: 21 s;
- SPF com o throttle do FRR (backoff) e Dijkstra por índices: 100 roteadores só OSPF de 0,73 s
  para 0,22 s;
- entrega sem clonar o enlace e LS Update agrupado por instante: 500 só OSPF 4,9 → 3,8 s;
- FIB incremental para BGP e próximo salto em cache: com eBGP 14,5 → 7,2 s;
- SPF com conjuntos de next-hop em arena: 760 → 180 µs por SPF;
- final: 5,65 s.

Pool persistente × `thread::scope` por janela (500, 8 threads): 3,1 s × 11,3 s. Limiar de
roteadores ativos por janela para usar o pool: 16 (100 roteadores 18 % mais lentos em 8 threads),
48 (empata em 100, 500 mantém 3,2 s), 96 (500 cai para 3,6 s): fica 48.

Engine (`cargo test --release`, RSS do processo): um `Session` por roteador virtual custa
~98–140 KiB (100 e 500 roteadores); com o estado do simulador, ~1,2 MiB por roteador em 500. Montar o
laboratório de 500 roteadores por comandos (uma transação cada) leva 150 ms; 60 s virtuais pelo
`tool.netsim.advance`, 4,7 s.

- 2026-10-27, G3.5 (**medido**, esta máquina, release, criterion):
  - `forwarding/rows_100k` (100 mil rótulos, 10 mil FECs): 38,9 → 22,5 ms;
  - `mpls_page/cached`, a página sob o lock: 39 ms → 1,1 ms;
  - `mpls_page/find_cached`: 25 ms → 0,48 ms;
  - `mpls_page/service_build`: 47 ms, fora do lock;
  - o netlink no kernel (lote × um a um, dump de 100 mil) fica pendente: precisa do `mpls_router`.

### G1.27f — check-gateway de rotas estáticas (**medido**, 2026-10-28, 32 threads, build release)

Daemon real em netns (`netns_route_check::load_1000_gateways`, `--ignored`), 1 000 gateways num
segundo namespace, uma rota por gateway, intervalo de 10 s (100 sondas/s), 30 s medidos na thread
`svc-route-check` (`/proc/<pid>/task/*/stat`):

| Método | CPU da thread | Sondas atrasadas (média / máx.) | Inalcançáveis |
|---|---|---|---|
| ping | 0,50 % de um núcleo | 9 ms / 24 ms | 0 |
| arp | 0,37 % de um núcleo | 9 ms / 119 ms (o máximo inclui os 1 000 `ip.route.set` da troca) | 0 |

O atraso médio é metade do tick de 20 ms; sobre 10 s, 0,1 %. Uma thread basta (0,5 % de um
núcleo): dividir por interface só acrescentaria um lock à agenda.

Engine (`cargo bench -p corerouter-engine --bench gateway_check`, 4 rotas por gateway), antes →
depois das otimizações deste PR (lista de gateways caídos no `effective`, contagem de rotas numa
passada, log agregado, sync em cache pela geração do config):

| Caso | 1 000 gateways | 10 000 gateways |
|---|---|---|
| sync por segundo, config igual (sob o lock) | 0,88 ms → 0,002 ms | 9,4 ms → 0,024 ms |
| tomar os alvos (config mudou) | 0,98 ms | 9,7 ms |
| relato de um tick, todos respondendo | 0,28 ms | 3,0 ms |
| todos caem e voltam (2 applies) | 43,7 ms → 7,2 ms | 3 643 ms → 78 ms |
| agenda: um intervalo inteiro a ticks de 20 ms (sem lock) | 0,82 ms | 12,9 ms |

### LSP ping (G3.5b)

Release, criterion, esta máquina (32 núcleos), 2026-10-28, **medido**
(`cargo bench -p corerouter-hal --bench lsp_echo`):

| Caminho | Tempo |
|---|---|
| Codificar um MPLS echo request com DDMAP | 117 ns |
| Ler o mesmo pedido | 104 ns |
| Resposta de trânsito completa (ILM e FECs com 100 mil entradas) | 363 ns |

VM do laboratório, build debug, 2026-10-28, **medido** (`scripts/lsp-ping-live.sh`, dois saltos
com LDP do FRR): LSP ping mín. 69 µs, mediana 90 µs, p95 590 µs; ICMP do kernel no mesmo caminho
mín. 11 µs, média 17 µs.

### G3.5: rótulos MPLS no kernel, lote × um a um (VM do laboratório, 2026-10-27)

**Medido**, VM `corerouter-lab` (8 vCPUs EPYC-Genoa `host-model`, kernel 7.0, `mpls_router`),
build release, `tests/netns_mpls.rs` (`ten_thousand_labels_in_batches_and_one_by_one`,
`MPLS_LABELS=10000` e `100000`):

| Rótulos | Em lote (64 KiB por `sendmsg`) | Um a um | Dump |
|---|---|---|---|
| 10 mil | 10,1 ms | 15,9 ms | 2,8 ms |
| 100 mil | 98,4 ms | 159,4 ms | 33,7 ms |

O lote ganha 1,6×; o custo por rótulo é do kernel (~1 µs), não das idas e voltas.

### G3.6i: o nosso BFD contra o `bfdd` do FRR (VM do laboratório, 2026-10-27)

**Medido**, VM `corerouter-lab` (8 vCPUs EPYC-Genoa `host-model`, kernel 7.0, virtio), FRR
10.7.1, build release, 50 ms × 3, 15 s em regime (`scripts/frr-bfd-live.sh load`, com
`BFD_THREADS=1,2,4`). CPU nossa por thread; a do `bfdd`, do processo.

| sessions | our threads | our CPU %/thread | bfdd CPU % | our tx jitter p99 median (µs) | worst | bfdd tx gap p99 median (µs) | worst | our false downs | bfdd false downs |
|---|---|---|---|---|---|---|---|---|---|
| 100 | 1 | 7.5 | 5.6 | 97 | 108 | 50940 | 53587 | 0 | 0 |
| 500 | 1 | 24.8 | 20.3 | 87 | 265 | 56052 | 56052 | 0 | 0 |
| 1000 | 1 | 36.5 | 32.7 | 69 | 331 | 56052 | 56052 | 0 | 0 |
| 1000 | 4 | 15.4 | 44.7 | 87 | 212 | 56052 | 56052 | 0 | 0 |

Nós contra nós na mesma VM (`bfd::tests::load`, 10 s): 1000 sessões numa thread 32,4 %, com 8
threads 8,2 % por thread. Data plane: `bfdd` → `bgpd` em 0,20–0,26 ms (5 cortes).

- 2026-10-28, G3.6h, VM `corerouter-lab` (8 vCPUs, kernel 7.0, release, BNG Blaster 1.0.1, sem
  root): tomada do par com o ativo sem energia, **medido**. Sem BFD: 0,96–1,18 s. Com BFD `fast`
  nos dois caminhos: 0,13–0,20 s, e o nó novo ativo 150–154 ms depois do último pacote do par. O
  tráfego volta em 0,19 s (1 mil sessões), 0,25 s (10 mil) e 1,04 s (100 mil); 0 perdidas.
- 2026-10-28, G3.6h, dois daemons debug em namespace (Ryzen AI Max+ 395), **medido**: com o laço
  do `ppp-ha` acordado pelo evento, a decisão sai 0–4 ms depois da detecção do BFD (antes, com o
  tique de 10 ms, saía ~10 ms depois).

### G3.4f: banco SR de 10 000 SIDs (medido)

2026-10-28, 32 núcleos (carga ~1,3), build de bench (release), `cargo bench -p corerouter-hal-frr --bench frr_sr`:
1 000 roteadores SR, 10 000 prefix SIDs, 1,5 MiB de JSON.

| Medida | Resultado |
|---|---|
| leitura do banco SR para o modelo | 8,5 ms |
| conflitos de SID sobre ele (1 995 achados) | 2,6 ms |

### G3.4d: TI-LFA, 10 000 prefixos (medido)

2026-10-28, 32 núcleos, build de bench (release).

| Medida | Antes | Depois |
|---|---|---|
| cobertura de 10 000 prefixos num área de 500 roteadores (`cargo bench -p corerouter-netsim --bench tilfa`) | 62,4 ms | 15,1 ms |
| reparos para todos os 500 roteadores | — | 9,6 ms |
| leitura de 10 000 rotas com reserva do zebra (6,5 MiB de JSON, `--bench frr_sr`) | — | 21,8 ms |

O antes recalculava 5 SPFs por (destino, vizinho); agora a árvore da raiz, a árvore sem cada
vizinho e a árvore reversa de cada destino são calculadas uma vez e compartilhadas (`Rc`), e só a
árvore reversa sem o recurso é por par.

- 2026-10-28, G4.3hh, adoção de 100 mil sessões no par BNG (**medido**).
  - VM `corerouter-lab`, 8 vCPUs, kernel 7.0, release, BNG Blaster 1.0.1, caminho lento, 6
    workers, BFD `fast`, `cargo xtask bng-lab --only ha`. Subida de volta (1ª / mediana / todas
    as 32 sondas):
    - 100 mil: antes 0,899 / 1,090 / 1,202 s; depois 0,195 / 0,216 / 0,244 s.
    - Todas adotadas: 1102 → 273 ms do último sinal de vida.
    - 10 mil: antes 0,175 / 0,193 / 0,203 s; depois 0,157 / 0,182 / 0,203 s.
  - Host (Ryzen AI Max+ 395, release), `pppoe_ha_tests::adopt_profile`, 100 mil sessões, 8
    workers: o worker responde em 7 ms (antes 310 ms, tudo de uma vez); todas adotadas em
    62–66 ms; a contabilidade em 180 ms.
  - Rotas para `bng0` (namespace, `tests/netns_routes_batch.rs`), 100 mil /32:
    - `rtnetlink` uma a uma: 348 ms com 1 thread, 188 ms com 8;
    - lote: 132 ms com 1 thread, 221 ms com 8.
  - `benches/netns_routes_batch.rs`, 10 mil /32: 13,1 ms em lote contra 31,7 ms uma a uma.

### G3.9: RouterOS 7.25 CHR × CoreRouter (medido, 2026-10-28)

VM do laboratório (8 vCPUs, KVM aninhado: CHR com 2 vCPUs e 512 MiB), build release, FRR 10.7.1.
`cargo xtask vm-lab run -- scripts/routeros-interop.sh`.

| Medida | Valor |
|---|---|
| Full OSPF ptp depois do commit (hello 1 s) | 1,8–7,6 s |
| Rotas pelo CoreRouter no CHR depois do commit | 6,6–14,4 s |
| Sessão LDP operacional | 0,95–2,5 s |
| BFD up depois do Full | 1,8–2,4 s |
| Corte silencioso, BFD 300 ms × 3: CHR derruba a adjacência / buraco no ping | 0,67–0,80 s / 1,16–1,29 s |
| Corte silencioso, BFD 300 ms × 4: idem | 1,08 s / 1,55 s |
| Perda de portadora: buraco no ping | 0,60–0,70 s |
| Corte silencioso sem BFD (dead 4 s): CHR derruba a adjacência | 3,2–3,5 s |
| Volta do CoreRouter: buraco | < 0,1 s |
| Template passivo: trânsito desviado / sub-rede fora do CHR / buraco | 26–573 ms / 1,3–1,9 s / nenhum |
| Instância desligada: buraco | 0,44–1,4 s |
| BFD 100 ms × 3, sessão nova: quedas em 30 s (CoreRouter / FRR) | 15 / 12–13 |
| BFD 300 ms × 3 e × 4, sessão nova: quedas em 30 s | 0 e 0 |
| BFD 100 ms × 3 trocado com a sessão em Up: quedas em 30 s | 0 |

- 2026-10-28, G1.6m, **medido** (KVM, imagem release, QEMU 2 vCPUs/1 GiB): kernel → daemon
  pronto 0,90–0,91 s com o renomeio das portas (0,92 s antes); a espera de a lista de links
  parar (100 ms) custa ~0,1 s no `early boot` (110 ms contra 14 ms); com 300 ms o pronto ia a
  1,10 s.
