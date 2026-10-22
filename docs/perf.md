# Desempenho (medições)

Regra em `AGENTS.md`, "Desempenho e escolha de implementação". Cada número diz se é **medido**
(com máquina, build e data) ou **estimado**. Os benchmarks são do G0.9: `cargo xtask bench`
(criterion 0.8, dev-dependency só dos crates medidos; fora do build normal e do wasm).

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

**`sccache` não foi adotado** (medido, workspace inteiro com testes, pasta de build nova como a
de uma sessão em paralelo): sem `sccache` 27 s; `sccache` frio 34 s; `sccache` quente em outra
pasta 36 s, com 0% de acerto em Rust. Ele não reaproveita entre caminhos de saída diferentes nem
crates com compilação incremental, e o build já é curto. No CI, o `rust-cache` restaura o
`target` inteiro de uma vez. Rever se as builds ficarem longas.

**Pasta de build por sessão** (**medido**, `cargo xtask ci` do zero numa pasta nova, 32 núcleos,
2026-10-22): com debuginfo completo, 15 GB e 163 s; com `debug = "line-tables-only"` no nosso
código e sem debuginfo nas dependências (`[profile.dev]` do `Cargo.toml`), 6,6 GB e 135 s. Dos
6,6 GB, 2,1 GB são os 87 executáveis de teste (cada arquivo de `tests/` vira um binário com o
workspace inteiro) e 1,7 GB o cache incremental.
