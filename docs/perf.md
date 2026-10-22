# Desempenho (medições)

Regra em `AGENTS.md`, "Desempenho e escolha de implementação". Cada linha diz se é **medido**
(com máquina, build e data) ou **estimado**. Benchmarks: `cargo xtask bench` (G0.9).

| O quê | Resultado | Tipo | Como / onde | Data |
|---|---|---|---|---|
| Canal de controle: uma requisição em conexão persistente (loopback, TCP) antes da correção | ~41 ms (Nagle + ACK atrasado; ~83 ms ida e volta pela CLI) | medido | cliente Python persistente; `corerouter-cli` | 2026-10-22 |
| Canal de controle: idem depois da correção (escrita única + `TCP_NODELAY`) | ~19 µs | medido | PR #25 (G0.3), teste de latência em `crates/control` | 2026-10-22 |
| `Session::execute` de um comando simples (motor) | < 1 ms | medido (grosseiro) | ida e volta no loopback sem rede | 2026-10-22 |

## Decisões tomadas com base nestes números

- Canal de controle síncrono, uma escrita por linha e `TCP_NODELAY` em todo socket (G0.3).

## Histórico de revisão

- 2026-10-22 — versão inicial.
