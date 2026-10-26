id: processo

Partes do CI (8 núcleos nos testes somando runners), complemento do #269. O #269 entrou com
dois commits temporários das medições, que este PR desfaz: o `test` volta a 2 partes (eram 3)
e o cache do cargo volta a ser salvo só pela `main` (salvava também a branch do #269).

- **8 núcleos nos testes, somando runners:** o `test` e o `xdp-root` rodam em duas partes,
  cada uma num runner de 4 vCPU (`COREROUTER_CI_PARTITION=i/2`). O `test` passa
  `--partition hash:i/2` ao nextest (um teste fica na mesma parte quando outros entram; os
  doctests só na parte 1); `.config/nextest.toml` começa primeiro os três testes de mais de
  60 s, que antes, começando por último, seguravam sozinhos o fim de uma parte. O `xdp-root`
  divide os testes de root pelo tempo medido de cada um (o mais longo para a parte mais leve),
  e cada parte continua rodando um por vez, porque eles medem vazão e precisão. Dentro de cada
  job, o nextest e o cargo já usam todos os núcleos (o padrão é o número de CPUs). Runner maior
  é pago e runner próprio na máquina do usuário rodaria código de PR de fork (repositório
  público): nenhum dos dois.

## perf

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
