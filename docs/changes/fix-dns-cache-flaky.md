id: fix-dns-cache-flaky

O teste `cache::tests::a_flood_of_unique_names_leaves_the_hot_ones` (G4.1x) deixa de falhar ao
acaso. Ele reprovou o `cargo xtask ci --affected` da G4.1zo duas vezes seguidas (TRY 2 FAIL), sem
nada do cache mudado.

**A causa, medida:**
- O esboço de frequência do W-TinyLFU usa um hash com chave aleatória (`RandomState`). É de
  propósito: assim um cliente não escolhe nomes que caiam nos contadores dos nomes quentes.
- No cache do teste (100 entradas, 128 palavras de contador), um nome único às vezes empata com um
  nome quente logo depois da redução à metade e o tira do cache. O nome quente falta uma vez, volta
  ao cache, e às vezes puxa outras faltas em seguida.
- Em 200 rodadas (**medido**, 2026-11-20): 162 sem falta nenhuma; nas outras 38, de 1 a 24 faltas
  em 10 000 consultas quentes (no máximo 0,24 %).
- O teste exigia 0 faltas, uma garantia que um esboço probabilístico não dá. Quando havia falta, a
  conta `evicted + rejected == 20 000 − 50` também não fechava: cada falta põe o nome de volta e
  conta mais uma entrada.

**A correção (só o teste):**
- No máximo 1 % de faltas, contra a "maioria" que a política antiga (descarte por chegada)
  perdia.
- A conta passa a somar as faltas.
- Não houve mudança de comportamento no cache. Com a correção, as 200 de 200 rodadas passam.
