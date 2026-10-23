id: audit-capacidade-relatorio

Relatório da auditoria (`docs/audit-2026-10.md`), seção nova "Capacidade e persistência": limites
da config (15 MiB por config; tetos por item), medição de commit, boot e revisões que voltam do
reboot com configs de 5 e 10 MiB (**medido**, 2026-10-23), e o antes/depois das duas correções
pedidas pelo usuário: histórico em disco como diferença (#141, 64 de 64 revisões voltam do reboot)
e seções copy-on-write (#139, G0.16), com o ajuste do #143 (boot de 149 ms com 5 MiB e 208 ms com
10 MiB, 64 revisões, mesma memória). Duas gaps novas para o que ainda não é linear.

| G0.21 | Listas grandes da config sem cópia ao acrescentar um item | model, engine | Acrescentar ou remover uma entrada de uma address-list de 60 000 (ou rota, regra) copia a lista inteira (~0,6 ms, **medido**, `engine_txn/single/address_list_add_remove/60000`) porque a seção copy-on-write do G0.16 é a lista toda. Lista persistente ou em blocos (copy-on-write por bloco, chave pelo `id`), sem dependência nova de licença incompatível; critério: `engine_txn/build/8000` linear (custo por comando constante de N = 2000 a 8000) e add numa lista de 60 000 < 20 µs | 8 h | aberto |
| G0.22 | Commit incremental: validar, serializar e aplicar só as seções que mudaram | engine, model, hal | Com 10 000 rotas um commit de `interface.set` ainda gasta ~6 ms em `validate_all` (~1,2 ms), `persist::encode_config` (~2,2 ms) e no `apply` (~1,5 ms), tudo sobre a config inteira (**medido**, G0.16). Usar `CowArc::ptr_eq` para saber o que mudou e rodar só os validadores, a serialização e o diff do plano dessas seções; critério: `engine_scale/commit/routes/10000` com uma mudança fora das rotas < 1 ms | 10 h | aberto |
