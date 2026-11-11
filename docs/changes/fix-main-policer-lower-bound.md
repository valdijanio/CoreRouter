id: fix-main-policer-lower-bound

`main` vermelha em 008a72cc (issue 605): o proptest `shaper_props::policer_exact_under_races`
(`crates/dataplane-ebpf-common`) falhou duas vezes seguidas com `rate_k = 256, cpus = 13,
size = 801, secs = 2` (`45657 < 50116`). O defeito era do teste, não do policer: ele oferece
`cpus` pacotes no mesmo instante, a cada `step`, e cobrava a taxa cheia. Com taxa baixa e
rajada grande os instantes ficam mais afastados que o tempo do balde (108 ms contra os 100 ms
do `bucket-size` padrão): o balde transborda entre um instante e outro e o policer passa um
balde por instante (3 de cada 13 pacotes), que é o que um policer deve a uma rajada.

O que mudou (só o teste): o corpo da propriedade virou a função `races`; o piso passa a ser a
taxa enquanto a recarga de um instante cabe no balde (como antes) e, quando não cabe, um balde
menos um pacote por instante. A entrada que quebrou a `main` e as bordas (recarga que cabe por
pouco e que não cabe) viraram o teste fixo
`policer_owes_a_bucket_per_instant_when_the_refill_overflows_it`.

Números (**medido**, 2026-11-11, máquina de desenvolvimento, build dev): o teste antigo
falhava em 5 de 200 execuções (2,5% por execução, 256 casos cada); o novo, 0 de 200. O piso
novo passou 40 000 casos sorteados só na faixa de taxa baixa (256–1500 kbit/s) e 6 000 na
faixa inteira; as outras duas propriedades do arquivo (`shaper_bounds`,
`routeros_burst_long_run_average`) passaram 6 000 casos cada sem falha.

Como testar: `cargo test -p corerouter-dataplane-ebpf-common --test it shaper_props`.
