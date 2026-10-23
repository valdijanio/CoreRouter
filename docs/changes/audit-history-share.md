id: audit-history-share
history: G0.20 resolvido por audit-history-share (revisões restauradas dividem as seções CowArc; boot de 64 revisões de 10 MiB em 208 ms, RAM igual à de antes)

Continuação do audit-history (#141), em cima do G0.16 (#139). Depois do #141, o boot desserializava
cada uma das 64 revisões como uma `Config` independente. Com 10 MiB, isso deixava 64 cópias
inteiras na RAM e o boot ia de ~0,3 s para 1,2–1,5 s. Este PR **resolve a G0.20**: a coluna Status
da linha G0.20 em `docs/gaps.md` pode passar a "feito (`stream/audit-history-share`)".

- `model::config_delta` (novo): aplica e calcula a diferença seção por seção sobre os `CowArc` do
  G0.16, nos níveis `Config`, `Ip` e `Firewall`.
  - **Boot:** a revisão `k` é um clone da `k+1` (só contadores de referência), com só as seções
    que o delta toca reconstruídas. Os campos pequenos de cada nível passam pelo JSON com as
    seções grandes vazias. Uma seção que o delta não cita continua a mesma alocação nas duas
    revisões (`CowArc::ptr_eq`).
  - **Commit:** uma seção que a revisão nova divide com a anterior (o que o commit não tocou) nem
    é serializada. O arquivo de revisão custa o que o commit mudou, e saiu a comparação dos dois
    textos inteiros (`json_delta::diff_text` e o texto guardado entre saves foram removidos).
  - O formato dos arquivos não muda. O resultado é o mesmo da árvore inteira, e a diferença
    tipada é a mesma da árvore (testado). Os deltas continuam sendo tratados como entrada hostil.
- Testes:
  - `all_64_revisions_of_a_big_config_survive_a_reboot` agora confere que, depois do reboot,
    seção igual entre revisões vizinhas ⇔ mesmo ponteiro (`ip`, `firewall`, address lists), e que
    as seções que nenhum commit tocou (interfaces, rotas, endereços, filtro, DHCP) são uma
    alocação só nas 64 revisões.
  - Em `config_delta`: igualdade com o caminho da árvore, compartilhamento, seções que somem e
    voltam do JSON, e deltas hostis recusados.
- Bench: `storage_fs/history64/*` mede também o pico de RSS do boot (`VmHWM`), num processo filho
  que só faz o `Session::with_storage`.

Como testar:

- `cargo test -p corerouter-engine --test history_files`
- `cargo test -p corerouter-model config_delta`
- `cargo bench -p corerouter-storage-fs --bench commit -- storage_fs/history64`

## perf

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
