id: fix-netns-routes-batch-guard

`netns_routes_batch` (teste e benchmark do `hal-linux`) deixou de reprovar ao acaso. A checagem
"namespace limpo" só aceitava `lo` e `bng0`. Desde o G4.3y, o caminho lento do PPPoE cria o par
veth `bng0` ↔ `bng0p` e a bridge `bng0br`, e o `ip -o link` mostra o veth como `bng0@bng0p`. O
primeiro teste do arquivo que montava o `SlowPath` deixava essas interfaces, e os seguintes se
recusavam a rodar. Isso dependia da ordem: em sequência, 3 de 4 testes falhavam; o lote do #662
caiu assim no runner. A checagem agora tira o sufixo `@par` e aceita as três interfaces do
próprio caminho lento. Teste:
`COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- cargo test -p corerouter-hal-linux --test netns_routes_batch -- --test-threads 1`
(antes, 1 de 4 passava; agora 4 de 4, **medido**).
