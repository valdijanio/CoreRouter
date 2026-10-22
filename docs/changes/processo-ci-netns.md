id: processo

Mais tempo tirado do CI (números em `docs/perf.md`, "CI e build"). Os testes em namespace
(`cargo xtask netns`) compilam todos os binários num `cargo test --no-run` e rodam os 11 ao mesmo
tempo, cada um no seu user + network namespace descartável, como antes, com a saída agrupada
por binário: de 33–36 s para ~9 s nesta máquina (**medido**, 32 núcleos, build pronto). No CI,
os pacotes do `apt` vêm de cache (`awalsh128/cache-apt-pkgs-action`, fixado por SHA), sem o
`apt-get update` que variava de 14 s a 114 s; o passo do `vrf` só atualiza a lista de pacotes
quando precisa baixar o módulo.
