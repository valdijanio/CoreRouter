id: processo-ci-3-vagas

Vagas de CI na máquina de 2 para 3 (pedido do usuário, 2026-10-29): com o disco de build próprio
(`/srv/build`) e 8–10 sessões em paralelo, o gargalo passou a ser a fila das 2 vagas do
`cargo xtask ci` (sessões esperando até 30 min, **medido** em 29/10). A máquina tem 32 núcleos;
3 compilações juntas cabem sem que cada uma fique bem mais lenta (**estimado**; 4 ficaria
limitado pela RAM com a GPU reservando 64 GB). `COREROUTER_CI_SLOTS` continua mudando o número.
