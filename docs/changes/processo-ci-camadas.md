id: processo

Integração mais rápida, depois da rodada de 7 agentes (do primeiro PR pronto, 45 min sem nenhum
entrar): portão em duas camadas e teste instável que não trava a fila. No PR, `cargo xtask ci
--fast` (sem os testes contra o kernel e o `bench-check`); no lote da fila de entrada
(`workflow_dispatch`), no modo um por um (a fila dispara o completo no commit que vai entrar) e
na `main`, o completo. `nextest --retries 1` e, no passo `netns`, o binário que falha roda de
novo sozinho num namespace novo: passar na segunda vez é instável (aviso no CI), não falha. As
sessões ficam "prontas para a fila" ao abrir o PR, sem esperar o CI do GitHub. Motivo: quatro
testes instáveis em 2026-10-22 (latência, ping IPv6, DAD, `netns_l2`), cada um travando a fila
por 5–10 min.
