id: processo-codigo-de-terceiros

Regra nova no CLAUDE.md/AGENTS.md (pedido do usuário, 2026-10-29): em dúvida, problema ou análise
de desempenho que passe por um pacote de terceiros (FRR, kernel, buildroot, nftables, crates), é
obrigatório ler o código do pacote e, quando preciso, compilar com logs e testar por dentro, com
a evidência registrada no PR e a correção no lugar do defeito (patch na imagem e texto para o
projeto de origem). Primeiro caso: o abort do TI-LFA no `ospfd` (G3.4l).
