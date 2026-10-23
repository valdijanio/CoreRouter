id: docs

`docs/ui-style.md`: padrão aprovado pelo usuário para janelas de lista e o modal de adicionar
(G0.24): barra **+ − ✓ ✗ 💬** com filtros e Find, selos de estado e origem, rodapé com contagens,
editar por duplo clique, modal com ⓘ em cada rótulo, campos calculados, cadastro em série numa
transação, checagens (conflito, uso na rede, perda de acesso), prévia dos comandos e Cancel/Apply/OK.
A referência é IP › Addresses (G1.28).

| G0.24 | Componentes do padrão de janela de lista e modal de adicionar | ui, engine | Barra de ações (+ − ✓ ✗ 💬) com o porquê do cinza vindo do engine, filtros em selos, rodapé com contagens, menu de clique direito (copiar como comando CoreRouter/RouterOS), modal reutilizável com ⓘ por rótulo, campos calculados pelo engine, cadastro em série numa transação, checagens com selo e prévia dos comandos, Cancel/Apply/OK; documentado em `docs/ui-style.md` | 8 h | aberto |
| G1.28 | IP › Addresses no padrão de lista (referência) | ui, engine, hal-linux | Estado (active/disabled/invalid/tentative), origem (static/dhcp/ra/slaac), lifetime, VRF; `disabled` por endereço (fica na config, sai do kernel); modal com rede calculada, série por faixa, checagem de sobreposição e de ARP (RFC 5227) em segundo plano, aviso de perda de acesso | 6 h | aberto |
