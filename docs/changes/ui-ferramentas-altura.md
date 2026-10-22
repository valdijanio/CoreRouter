id: ui

Janelas de ferramentas do tamanho do conteúdo, e o `:resolve` só no Tools (pedido do usuário).

- **IP › DNS Resolve saiu.** Era um subconjunto do Tools › DNS Lookup (G6.6), e perguntar um nome é
  diagnóstico, não configuração. O **Resolve…** da janela DNS Cache abre o DNS Lookup já com o nome
  e o tipo da entrada selecionada, perguntando ao roteador. O comando `ip.dns.resolve` (o
  `:resolve` do RouterOS) continua para o terminal, scripts e MCP.
- **Tools › DNS Lookup e MTR abrem da altura do formulário** e crescem com as respostas (o egui
  aumenta a janela quando o conteúdo cresce), em vez de abrir num tamanho fixo com a tabela
  ocupando o espaço vazio. Redimensionada pelo usuário, a janela fica do tamanho que ele deu. As
  listas (Interfaces, Leases, Firewall…) continuam com tamanho fixo, como no WinBox.

Como testar: abra Tools › DNS Lookup (só o formulário), pergunte `uol.com.br` (a janela cresce
com as respostas); DNS Cache › selecione uma entrada › **Resolve…**; Tools › MTR.
