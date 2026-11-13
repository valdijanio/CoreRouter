//! Portuguese labels and explanations of IP › Services (G1.6p), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("Address", "Endereço"),
    ("Available From", "Disponível de"),
    ("Certificate", "Certificado"),
    ("IP Services", "Serviços IP"),
    ("Last Error", "Último erro"),
    ("Name", "Nome"),
    ("Port", "Porta"),
    ("Refused", "Recusadas"),
    ("Status", "Estado"),
    ("This window reaches the router through", "Esta janela chega ao roteador por"),
    ("Turning it off, moving it or leaving your address out of Available From blocks your next login.", "Desligá-lo, movê-lo ou deixar o seu endereço fora de Disponível de bloqueia o seu próximo login."),
    ("everyone", "todos"),
    ("router's own", "do roteador"),
    ("this session", "esta sessão"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    ("ip_services.address", "## Endereço\n\nO endereço em que o serviço escuta. `::` é todo endereço IPv6 e IPv4; `0.0.0.0`, todo IPv4. Precisa ser um endereço do roteador. Para limitar **quem** pode conectar, use **Disponível de**; este campo limita **onde** o serviço responde.\n\n## Cuidado\nNo `www-ssl`, sair do endereço que esta janela usa bloqueia o seu próximo login."),
    ("ip_services.available_from", "## Disponível de\n\nAs redes que podem conectar (o `address` do RouterOS), separadas por vírgula; um endereço sozinho é um host. Vazio é todo mundo que alcança a porta. Os outros são desconectados sem resposta e contados em **Recusadas**.\n\n## Recomendado\nNo `metrics`, que não tem login, indique o servidor Prometheus. Em redes não confiáveis, uma regra de firewall protege melhor: o pacote nem chega ao serviço.\n\n## Cuidado\nNo `www-ssl`, deixar o seu endereço de fora bloqueia o seu próximo login."),
    ("ip_services.certificate", "## Certificado\n\nSó no `www-ssl`: o `/certificate` com que ele atende (System › Certificates); `none` é o do próprio roteador, feito no primeiro boot. Só aparecem os certificados com a chave privada.\n\n## Cuidado\nOs navegadores veem o certificado novo na hora; uma GUI ou CLI que fixou o antigo por esta porta pede para confiar no novo. As conexões já abertas continuam."),
    ("ip_services.enabled", "## Ativado\n\nSe o serviço escuta. O roteador abre ou fecha o socket na hora, sem reiniciar; as conexões já abertas continuam."),
    ("ip_services.last_error", "## Último erro\n\nPor que o socket não abriu, como uma porta já em uso. O roteador tenta de novo a cada poucos segundos."),
    ("ip_services.name", "## Nome\n\n**www-ssl**: a GUI no navegador e o canal de controle por WebSocket, em HTTPS com o certificado do roteador. **www**: HTTP puro que só redireciona para o `www-ssl`, para a senha nunca trafegar em claro. **metrics**: o endpoint `/metrics` do Prometheus, sem login.\n\nO selo **esta sessão** marca o serviço por onde esta janela chegou."),
    ("ip_services.port", "## Porta\n\nA porta TCP, de 1 a 65535. Padrões: 443 no `www-ssl`, 80 no `www`, 9100 no `metrics`. `www-ssl` e `www` não podem dividir a mesma porta.\n\n## Cuidado\nNo `www-ssl`, trocar a porta que esta janela usa bloqueia o seu próximo login no endereço antigo: o navegador precisa usar a porta nova."),
    ("ip_services.refused", "## Recusadas\n\nConexões derrubadas porque o cliente não está em **Disponível de**, desde que o socket abriu. Um número que cresce pode ser alguém varrendo o roteador, ou um cliente que você esqueceu de liberar."),
    ("ip_services.status", "## Estado\n\n**listening**: o socket está aberto. **stopped**: desligado, ou nenhum daemon o executa. **error**: não abriu; veja **Último erro**."),
    ("menu.ip-services", "## O que faz\nOs serviços do roteador na rede, como o `/ip service` do RouterOS: quais estão ligados, em que porta e endereço, e quem pode conectar.\n\n## Cuidado\nO roteador recusa uma mudança que bloquearia o próximo login da sessão que usa aquele serviço, a menos que você confirme. O Safe Mode é o jeito de testar: se a conexão cair, o roteador desfaz a mudança."),
];
