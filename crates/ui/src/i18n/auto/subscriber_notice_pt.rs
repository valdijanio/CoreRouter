//! Portuguese labels and explanations of the Subscriber Notices window
//! (G4.10), each sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"Active"##, r##"Ativos"##),
    (r##"Add as New Page"##, r##"Adicionar como nova página"##),
    (r##"Address"##, r##"Endereço"##),
    (r##"Address List"##, r##"Address list"##),
    (r##"Addresses"##, r##"Endereços"##),
    (r##"Behaviour"##, r##"Comportamento"##),
    (r##"Block (com página)"##, r##"Bloquear (com página)"##),
    (r##"Button Text"##, r##"Texto do botão"##),
    (r##"Button URL"##, r##"URL do botão"##),
    (r##"Captive-portal probes the router answers: Android, Apple, Windows, Firefox, Linux and others"##, r##"Sondas de detecção de portal que o roteador responde: Android, Apple, Windows, Firefox, Linux e outros"##),
    (r##"Color"##, r##"Cor"##),
    (r##"Continue Text"##, r##"Texto de continuar"##),
    (r##"DHCP option 114 needs an https address with a valid certificate (capport_url)"##, r##"A opção DHCP 114 precisa de um endereço https com certificado válido (capport_url)"##),
    (r##"DNS"##, r##"DNS"##),
    (r##"Dst. Address"##, r##"Endereço de destino"##),
    (r##"Dst. Host"##, r##"Host de destino"##),
    (r##"Each page view, newest first: proof that the subscriber was told."##, r##"Cada visualização da página, a mais recente primeiro: a prova de que o assinante foi avisado."##),
    (r##"Empty: a blocked subscriber reaches only the page. Add the ISP's site and the payment pages (PIX, boleto)."##, r##"Vazio: um assinante bloqueado só alcança a página. Adicione o site do provedor e as páginas de pagamento (PIX, boleto)."##),
    (r##"Intercept"##, r##"Interceptar"##),
    (r##"Interval"##, r##"Intervalo"##),
    (r##"Kill Connections"##, r##"Encerrar conexões"##),
    (r##"Log"##, r##"Log"##),
    (r##"Login"##, r##"Login"##),
    (r##"Logo URL"##, r##"URL do logo"##),
    (r##"Members"##, r##"Membros"##),
    (r##"Mode"##, r##"Modo"##),
    (r##"Name"##, r##"Nome"##),
    (r##"New Notice Profile"##, r##"Novo perfil de aviso"##),
    (r##"New Walled Garden Entry"##, r##"Nova entrada do walled garden"##),
    (r##"No notice profile: add one in IP › Subscriber Notices"##, r##"Nenhum perfil de aviso: adicione um em IP › Subscriber Notices"##),
    (r##"No profiles. Add one: an address list (bloqueados, aviso) and what its members get. RADIUS Mikrotik-Address-List, PPP profiles and DHCP leases fill the list."##, r##"Nenhum perfil. Adicione um: uma address list (bloqueados, aviso) e o que os membros recebem. O Mikrotik-Address-List do RADIUS, os perfis PPP e os leases do DHCP preenchem a lista."##),
    (r##"Nothing changed"##, r##"Nada mudou"##),
    (r##"Notice Profile"##, r##"Perfil de aviso"##),
    (r##"OS probes"##, r##"sondas de sistema"##),
    (r##"Page"##, r##"Página"##),
    (r##"Pages"##, r##"Páginas"##),
    (r##"Port 80 to the page"##, r##"Porta 80 para a página"##),
    (r##"Portal"##, r##"Portal"##),
    (r##"Preview (sample values)"##, r##"Prévia (valores de exemplo)"##),
    (r##"Profile"##, r##"Perfil"##),
    (r##"Profiles"##, r##"Perfis"##),
    (r##"Rate Limit"##, r##"Limite de taxa"##),
    (r##"Remove"##, r##"Remover"##),
    (r##"Revert"##, r##"Desfazer"##),
    (r##"Save"##, r##"Salvar"##),
    (r##"Seen"##, r##"Viu"##),
    (r##"Select a subscriber first"##, r##"Selecione um assinante antes"##),
    (r##"Select one or more rows first"##, r##"Selecione uma ou mais linhas antes"##),
    (r##"Since"##, r##"Desde"##),
    (r##"Source"##, r##"Origem"##),
    (r##"Subscriber Notices"##, r##"Avisos ao assinante"##),
    (r##"Test as Client"##, r##"Testar como cliente"##),
    (r##"Text"##, r##"Texto"##),
    (r##"The built-in page is read only: type a name and add it as a new page to edit its texts."##, r##"A página embutida é só de leitura: digite um nome e adicione-a como nova página para editar os textos."##),
    (r##"Time"##, r##"Hora"##),
    (r##"Timeout"##, r##"Tempo limite"##),
    (r##"Title"##, r##"Título"##),
    (r##"Type a name"##, r##"Digite um nome"##),
    (r##"Unblock (no page)"##, r##"Desbloquear (sem página)"##),
    (r##"User Agent"##, r##"User agent"##),
    (r##"Variables: {login} {plano} {valor} {vencimento} {link_pix} {endereco} {perfil}"##, r##"Variáveis: {login} {plano} {valor} {vencimento} {link_pix} {endereco} {perfil}"##),
    (r##"Via"##, r##"Via"##),
    (r##"Walled Garden"##, r##"Walled Garden"##),
    (r##"Walled Garden Entry"##, r##"Entrada do walled garden"##),
    (r##"Walled garden addresses"##, r##"Endereços do walled garden"##),
    (r##"Webhook"##, r##"Webhook"##),
    (r##"default (built-in)"##, r##"padrão (embutida)"##),
    (r##"new page name"##, r##"nome da nova página"##),
    (r##"none: this address browses normally"##, r##"nenhum: este endereço navega normalmente"##),
    (r##"under a profile"##, r##"sob um perfil"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"menu.subscriber-notice"##, r##"## O que faz
A página de bloqueio e de aviso do provedor. Um **perfil** liga uma *address list* do firewall a um modo:
- **block:** só DNS, a página e o walled garden passam; o resto é recusado na hora (o app mostra "sem conexão" em vez de travar);
- **notice:** internet normal; o sistema do aparelho mostra "Entrar na rede" até o assinante ver a página;
- **throttle:** como o aviso, com a banda reduzida.

## Como o cliente vê a página, sem erro de certificado
Todo sistema (Android, iPhone, Windows, Linux) testa a rede com um endereço **HTTP** conhecido. O roteador responde no lugar dele, e o próprio sistema abre a página. Funciona para quem só usa apps e HTTPS, com DNS criptografado e atrás do roteador do cliente.

## Quem põe na lista
Lista estática, o lease do DHCP ou o secret do PPP ("Block (com página)"), o `Mikrotik-Address-List` do RADIUS, o CoA, a API e o MCP. Sair da lista libera em segundos, sem derrubar o PPPoE."##),
    (r##"subscriber-notice.active.seen"##, r##"## Seen
Se o assinante viu a página (e há quanto tempo). No aviso, quem viu navega livre pelo *interval* do perfil."##),
    (r##"subscriber-notice.active.source"##, r##"## Source
**static:** uma entrada da address list na config. **dynamic:** posta pelo RADIUS, pelo PPP, pelo DHCP ou pela API, com prazo."##),
    (r##"subscriber-notice.garden"##, r##"## Walled Garden
O que um assinante bloqueado ainda alcança: o site do provedor, a página do PIX, o boleto. Um domínio é resolvido pelo DNS do próprio roteador a cada 5 minutos; um prefixo vale como está.

## Recomendado
Comece vazio e adicione só o necessário: cada entrada é um caminho para fora do bloqueio."##),
    (r##"subscriber-notice.garden.addresses"##, r##"## Addresses
Quantos endereços o DNS do roteador resolveu para a entrada agora."##),
    (r##"subscriber-notice.garden.dst_address"##, r##"## Dst. Address
Um endereço ou prefixo liberado como está (`203.0.113.0/24`)."##),
    (r##"subscriber-notice.garden.dst_host"##, r##"## Dst. Host
Um domínio (`pix.banco.com.br`). O roteador resolve e libera os endereços. Subdomínios entram um a um."##),
    (r##"subscriber-notice.log"##, r##"## Log
Cada visualização da página, com o sistema que trouxe o assinante (a sonda do Android, do iPhone…), o login e o navegador: a prova de que ele foi avisado. `timeout`: o aviso acabou sem visualização."##),
    (r##"subscriber-notice.log.via"##, r##"## Via
O que trouxe o assinante à página: a sonda de um sistema (`android`, `apple`, `windows`, `firefox`, `linux`…), `browser` (um site HTTP), `continue` (o link de continuar) ou `timeout`."##),
    (r##"subscriber-notice.page.button_text"##, r##"## Button Text
O texto do botão principal (`Pagar com PIX`)."##),
    (r##"subscriber-notice.page.button_url"##, r##"## Button URL
Para onde o botão leva; `{link_pix}` é o comum. Só `http://` e `https://`. O destino precisa estar no walled garden."##),
    (r##"subscriber-notice.page.color"##, r##"## Color
A cor do topo e do botão, `#rrggbb`."##),
    (r##"subscriber-notice.page.continue_text"##, r##"## Continue Text
No aviso: o link que marca a página como vista e libera a navegação."##),
    (r##"subscriber-notice.page.logo_url"##, r##"## Logo URL
O endereço `https://` do logo. Ele precisa estar no walled garden, ou o assinante bloqueado não o carrega."##),
    (r##"subscriber-notice.page.text"##, r##"## Text
O corpo da página. Uma linha em branco separa parágrafos. As variáveis `{login}` `{plano}` `{valor}` `{vencimento}` `{link_pix}` vêm do sistema do provedor (`ip.subscriber-notice.vars.set`) ou do PPP; `{endereco}` e `{perfil}` o roteador sabe."##),
    (r##"subscriber-notice.page.title"##, r##"## Title
O título no topo da página e na aba do navegador. Aceita variáveis."##),
    (r##"subscriber-notice.pages"##, r##"## Page
A página que o assinante vê, servida pelo próprio roteador. Edite os textos e veja a prévia ao lado. A embutida é só de leitura: copie-a como nova página."##),
    (r##"subscriber-notice.portal"##, r##"## Portal
O servidor da página no próprio roteador (porta 8880). Ele responde às sondas de cada sistema, mostra a página e registra a visualização. A opção DHCP 114 (RFC 8910) vai só com `capport_url` https e certificado válido."##),
    (r##"subscriber-notice.profile"##, r##"## O que é
Um perfil diz o que acontece com quem está numa *address list*: bloqueio com página, aviso ou redução. Um perfil por lista.

## Cuidado
A lista é a mesma do firewall: o sistema do provedor (MK-Auth, IXC, SGP) já sabe preenchê-la pela API ou pelo RADIUS."##),
    (r##"subscriber-notice.profile.address_list"##, r##"## Address List
A lista do firewall cujos membros recebem o perfil. O RADIUS (`Mikrotik-Address-List`), os perfis PPP, os leases do DHCP e a API a preenchem. Listas começando com `sn-` são do roteador."##),
    (r##"subscriber-notice.profile.behaviour"##, r##"## Behaviour
O que um membro recebe, em poucas palavras, calculado pelo roteador."##),
    (r##"subscriber-notice.profile.intercept"##, r##"## Intercept
O que da porta 80 vai para a página:
- **probes:** só as sondas de detecção de portal dos sistemas (o aparelho mostra "Entrar na rede"); o resto navega;
- **http:** todo site HTTP (também as sondas).

Padrão: http no bloqueio, probes no aviso. HTTPS nunca é interceptado (sem erro de certificado)."##),
    (r##"subscriber-notice.profile.interval"##, r##"## Interval
No aviso e na redução: depois de ver a página, o assinante fica livre por este tempo (`1d`, `6h`). Depois, a página aparece de novo."##),
    (r##"subscriber-notice.profile.kill_connections"##, r##"## Kill Connections
No bloqueio: encerra as conexões abertas do assinante quando ele entra na lista. Sem isso, um download em andamento continuaria pelo caminho rápido."##),
    (r##"subscriber-notice.profile.mode"##, r##"## Mode
- **block:** só DNS, a página, o walled garden e o pagamento passam; TCP recebe RST e o resto ICMP *administratively prohibited* na hora.
- **notice:** a internet funciona; a página aparece uma vez a cada *interval*.
- **throttle:** como notice, com a banda cortada para o *rate limit*."##),
    (r##"subscriber-notice.profile.name"##, r##"## Name
O nome do perfil (aparece no log e no webhook)."##),
    (r##"subscriber-notice.profile.page"##, r##"## Page
A página mostrada; vazio usa a embutida. Edite na aba Pages."##),
    (r##"subscriber-notice.profile.rate_limit"##, r##"## Rate Limit
Na redução: a banda do assinante enquanto ele está na lista, no formato do RouterOS `rx/tx` (`1M/1M`). Vira uma fila dinâmica em Queues."##),
    (r##"subscriber-notice.profile.timeout"##, r##"## Timeout
No aviso e na redução: se o assinante não vir a página neste tempo, o aviso para sozinho (registrado no Log como `timeout`). 0: nunca para. Evita prender uma TV que não abre página."##),
    (r##"subscriber-notice.profile.webhook"##, r##"## Webhook
Avisa o sistema do provedor (POST JSON) quando um assinante entra ou sai da lista, para mandar WhatsApp, SMS ou e-mail. Cobre TV e IoT, que não mostram página."##),
    (r##"subscriber-notice.test"##, r##"## Test as Client
O que um endereço recebe agora: o perfil, se o DNS passa, se a porta 80 vai para a página, se o HTTPS é recusado, a resposta para a sonda de cada sistema e os motivos de não funcionar (walled garden vazio, regra de `input` que derruba o portal)."##),
];
