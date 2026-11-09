//! Portuguese labels and explanations of Routing › Rules (G1.27e), each
//! sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"0 hides the default route"##, r##"0 esconde a rota padrão"##),
    (r##"Action"##, r##"Ação"##),
    (r##"Comment"##, r##"Comentário"##),
    (r##"Disabled"##, r##"Desativado"##),
    (r##"Dst. Address"##, r##"Endereço de destino"##),
    (r##"Family"##, r##"Família"##),
    (r##"Interface"##, r##"Interface"##),
    (r##"Kernel List"##, r##"Lista do kernel"##),
    (r##"Kernel Table"##, r##"Tabela do kernel"##),
    (r##"Marks"##, r##"Marcas"##),
    (r##"Match"##, r##"Casa com"##),
    (r##"Min. Prefix"##, r##"Prefixo mínimo"##),
    (r##"Move Down"##, r##"Mover para baixo"##),
    (r##"Move Up"##, r##"Mover para cima"##),
    (r##"Name"##, r##"Nome"##),
    (r##"New Routing Rule"##, r##"Nova regra de roteamento"##),
    (r##"New Routing Table"##, r##"Nova tabela de roteamento"##),
    (r##"New Rule…"##, r##"Nova regra…"##),
    (r##"New Table…"##, r##"Nova tabela…"##),
    (r##"No rule yet: every packet uses the main table. + adds one."##, r##"Nenhuma regra ainda: todo pacote usa a tabela main. + adiciona uma."##),
    (r##"Owner"##, r##"Dono"##),
    (r##"Priority"##, r##"Prioridade"##),
    (r##"Routes"##, r##"Rotas"##),
    (r##"Routing Mark"##, r##"Marca de roteamento"##),
    (r##"Routing Rule"##, r##"Regra de roteamento"##),
    (r##"Routing Table"##, r##"Tabela de roteamento"##),
    (r##"Rule"##, r##"Regra"##),
    (r##"Rules"##, r##"Regras"##),
    (r##"Src. Address"##, r##"Endereço de origem"##),
    (r##"State"##, r##"Estado"##),
    (r##"Table"##, r##"Tabela"##),
    (r##"Tables"##, r##"Tabelas"##),
    (r##"Test"##, r##"Testar"##),
    (r##"Test a Packet"##, r##"Testar um pacote"##),
    (r##"Type"##, r##"Tipo"##),
    (r##"What"##, r##"O quê"##),
    (r##"any"##, r##"qualquer um"##),
    (r##"drift"##, r##"diferença"##),
    (r##"from: 10.91.0.7"##, r##"de: 10.91.0.7"##),
    (r##"in: ether3"##, r##"entrada: ether3"##),
    (r##"kernel differs"##, r##"kernel difere"##),
    (r##"marks without a table"##, r##"marcas sem tabela"##),
    (r##"routing mark"##, r##"marca de roteamento"##),
    (r##"set by the mangle"##, r##"posta pelo mangle"##),
    (r##"to: 8.8.8.8"##, r##"para: 8.8.8.8"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"kernel"##, r##"## O que é
A lista inteira de regras do kernel, na ordem em que ele a percorre, com quem escreveu cada linha. Mostra no que as regras viraram e as regras de outros programas, que o CoreRouter nunca remove."##),
    (r##"kernel.marks"##, r##"## O que é
Marcas de roteamento do mangle que não nomeiam tabela. Sozinhas não mandam o pacote a lugar nenhum: só uma regra com esse `routing_mark` as usa. Crie uma tabela com esse nome ou use a marca numa regra."##),
    (r##"kernel.match"##, r##"## O que é
O que a linha casa: origem, destino, interface de entrada, marca, ou `l3mdev` para pacote em VRF."##),
    (r##"kernel.owner"##, r##"## O que é
- `kernel`: do próprio kernel.
- `corerouter`: escrita a partir desta configuração.
- `foreign`: outro programa ou `ip rule`. Fica intacta e pode mudar o que as regras decidem."##),
    (r##"kernel.priority"##, r##"## O que é
Menor roda primeiro. A regra 0 é a tabela `local`, as marcas do mangle 100 a 999, as VRFs 1000 e 1001, as regras desta janela de 2000 em diante e a `main` 32766."##),
    (r##"kernel.rule"##, r##"## O que é
A regra da aba Rules por trás desta linha."##),
    (r##"kernel.what"##, r##"## O que é
O que a linha representa, em palavras."##),
    (r##"menu.routing-rules"##, r##"## O que faz
Roteamento por política: regras que escolhem a tabela de rotas pela origem, destino, interface de entrada ou marca de roteamento, as tabelas nomeadas para onde apontam e a lista inteira de regras do kernel."##),
    (r##"rules"##, r##"## O que é
Uma regra de roteamento por política (`/routing rule` do RouterOS). As regras rodam de cima para baixo e a primeira que decide vence. Um pacote para um endereço deste roteador nunca chega a elas: a tabela `local` do kernel vem antes.

## Cuidado
Uma regra pode parar as respostas da sua própria sessão. A janela avisa e pede confirmação; o Safe Mode também protege."##),
    (r##"rules.action"##, r##"## O que é
- `lookup`: procura na tabela; sem rota lá, segue para a próxima regra.
- `lookup-only-in-table`: procura só nessa tabela; sem rota lá, o pacote fica inalcançável.
- `drop`: descarta em silêncio.
- `unreachable`: descarta, e o remetente recebe ICMP unreachable."##),
    (r##"rules.disabled"##, r##"## O que é
Fica na config e sai do kernel. Mantém o lugar na ordem."##),
    (r##"rules.dst_address"##, r##"## O que é
O destino que o pacote precisa ter. Vazio: qualquer um. Um endereço também limita a regra à família dele."##),
    (r##"rules.family"##, r##"## O que é
IPv4, IPv6 ou as duas. Regra sem endereço vale para as duas."##),
    (r##"rules.interface"##, r##"## O que é
A interface por onde o pacote entrou. `lo` casa com os pacotes do próprio roteador. Membro de VRF é recusado: a tabela da VRF responde antes de qualquer regra, então marque esses pacotes no mangle."##),
    (r##"rules.min_prefix"##, r##"## O que é
Rotas desse tamanho ou menores são ignoradas na tabela (`suppress_prefixlength` do Linux). 0 esconde a rota padrão: usa as rotas específicas da tabela e, sem elas, segue para a próxima regra."##),
    (r##"rules.order"##, r##"## O que é
A posição na lista: as regras rodam nessa ordem. A prioridade no kernel sai dela."##),
    (r##"rules.routing_mark"##, r##"## O que é
A marca de roteamento que uma regra de mangle pôs no pacote. Marca com o nome de uma tabela já manda o pacote para ela, antes de qualquer regra; este campo é para marca que não nomeia tabela."##),
    (r##"rules.src_address"##, r##"## O que é
A origem que o pacote precisa ter. Vazio: qualquer uma. Pacote do próprio roteador ainda sem origem escolhida não casa."##),
    (r##"rules.state"##, r##"## O que é
- `active`: está no kernel.
- `disabled`: fora do kernel.
- `warning`: do jeito que está, não faz nada; a linha abaixo da tabela diz por quê."##),
    (r##"rules.table"##, r##"## O que é
Onde procurar: `main`, uma VRF ou uma tabela da aba Tables. A tabela precisa de rotas próprias: as redes conectadas ficam na `main`, então o tráfego para uma rede local costuma precisar de uma regra para a `main` acima desta."##),
    (r##"rules.test"##, r##"## O que é
Percorre as regras como o kernel faria para um pacote com esses campos e mostra cada regra que casou. O kernel também é consultado: uma diferença aparece como aviso, por exemplo uma regra posta por outro programa.

Com interface de entrada, a origem é obrigatória: o kernel se recusa a rotear pacote sem ela."##),
    (r##"tables"##, r##"## O que é
Tabelas de roteamento com nome (`/routing table` do RouterOS), mais a `main` e as VRFs. A rota entra numa delas com `routing_table` em IP › Routes; uma regra ou uma marca do mangle com o mesmo nome manda pacotes para lá."##),
    (r##"tables.marks"##, r##"## O que é
Regras de mangle que marcam pacotes para esta tabela."##),
    (r##"tables.name"##, r##"## O que é
Até 15 de A-Z a-z 0-9 - _ . Não pode ser nome de tabela do kernel nem de VRF."##),
    (r##"tables.routes"##, r##"## O que é
Rotas estáticas nesta tabela."##),
    (r##"tables.rules"##, r##"## O que é
Regras que procuram nesta tabela."##),
    (r##"tables.table"##, r##"## O que é
O número da tabela no kernel, escolhido automaticamente e guardado na config. `ip route show table N` mostra."##),
    (r##"tables.type"##, r##"## O que é
- `main`: a tabela principal do kernel.
- `vrf`: a tabela de uma VRF (muda em IP › VRF).
- `named`: uma desta janela."##),
];
