id: valida-pppoe-monitor

PPPoE Client: com a autenticação recusada, o painel de monitor deixava AC Name, AC MAC e Session
ID vazios, embora o cliente tivesse falado com o concentrador (achado do usuário na VM
`corerouter-teste`, cliente `vvs` na `ether1` com a conta do provedor: "login refused — bad
username or password" e os campos com "—"). O `interface.pppoe-client.monitor` tirava esses
campos só da sessão de pé. Agora o `Runner` guarda o concentrador da última tentativa que chegou
a um (`Peer`: AC Name, AC MAC, Session ID e a autenticação que o LCP combinou), e o monitor mostra,
nesta ordem, o da sessão de pé, o da que está negociando (depois do PADO/PADS) ou o da última
tentativa. Também vale para `encoding`: um login PAP recusado mostra `pap`. A redial que volta à
descoberta continua mostrando o concentrador anterior até a nova oferta. A assinatura do comando
diz de onde vêm os quatro campos.

Como testar: `cargo test -p corerouter-engine --lib pppoe_client` (teste novo
`a_refused_login_keeps_the_bng_it_spoke_to`: o BNG do laboratório recusa a senha `wrong`; o
monitor traz AC Name, AC MAC, Session ID e `pap`, e os mantém durante a redial). Na GUI:
PPP › PPPoE Client, um cliente com senha errada, painel de baixo.

Desempenho e paralelismo: uma cópia de um nome de até 64 caracteres por fim de sessão e por
leitura do monitor, fora do caminho de pacotes; nada a dividir.
