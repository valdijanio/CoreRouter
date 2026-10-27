//! Portuguese labels and explanations of Routing › RPKI (G3.2c), each
//! sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"Add a validator to reject routes whose origin a ROA contradicts."##, r##"Adicione um validador para descartar as rotas cuja origem uma ROA contradiz."##),
    (r##"Address"##, r##"Endereço"##),
    (r##"Check"##, r##"Verificar"##),
    (r##"Comment"##, r##"Comentário"##),
    (r##"Disabled"##, r##"Desativado"##),
    (r##"Expire Interval"##, r##"Validade dos dados"##),
    (r##"FRR"##, r##"FRR"##),
    (r##"FRR bgpd:"##, r##"bgpd do FRR:"##),
    (r##"Group"##, r##"Grupo"##),
    (r##"Name"##, r##"Nome"##),
    (r##"New RPKI Validator"##, r##"Novo validador RPKI"##),
    (r##"New Validator…"##, r##"Novo validador…"##),
    (r##"No validator yet: + adds one (Routinator, rpki-client, StayRTR, FORT…)."##, r##"Nenhum validador ainda: + adiciona um (Routinator, rpki-client, StayRTR, FORT…)."##),
    (r##"Policy"##, r##"Política"##),
    (r##"Port"##, r##"Porta"##),
    (r##"Preference"##, r##"Preferência"##),
    (r##"RPKI Check"##, r##"Verificar RPKI"##),
    (r##"RPKI Validator"##, r##"Validador RPKI"##),
    (r##"Refresh Interval"##, r##"Intervalo de atualização"##),
    (r##"Retry Interval"##, r##"Intervalo de nova tentativa"##),
    (r##"accept"##, r##"aceitam"##),
    (r##"invalid"##, r##"inválida"##),
    (r##"matches"##, r##"corresponde"##),
    (r##"off: no validator"##, r##"desligado: sem validador"##),
    (r##"on: invalid routes rejected"##, r##"ligado: inválidas descartadas"##),
    (r##"origin AS or AS path"##, r##"AS de origem ou AS path"##),
    (r##"reject"##, r##"descartam"##),
    (r##"unknown"##, r##"desconhecida"##),
    (r##"unverified"##, r##"não verificada"##),
    (r##"valid"##, r##"válida"##),
    (r##"waits for a policy"##, r##"aguardam política"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"rpki"##, r##"## O que é
Um validador RPKI (o `/routing rpki` do RouterOS): o roteador mantém uma sessão RTR (RFC 8210, ou RFC 6810 com validador antigo) com ele e recebe as ROAs validadas (VRPs). O bgpd do FRR mantém a sua própria sessão com o mesmo validador e descarta as rotas inválidas.

## Cuidado
Adicionar o primeiro validador liga a política: rotas RPKI-inválidas são descartadas em toda conexão que não tiver `rpki_invalid=accept` (`routing.rpki.invalid.set`). A RFC 8481 §5 só aplica política com configuração do operador; esta é a configuração.

## Recomendado
Dois validadores de implementações diferentes (Routinator e rpki-client, por exemplo), perto do roteador."##),
    (r##"rpki.address"##, r##"## O que é
O endereço do validador. Rode-o perto do roteador (no mesmo site ou no próprio roteador): o RTR não tem criptografia própria (a RFC 8210 §9 pede rede confiável)."##),
    (r##"rpki.check"##, r##"## O que é
O `rpki-check` do RouterOS: o estado RFC 6811 de um prefixo para um AS de origem (ou um AS path, cujo último AS é a origem) e as VRPs que o cobrem."##),
    (r##"rpki.disabled"##, r##"## O que é
Fica na configuração, sem sessão."##),
    (r##"rpki.error"##, r##"## O que é
Por que a última sessão falhou, ou o último Error Report do validador (RFC 8210 §12)."##),
    (r##"rpki.expire_interval"##, r##"## O que é
Por quanto tempo os dados valem sem uma atualização bem-sucedida (RFC 8210 §6: 600..172800, padrão 7200). Depois disso as VRPs saem e toda rota fica `unverified` (nunca bloqueada)."##),
    (r##"rpki.frr"##, r##"## O que é
O estado RTR do próprio bgpd (`show rpki cache-connection`): é o FRR que descarta as inválidas, então ele também precisa estar conectado. Precisa do módulo rpki do FRR (`frr-rpki-rtrlib`, `bgpd -M rpki`)."##),
    (r##"rpki.group"##, r##"## O que é
O banco que o validador alimenta (o `group` do RouterOS). Hoje todo validador ativo alimenta a única tabela que o FRR usa."##),
    (r##"rpki.name"##, r##"## O que é
Um nome para o validador."##),
    (r##"rpki.policy"##, r##"## O que é
O que o RPKI faz agora: liga assim que um validador está ativo. Então cada conexão iBGP descarta as rotas inválidas (`reject`), salvo se disser `accept`; as conexões eBGP não aceitam nada até terem política (RFC 8212), e a checagem RPKI entra nessa política.

Validador fora do ar nunca bloqueia tráfego: sem dados as rotas ficam `unverified` e passam."##),
    (r##"rpki.port"##, r##"## O que é
A porta RTR. A da IANA é 323; o Routinator escuta em 3323 por padrão, o StayRTR em 8282."##),
    (r##"rpki.preference"##, r##"## O que é
Com vários validadores, o de preferência maior é usado primeiro (RouterOS). Vazio: o de menor endereço."##),
    (r##"rpki.refresh_interval"##, r##"## O que é
Segundos entre consultas (Serial Query). Vazio: o do próprio validador, do End of Data (RFC 8210 §6: 1..86400, padrão 3600). O validador também avisa mudanças na hora (Serial Notify). O FRR consulta no máximo a cada 3600 s."##),
    (r##"rpki.retry_interval"##, r##"## O que é
Segundos até tentar de novo depois de uma consulta que falhou (RFC 8210 §6: 1..7200, padrão 600)."##),
    (r##"rpki.serial"##, r##"## O que é
O serial dos dados guardados; cada atualização do validador o aumenta, e o roteador pede só a diferença (Serial Query)."##),
    (r##"rpki.state"##, r##"## O que é
`sync`: a última resposta terminou com End of Data e os dados valem. `connecting`/`loading`: uma consulta está em andamento. `idle`: esperando para tentar de novo. `error`: a última sessão falhou (veja Error). `no daemon`: o laboratório virtual, nenhum cliente RTR roda."##),
    (r##"rpki.version"##, r##"## O que é
A versão do protocolo RTR em uso: 1 (RFC 8210) ou 0 (RFC 6810), rebaixada uma vez quando o validador é antigo (RFC 8210 §7)."##),
    (r##"rpki.vrps"##, r##"## O que é
As Validated ROA Payloads guardadas, por família: uma ROA pode gerar várias (uma por prefixo e max length)."##),
];
