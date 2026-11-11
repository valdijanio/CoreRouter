//! Portuguese labels and explanations of Interfaces › Wi-Fi (G1.30), each
//! sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    (r##"BSSID"##, r##"BSSID"##),
    (r##"Band"##, r##"Banda"##),
    (r##"Change…"##, r##"Alterar…"##),
    (r##"Channel"##, r##"Canal"##),
    (r##"Connect…"##, r##"Conectar…"##),
    (r##"Copy"##, r##"Copiar"##),
    (r##"Country"##, r##"País"##),
    (r##"Disabled"##, r##"Desativado"##),
    (r##"Enable the radio first: an off radio does not scan"##, r##"Ative o rádio primeiro: rádio desligado não varre"##),
    (r##"Error"##, r##"Erro"##),
    (r##"Hidden Network"##, r##"Rede oculta"##),
    (r##"Last Failure"##, r##"Última falha"##),
    (r##"Lock to BSSID"##, r##"Fixar no BSSID"##),
    (r##"MTU"##, r##"MTU"##),
    (r##"Name"##, r##"Nome"##),
    (r##"Networks"##, r##"Redes"##),
    (r##"No scan yet: Rescan listens on every channel."##, r##"Nenhuma varredura ainda: Varrer de novo escuta todos os canais."##),
    (r##"Note"##, r##"Observação"##),
    (r##"Open…"##, r##"Abrir…"##),
    (r##"Passphrase"##, r##"Senha"##),
    (r##"Radio"##, r##"Rádio"##),
    (r##"Radios"##, r##"Rádios"##),
    (r##"Rate"##, r##"Taxa"##),
    (r##"Reconnect"##, r##"Reconectar"##),
    (r##"Reconnects"##, r##"Reconexões"##),
    (r##"Rescan"##, r##"Varrer de novo"##),
    (r##"SSID"##, r##"SSID"##),
    (r##"Scan…"##, r##"Varrer…"##),
    (r##"Security"##, r##"Segurança"##),
    (r##"Select an enabled radio first"##, r##"Selecione um rádio ativo primeiro"##),
    (r##"Select one network first"##, r##"Selecione uma rede primeiro"##),
    (r##"Select one or more radios first"##, r##"Selecione um ou mais rádios primeiro"##),
    (r##"Select one radio first"##, r##"Selecione um rádio primeiro"##),
    (r##"Select one radio to see its link."##, r##"Selecione um rádio para ver o enlace dele."##),
    (r##"Signal"##, r##"Sinal"##),
    (r##"State"##, r##"Estado"##),
    (r##"This router has no Wi-Fi radio"##, r##"Este roteador não tem rádio Wi-Fi"##),
    (r##"Two letters (ISO 3166-1): BR, US, DE. One country for every radio."##, r##"Duas letras (ISO 3166-1): BR, US, DE. Um país para todos os rádios."##),
    (r##"Wi-Fi"##, r##"Wi-Fi"##),
    (r##"Wi-Fi Country"##, r##"País do Wi-Fi"##),
    (r##"absent"##, r##"ausente"##),
    (r##"access points"##, r##"pontos de acesso"##),
    (r##"blocked"##, r##"bloqueado"##),
    (r##"can be joined"##, r##"dá para entrar"##),
    (r##"connected"##, r##"conectado"##),
    (r##"connecting"##, r##"conectando"##),
    (r##"disabled"##, r##"desativado"##),
    (r##"error"##, r##"erro"##),
    (r##"failed"##, r##"falhou"##),
    (r##"for"##, r##"há"##),
    (r##"hidden"##, r##"oculta"##),
    (r##"in force:"##, r##"em vigor:"##),
    (r##"last scan:"##, r##"última varredura:"##),
    (r##"management frames protected"##, r##"quadros de gerência protegidos"##),
    (r##"network not found"##, r##"rede não encontrada"##),
    (r##"no answer"##, r##"sem resposta"##),
    (r##"no country"##, r##"sem país"##),
    (r##"no network"##, r##"sem rede"##),
    (r##"none"##, r##"nenhuma"##),
    (r##"open"##, r##"aberta"##),
    (r##"radios"##, r##"rádios"##),
    (r##"refused by the access point"##, r##"recusado pelo AP"##),
    (r##"scan failed"##, r##"a varredura falhou"##),
    (r##"scanning…"##, r##"varrendo…"##),
    (r##"searching"##, r##"procurando"##),
    (r##"this card follows its own firmware"##, r##"esta placa segue o próprio firmware"##),
    (r##"wrong passphrase?"##, r##"senha errada?"##),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "interface.wifi",
        r##"## O que é
Um rádio Wi-Fi em modo estação: o roteador entra numa rede Wi-Fi como cliente, para gerência ou como uplink (o `/interface wifi` do RouterOS com `mode=station`). Uma rede por rádio.

## Antes de aplicar
A janela confere por você:
- o tamanho da senha;
- se a última varredura ouviu a rede;
- o país (rádio sem país não liga);
- se a sua sessão chega por este rádio.

Os comandos que ela vai rodar aparecem embaixo.

## Cuidado
- Mudar a rede do rádio por onde você gerencia o roteador pode derrubar a sua sessão: use o **Safe Mode**, que desfaz a mudança se a sessão não voltar.
- Uma estação não entra em bridge: roteie por ela."##,
    ),
    (
        "interface.wifi.band",
        r##"## O que é
Entra só nesta banda: `2ghz`, `5ghz` ou `6ghz`. Em branco: a banda em que a rede estiver, começando pelo ponto de acesso mais forte.

## Quando usar
Rede com o mesmo nome em duas bandas, quando você quer a mais rápida (5 GHz) ou a que alcança mais longe (2,4 GHz)."##,
    ),
    (
        "interface.wifi.bssid",
        r##"## O que é
O endereço MAC de um ponto de acesso. Na configuração: entra só naquele ponto de acesso, mesmo que outro da mesma rede esteja mais forte. Em branco: qualquer um.

## Cuidado
Com o BSSID fixado o rádio não troca de ponto de acesso: se aquele sair do ar, o enlace fica caído."##,
    ),
    (
        "interface.wifi.channel",
        r##"## O que é
A banda e o canal em que o ponto de acesso está, com a frequência. A estação não escolhe o canal: quem escolhe é o ponto de acesso.

## Cuidado
No domínio regulatório mundial (sem país definido) o rádio só escuta em 5 GHz. Em canais com detecção de radar (DFS) o ponto de acesso pode mudar de canal."##,
    ),
    (
        "interface.wifi.country",
        r##"## O que é
O país em que o roteador está, com duas letras (ISO 3166-1: `BR`, `US`, `DE`). Ele decide os canais e a potência que os rádios podem usar. É um país só para todos os rádios do roteador.

## Por que é obrigatório
Sem país o kernel usa o domínio mundial: em 5 GHz o rádio só escuta, e em 2,4 GHz fica limitado. Com o país errado o rádio transmite onde não pode. Por isso um rádio não liga antes de o país ser definido.

## Em vigor
O que o kernel está aplicando agora. Algumas placas (Intel) seguem o próprio firmware e ignoram o país definido aqui; a janela avisa."##,
    ),
    (
        "interface.wifi.disabled",
        r##"## O que é
O rádio está desligado: não varre, não entra em rede e não transmite. Todo rádio começa desativado (como no RouterOS) e é ligado quando tem uma rede e o roteador tem um país."##,
    ),
    (
        "interface.wifi.failure",
        r##"## O que é
Por que a última tentativa não terminou em enlace, em palavras:
- **senha errada?** A troca de chaves falhou. No WPA2 o ponto de acesso nunca diz que a senha está errada, só para de responder: sinal muito fraco e filtro de MAC dão o mesmo resultado.
- **rede não encontrada.** Nenhum ponto de acesso com aquele nome e aquela segurança respondeu à varredura: fora de alcance, outra banda, rede oculta sem *Rede oculta* marcado, ou canal que o país não permite.
- **recusado pelo AP.** Com o motivo que ele deu.
- **sem resposta.** Várias tentativas seguidas não deram em nada.

A causa fica na tela enquanto o roteador continua tentando."##,
    ),
    (
        "interface.wifi.hidden",
        r##"## O que é
A rede não anuncia o nome. O rádio então pergunta por ela pelo nome em cada canal, em vez de esperar ouvi-la.

## Cuidado
Rede oculta não é mais segura: o nome vai em claro toda vez que um cliente entra."##,
    ),
    (
        "interface.wifi.mtu",
        r##"## O que é
O maior pacote que a interface carrega, de 68 a 2304 bytes. O padrão 1500 é o que a Ethernet atrás do ponto de acesso carrega; deixe assim, a não ser que você saiba que o caminho aceita mais."##,
    ),
    (
        "interface.wifi.name",
        r##"## O que é
O nome do rádio: `wifi1`, `wifi2`… (como no RouterOS 7). Ele fica preso ao endereço MAC da placa, então não muda de um boot para outro. Regras de firewall, endereços e o DHCP client usam esse nome como o de qualquer interface."##,
    ),
    (
        "interface.wifi.networks",
        r##"## O que é
O que a última varredura do rádio ouviu: uma linha por ponto de acesso, do mais forte para o mais fraco. **Varrer de novo** escuta todos os canais outra vez (alguns segundos). **Conectar…** abre a configuração do rádio com a rede preenchida; falta só digitar a senha.

## Em que não dá para entrar
A linha fica esmaecida, com o motivo: redes com 802.1X (usuário e senha ou certificado), OWE e as antigas WEP e WPA/TKIP não são suportadas."##,
    ),
    (
        "interface.wifi.networks.security",
        r##"## O que é
O que o ponto de acesso oferece:
- **WPA3**, **WPA2/WPA3**, **WPA2**: com senha. Em WPA2/WPA3 o roteador usa WPA3.
- **aberta**: sem criptografia; quem estiver no alcance lê o que não for criptografado por conta própria.
- **802.1X**, **OWE**, **WEP/WPA**: ainda não dá para entrar."##,
    ),
    (
        "interface.wifi.passphrase",
        r##"## O que é
A senha da rede: de 8 a 63 caracteres. Com *Segurança* `wpa2` também vale a chave de 64 dígitos hexadecimais.

## Como fica guardada
Selada na configuração (cifrada com a chave do roteador). Ela não aparece de novo: listas, log, journal e `/export` mostram `***`. Deixe o campo em branco para manter a que o roteador já tem."##,
    ),
    (
        "interface.wifi.radio",
        r##"## O que é
O driver do kernel da placa (`iwlwifi`, `mt7921e`, `rtw89_8852be`…). Placa cujo driver ou firmware não está na imagem não aparece aqui: veja System › Resources, problemas de hardware."##,
    ),
    (
        "interface.wifi.rate",
        r##"## O que é
A taxa de transmissão que o driver está usando agora, em Mbit/s. Ela acompanha o sinal: o rádio a reduz quando quadros começam a se perder. É a taxa no ar, não a vazão: espere perto da metade."##,
    ),
    (
        "interface.wifi.reconnects",
        r##"## O que é
Quantas vezes o enlace caiu desde que o rádio foi ligado (mudança feita por você não conta). Um número que não para de crescer indica sinal fraco, interferência ou ponto de acesso que reinicia."##,
    ),
    (
        "interface.wifi.security",
        r##"## O que é
Como o rádio se autentica:
- **auto** (padrão): WPA3 se o ponto de acesso oferece, senão WPA2.
- **wpa3**: só WPA3; nunca volta para WPA2.
- **wpa2**: só WPA2, para ponto de acesso que se comporta mal com WPA3.
- **open**: sem senha e sem criptografia.

## Cuidado
Em rede aberta, quem estiver no alcance lê o tráfego que não for criptografado por conta própria (HTTPS, TLS, VPN). Redes com 802.1X e OWE ainda não são suportadas."##,
    ),
    (
        "interface.wifi.signal",
        r##"## O que é
A força com que o ponto de acesso é ouvido, em dBm (quanto mais perto de zero, mais forte).
- **-65 dBm ou melhor** (verde): confortável.
- **de -66 a -75 dBm** (âmbar): funciona, com taxas menores.
- **abaixo de -75 dBm** (vermelho): o enlace cai e tenta de novo."##,
    ),
    (
        "interface.wifi.ssid",
        r##"## O que é
O nome da rede, de 1 a 32 bytes, exatamente como o ponto de acesso anuncia (maiúsculas e espaços contam). Em branco: o rádio esquece a rede e a senha dela."##,
    ),
    (
        "interface.wifi.state",
        r##"## O que é
Onde o rádio está:
- **conectado**: na rede, com a troca de chaves feita.
- **procurando**: varrendo atrás da rede.
- **conectando**: autenticando com um ponto de acesso.
- **sem rede**: ligado, sem rede definida.
- **sem país**: ativado, mas o roteador ainda não tem país; o rádio fica desligado.
- **bloqueado**: desligado por uma chave, pela tecla de modo avião ou pelo firmware (rfkill).
- **ausente**: a placa não está lá (removida, ou o driver não carregou).
- **desativado**: desligado.

Um segundo selo diz por que a última tentativa falhou."##,
    ),
    (
        "menu.wifi",
        r##"## O que faz
O `/interface wifi` do RouterOS em modo estação: o roteador entra numa rede Wi-Fi como cliente, para gerência ou como uplink. Cada rádio é uma interface (`wifi1`), que endereços, o DHCP client e as regras de firewall nomeiam como qualquer outra.

## Como o CoreRouter faz
- WPA2 e WPA3 com senha, e rede aberta com aviso.
- A senha fica selada na configuração e não aparece de novo.
- Rádio não liga antes de o país ser definido.
- O motivo de uma falha vem em palavras: senha errada, rede não encontrada, recusado.
- Mudar a rede do rádio por onde você chega pede o Safe Mode."##,
    ),
];
