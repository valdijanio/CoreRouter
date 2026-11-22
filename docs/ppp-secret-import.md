# Migrar os secrets PPP do MikroTik, com as senhas (G4.3n)

Um provedor que sai do RouterOS leva os assinantes locais (`/ppp secret`) com as senhas, sem
pedir a ninguém para digitar de novo. Três peças:

1. **`ppp.secret.import`** lê um export do RouterOS e importa os secrets numa mudança só;
2. as senhas ficam **seladas** na config (cifradas, com a chave fora dela);
3. o nosso **`/export show-sensitive`** devolve as senhas, só para o grupo `full`, e a ida e
   volta (RouterOS → nós → nós) fica idêntica.

## Como usar

No MikroTik:

```
/ppp secret export show-sensitive file=secrets
```

(ou um `/export show-sensitive` inteiro: só `/ppp secret` e `/ppp profile` são lidos). **Sem
`show-sensitive` o RouterOS omite as senhas sem avisar**; a pré-visualização conta quantos
secrets vieram sem senha.

Na GUI: **PPP › Secrets › Import from MikroTik…**. O arquivo vem do caminho (o app lê, até
32 MiB), arrastado para a janela ou colado. **Preview** roda o comando com `dry_run`: selos com
quantos têm senha, quantos não, perfis que faltam, nomes que já existem e erros; a tabela de
perfis mapeia cada perfil do RouterOS para um nosso (ou "criar a partir do arquivo", quando o
arquivo o define). Mudar o mapeamento refaz a pré-visualização. **Import** aplica numa revisão;
com **Enter Safe Mode** antes, perder o roteador desfaz a importação. O texto nunca aparece na
tela e é esquecido ao importar e ao fechar; a janela lembra de apagar o arquivo.

Pelo comando (CLI, MCP, terminal):

```
corerouter-cli run ppp.secret.import "$(jq -n --rawfile t secrets.rsc '{text: $t, dry_run: true}')"
corerouter-cli run ppp.secret.import "$(jq -n --rawfile t secrets.rsc '{text: $t, profile_map: {VELHO: "default"}, on_conflict: "skip"}')"
```

- `profile_map`: perfil do RouterOS → nosso. Sem mapa, vale o mesmo nome; um perfil que o
  arquivo define e não temos é criado dele (`create_profiles`, padrão sim); qualquer outro
  impede a importação (aparece em `missing_profiles`).
- `on_conflict`: `skip` (padrão, o nosso fica), `replace` (o do arquivo toma o lugar, mantém o
  id) ou `rename` (`nome-2`, `nome-3`…).
- O relatório: `total`, `with_password`, `without_password`, `profiles` (cada perfil usado, com
  `here`, `in_file` e o destino), `conflicts`, `added`/`replaced`/`renamed`/`skipped`,
  `duplicates` (mesmo nome duas vezes no arquivo: fica o primeiro), `set_unknown` (`set` de algo
  que o arquivo não criou, como `set *0` do perfil `default`: o nosso fica), `unsupported`
  (campos sem equivalente aqui, com a contagem), `errors` (linha, nome, parâmetro, motivo),
  `warnings` (caller-id que não é MAC, endereço fixo repetido) e o lembrete de apagar o arquivo.
  **Nenhuma senha.**

## O leitor do export (`crates/engine/src/rsc.rs`)

Entende o que o RouterOS v7 escreve: linha de menu (`/ppp secret`, `/ppp/secret`) ou o menu na
frente de cada comando (`terse`); `\` no fim continua na linha seguinte (o recuo é descartado),
inclusive dentro de um valor entre aspas; os escapes `\"`, `\\`, `\n`, `\r`, `\t`, `\$`, `\?`,
`\_`, `\a`, `\b`, `\f`, `\v` e `\XX` (byte em hexa: o RouterOS escreve `ç` como `\C3\A7`); os
bytes viram UTF-8, ou Latin-1 quando não são (comentários antigos em Windows-1252);
`set [ find name=x ]`, `set [ find where name=x ]`, `set [ find default=yes ]` e `set *0`;
comentários, `;` e linhas em branco.

O texto é hostil: no máximo 32 MiB (16 MiB pelo canal de controle, o limite de uma requisição),
64 KiB por comando juntando as continuações, 64 argumentos, 4 KiB por valor e 250 mil comandos.
Um erro diz linha, coluna e o que se esperava, **nunca o texto** (o arquivo tem todas as
senhas). Testes: proptest no próprio módulo e no `tests/fuzz.rs` do engine, e o alvo de fuzz
`routeros_export` (`docs/fuzzing.md`).

## Senhas seladas (`crates/engine/src/sealing.rs`)

O CHAP e o MS-CHAP precisam da senha em si (RFC 1994 §2.2: o segredo entra no hash com o
desafio), então um hash como o dos usuários (Argon2id) não serve. A config guarda a senha
**selada**: `$cr1$` + base64 de AES-256-GCM (nonce aleatório de 96 bits, texto associado
fixo), com uma chave de 32 bytes **fora da config**, no estado `secret-key` do armazenamento:
`<config-dir>/state-secret-key.json`, modo 0600, criado no primeiro uso. RFC 1994 §6 pede que o
segredo seja legível só por quem precisa dele: aqui, só o engine abre a caixa (o login PPPoE, por
sessão, 0,5 µs **medido**; e o `export show-sensitive` do grupo `full`).

- Toda cópia da config leva a caixa, não a senha: revisões, os arquivos `rev-*.json`, o
  `running.json`, o `config.diff`, o `state.inspect`, o undo. Senhas iguais dão caixas
  diferentes (nonce aleatório).
- **Backup:** a config sem a chave não abre as senhas. Guarde a pasta inteira (ou faça
  `/export show-sensitive`, que é portátil). Uma chave que existe e não se lê nunca é trocada
  por outra (as senhas seladas com ela seriam perdidas): o login local é recusado com "password
  cannot be opened" e o log de partida diz por quê.
- Configs de antes do G4.3n (senhas em claro) são seladas na partida, numa revisão automática
  ("G4.3n: PPP passwords sealed at rest"); as revisões mais velhas ficam como estavam até saírem
  do histórico.
- No laboratório do navegador (wasm, sem fonte aleatória e sem disco) a chave e os nonces são
  daquela execução.

Onde a senha **não** aparece, com teste que procura o texto em cada saída
(`crates/engine/tests/ppp_import.rs`, `crates/mcp/tests/protocol.rs`,
`crates/ui/src/tests/ppp_import.rs`): journal (o `text` do import vira `*** (N bytes)`,
`auth::SECRET_PARAMS`), log, `config.diff`, `config.history`, `state.inspect`, `ppp.secret.list`
(`***`), os arquivos salvos, o `Debug` da config, a saída do MCP (as ferramentas mascaram toda
chave de segredo, inclusive o `show_sensitive` que o token local pediria) e a GUI.

## `/export show-sensitive`

Como no RouterOS v7, `show-sensitive` é uma bandeira sem valor (`show-sensitive=yes` é recusado).
O terminal pede a cada `print` que declara `show_sensitive` os segredos em claro; abaixo do grupo
`full` o roteador recusa ("needs group full"), como a política `sensitive` do RouterOS. Sem a
bandeira, um secret continua saindo comentado (`# add name=x: password is not exported (export
show-sensitive)`). O arquivo ganha um aviso no cabeçalho. O resultado volta por
`ppp.secret.import` (qualquer tamanho até o limite) ou por `/import` (até 1 MiB de script).

## Pesquisa

Fontes (a pesquisa da sessão principal, que o usuário aprovou em 2026-10-26, mais a leitura do
código atual):

- **MikroTik RouterOS v7** ([busca: show-sensitive](https://help.mikrotik.com/docs/dosearchsite.action?queryString=show-sensitive&where=ROS),
  [busca: ppp secret](https://help.mikrotik.com/docs/dosearchsite.action?queryString=ppp%20secret&where=ROS);
  páginas Configuration Management, User e PPP AAA): a senha do `/ppp secret` está na lista de
  dados sensíveis e só sai com `show-sensitive`, uma bandeira (`=yes` é recusado); um export sem
  ela omite as senhas sem aviso; o grupo `read` padrão já tem a política `sensitive` (nós somos
  mais restritos: só `full`). Nomes e padrões dos campos do `/ppp secret` e do `/ppp profile`.
- **[RFC 1994](https://www.rfc-editor.org/rfc/rfc1994)** (CHAP; sem errata técnica que mude isto), §2.2 (o segredo tem de estar em claro no autenticador) e §6 (segredos
  legíveis só pelo processo que precisa). RFC 2759 (MS-CHAPv2) tem a mesma exigência (o hash NT
  da senha).
- **[accel-ppp](https://docs.accel-ppp.org/)** `chap-secrets`: `user * senha ip [rate]`, arquivo em texto claro.
- **Outros** (documentação lembrada, não reaberta nesta sessão): Cisco IOS `password 7` é
  reversível e trivial; o tipo 6 cifra com AES e uma chave mestra guardada à parte (`key
  config-key password-encrypt`) — é o modelo que seguimos; Junos guarda segredos com `$9$`
  (ofuscação reversível, sem chave); VyOS e pfSense/OPNsense guardam as senhas locais do
  PPPoE no próprio arquivo de config.

O que adotamos: nomes e formato do RouterOS (a referência do usuário), `show-sensitive` como
bandeira, a cifra com chave separada (como o tipo 6 da Cisco, não ofuscação), e uma importação
própria em vez de `/import` cego: com pré-visualização, mapeamento de perfis, política de nomes
repetidos e uma transação só.

Melhorias propostas e aprovadas (entraram): senha fora de journal, log, MCP, diff e undo; senha
cifrada em repouso; lembrete de apagar o arquivo; `show-sensitive` só para `full`; `routes=`
importado (G4.3cd) com as mesmas recusas do `ppp.secret.add` (bloco de outro secret, pool,
endereço do roteador) e o arquivo conferido contra si mesmo (dois secrets no mesmo bloco, IP fixo
dentro do bloco de outro). Um campo que o `ppp.secret.add` não declara vai para `unsupported`.

Entrou também, porque o selo a teria piorado: o teto de uma config salva subiu de 15 para 31 MiB
(`persist::SAVE_BUDGET_BYTES` de 32 para 64 MiB). Com 15 MiB, 100 mil secrets completos não
cabiam nem em claro (21,8 MB), e o `bench-check` mostrou que nem 100 mil secrets mínimos cabiam
depois de selados.

Ficou de fora (gaps novas): import acima de 16 MiB pelo canal de controle (G4.3na) e selar os
outros segredos (TSIG, RADIUS) com o mesmo `show-sensitive` (G4.3nb).

**Cifra:** começamos com XChaCha20-Poly1305 e trocamos por AES-256-GCM depois de medir o login:
abrir uma senha de 12 bytes custava 1,33 µs com XChaCha20-Poly1305, 0,98 µs com
ChaCha20-Poly1305 e 0,094 µs com AES-256-GCM (**medido**, release, RustCrypto com AES-NI escolhido
em tempo de execução). Nonce aleatório de 96 bits: o limite do NIST SP 800-38D §8.3 é 2³² caixas
por chave, e um roteador sela no máximo alguns milhões na vida.

## Desempenho

**Medido** (build release, este laptop de desenvolvimento, 2026-10-26; `cargo test --release -p
corerouter-engine --test it ppp_import:: -- --ignored --nocapture`), 100 mil secrets com caller-id,
comentário e endereço fixo, 17,0 MB de export:

| etapa | tempo |
|---|---|
| leitura (`rsc::parse`) | 125–133 ms (750–800 mil linhas/s, ~130 MB/s) |
| `dry_run` (lê, valida, sela, desfaz) | 0,44–0,58 s |
| importação (sem commit) | 0,47–0,64 s (~5 µs por secret) |
| commit dos 100 mil (uma revisão) | 63–65 ms (214 ms antes do CowList da G4.3gb) |
| 40 mil importados no modo imediato (com commit) | 0,19–0,20 s (0,27–0,37 s antes do CowList) |
| abrir uma senha (base64 + AES-256-GCM + `String`) | 0,5 µs |

(Faixas: rodadas diferentes no mesmo laptop, com outras sessões compilando.) Pico de memória do
processo de teste: 372 MB (VmHWM, com o texto, a config, a cópia em claro do teste e o commit).
A config de 100 mil secrets fica com 26,5 MB selada e 21,8 MB em claro (+22 %, ~47 bytes por
senha), dentro do novo teto de 31 MiB.

**Login do BNG, antes e depois** (`cargo bench -p corerouter-daemon --bench pppoe_bng --
setup_1000`, release, do PADI ao IPCP Opened com MS-CHAPv2 local): 1000 sessões com senha em
claro em 12,23–15,19 ms e seladas em 12,51–15,39 ms (+1 a +5 %, +0,2 a +0,7 µs por sessão; três rodadas, a última com a máquina carregada). Com XChaCha20-Poly1305 eram
11,77 contra 13,28 ms (+13 %): foi isso que motivou a troca.

Paralelismo: a leitura e a selagem são por item e independentes, mas o engine não usa threads
(compila para wasm) e a importação é rara (uma vez por migração): 0,6 s para 100 mil não pede
divisão. O BNG abre a senha na thread do worker que atende o login, sem lock novo (a chave é um
`Arc` imutável no `Snapshot`).
