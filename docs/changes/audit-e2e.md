id: audit-e2e

Auditoria ponta a ponta: o `corerouter-daemon` de verdade (backend virtual, `--config-dir`
temporário, porta alta, `--no-discovery`), dirigido pela CLI (`--connect`, token local), pelo
MCP (`corerouter-cli mcp`, JSON-RPC no stdin) e por um harness em Python no canal de controle.

Cenários exercitados (todos passaram, salvo os bugs abaixo, já corrigidos): bridge + porta, VLAN
sobre ether e sobre bridge, bonding 802.3ad, VRF com membro, endereços v4/v6 (comentário com
aspas), rotas (main e VRF), address-list, filter, NAT, DNS (servidores, estático, zona primária
com registro), pool + servidor DHCP + rede + concessão fixa, NTP, syslog remoto, identidade;
modo transacional (`config.diff`, commit, discard, rollback + commit); Safe Mode (exit mantém,
cancel desfaz, outro cliente não entra nem sai sem `force`, dono desconecta e dono morto com
`kill -9` desfazem); `/export` → `/import` num daemon novo (export idêntico; running idêntico a
menos dos ids internos, que seguem a ordem do script); SIGTERM e reinício no mesmo diretório
(running e histórico idênticos); `kill -9` no meio de uma rajada de commits (sobe na última
revisão salva, com todo commit confirmado presente); entradas hostis no TCP e no stdin do MCP
(lixo, HTTP, UTF-8 inválido, NUL, array, tipos errados, chave desconhecida, aninhamento de
100 000 níveis, id gigante, linha de 17 MiB com e sem `\n`, 1000 conexões seguidas, conexões
meio abertas): o daemon nunca caiu nem travou; 16 clientes escrevendo em paralelo por 60 s.

Corrigido (cada um com teste que falha na `main`):

- **Estranho "ocupado" segurava vaga sem login para sempre (média).** O limite de ociosidade
  (30 s) zerava a cada byte: 8 conexões mandando um byte (ou um `ping`) a cada 29 s ocupavam
  todas as vagas sem login e **ninguém mais entrava**, nem o operador com token (medido contra o
  daemon: após 45 s, `too many connections that have not logged in`). Agora uma conexão fica no
  máximo `login_grace` (60 s) sem login no total, como o `LoginGraceTime` do SSH; logada, não há
  prazo. Teste: `control/tests/limits.rs::busy_strangers_are_cut_at_the_login_grace`.
- **Clientes com token esperando o lock contavam como "sem login" (média).** A conexão só virava
  logada depois de respondida; com um commit em curso, os 8 primeiros clientes que chegavam
  esperavam o lock ainda "sem login" e o 9º era recusado. Na rodada de 16 clientes por 60 s:
  548 recusas e 517 `Broken pipe` em 1740 operações. Agora o token conferido marca a conexão
  antes de o comando esperar a vez (`answer_with`, TCP/TLS e WebSocket). Depois: 4665 operações,
  zero erros. Teste: `limits.rs::clients_waiting_for_the_session_are_not_logged_out`.
- **MCP morto depois de reiniciar o daemon (média).** O backend `Remote` nunca reconectava: toda
  tool call respondia `send: Broken pipe` até reiniciar o próprio MCP (o daemon é recompilado e
  reiniciado pela fila de entrada). Agora a próxima chamada redisca (relê o token local, loga de
  novo com `--user`, no TLS exige o mesmo certificado), uma sessão de login expirada é refeita, e
  um pedido cuja resposta se perdeu **não** é reenviado ("may or may not have run").
  `Client::is_stale` detecta o fechamento entre pedidos. Testes:
  `mcp/tests/remote_reconnect.rs` (3).
- **`/import` grande era quadrático (média, desempenho).** Cada passo de um `engine.batch`
  atômico copiava o candidate inteiro (ponto de rollback próprio), embora o batch já guarde um.
  Medido no daemon (release): 20 000 entradas de address-list 22,8 s → 0,62 s; 10 000 rotas
  18,3 s → 0,25 s; 4000 regras 1,02 s → 0,08 s. Benchmark novo `engine/benches/batch_import.rs`
  (abaixo). Mudança pequena em `session.rs` (`in_batch: Option<bool>`).
- **`/export` de um bond saía com nota falsa (baixa).** O bond aparece em `/interface` (tipo
  `bonding`) e em `/interface bonding`, que tem `print` próprio: o export trazia
  `# add name=bond1: slaves is not exported` (como se fosse segredo) ao lado do `add` correto.
  Agora o submenu com `print` exporta a linha uma vez, e `/interface set` guarda o que só a
  interface sabe (`disabled`). Teste: `shell/tests/terminal.rs::bond_exports_once_without_a_note`.

Processo: a etiqueta de `docs/changes/` aceita dígitos (`audit-e2e`), começando por letra
(`xtask/src/changes.rs`).

Testes duráveis novos: `apps/corerouter-daemon/tests/e2e.rs` sobe o binário real (porta
efêmera, sem descoberta) — config de todas as áreas sobrevive a SIGTERM e a `kill -9` no meio de
commits, linhas hostis, Safe Mode desfeito quando o dono morre, 8 escritores paralelos sem perda
nem duplicata (~13 s em debug, **medido**).

Verificado e OK (sem mudança): limite de 16 MiB por linha (TCP e MCP), `recursion limit` do
serde para JSON profundo, `MAX_BATCH`, limites de tamanho por parâmetro, lote JSON-RPC recusado,
MCP sai no EOF do stdin, histórico sempre crescente, journal coerente (seq = revisão).
Comportamentos registrados, não bugs: no máximo 16 conexões por porta (o 17º cliente simultâneo
é recusado), e 8 delas sem login; uma conexão que conecta e não manda nada ocupa vaga sem login
até falar; em Safe Mode, mudanças de outro cliente também são desfeitas (como no RouterOS,
`docs/architecture.md`).

Para outras frentes (não mexido aqui):

- **Desempenho (persistência):** cada commit regrava o arquivo inteiro com o histórico; com 4000
  regras + 20 000 entradas + 10 000 rotas o `running.json` bate no teto de 32 MiB e um commit
  leva p50 110 ms / máx. 297 ms (release, **medido**); 16 clientes ficam em ~77 commits/s com
  p50 de 208 ms de fila.
- **DNS:** com `--backend virtual`, `allow_remote_requests` abre o encaminhador em
  `0.0.0.0`/`[::]` do host (a ACL `allowed_from` filtra, mas a porta fica exposta em todas as
  interfaces da máquina de desenvolvimento).

| G0.18 | DHCP: adicionar concessão fixa não pode reavaliar o servidor inteiro | engine | `ip.dhcp-server.lease.add` chama o `verdict` do servidor a cada concessão: 10 000 fixas num `/import` levam 17 s (release, **medido**, depois do batch linear). Avisos só da concessão nova (índice por endereço/MAC), import de 10 000 em < 1 s, mesmo texto de aviso | 3 h | aberto |

## perf

### audit-e2e — batch atômico sem cópia do candidate por passo (**medido**)

AMD Ryzen AI MAX+ 395 (32 CPUs), build release, 2026-10-22. `cargo bench -p corerouter-engine
--bench batch_import` (N entradas de address-list num `Session::batch` atômico, lab novo):

| N | antes | depois | mudança |
|---|---|---|---|
| 1000 | 16,4 ms | 4,67 ms | −72,7% |
| 4000 | 237 ms | 29,3 ms | −87,9% |

No daemon real (release, um `engine.batch` por bloco): 4000 regras 1,02 s → 0,08 s; 20 000
entradas de address-list 22,8 s → 0,62 s; 10 000 rotas 18,3 s → 0,25 s; 10 000 concessões fixas
64,0 s → 17,0 s (resto: G0.18).

Memória do daemon (VmRSS/VmHWM de `/proc/<pid>/status`, release, backend virtual): ocioso
10,8 MiB; + 4000 regras 47 MiB; + 20 000 entradas de address-list 137 MiB; + 10 000 rotas
150 MiB (pico 257 MiB durante os commits seguintes, que serializam o arquivo de 32 MiB);
+ 10 000 concessões fixas 244 MiB (pico 310 MiB); cache DNS com 50 000 nomes distintos
(encaminhador em loopback, upstream DoH local) 289 MiB, pico 354 MiB. Concessões dinâmicas não
foram medidas (o lab virtual não tem caminho de DHCP sem namespace). 16 clientes × 60 s de
escritas mistas: 4665 commits, 77/s, p50 208 ms, p99 450 ms, 0 erros; RSS 217 MiB.
