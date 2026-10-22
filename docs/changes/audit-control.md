id: audit-control

Auditoria do canal de controle (TCP/TLS/WebSocket, login, MCP, CLI): 13 dos 14 achados
corrigidos, 1 parcialmente (vira gap). Cada teste abaixo falhou na `origin/main` (19b550e) antes
da correção (**medido**: rodados numa cópia da `main` com a API adaptada).

- **Safe Mode nunca desfeito quando o caminho do dono morre em silêncio** (alta). Sem keepalive
  nem timeout, a thread da conexão ficava presa no `read` para sempre quando rota, endereço ou
  firewall cortavam a gerência (nenhum FIN/RST chega), e o `hang_up` nunca rodava. Agora todo
  socket aceito tem TCP keepalive (15 s + 3 × 5 s) e `TCP_USER_TIMEOUT` de 30 s no Linux
  (`control::conn::keepalive`, crate `socket2` já presente no lockfile). Teste
  `netns_safe_mode_drop` (namespace sem root: TLS em `10.77.0.1`, Safe Mode, `ip addr del`): o
  desfazer roda em 3,1 s com keepalive curto (**medido**); na `main`, nada em 20 s.
- **Vagas esgotadas antes do login / slowloris** (alta). 16 conexões TLS ociosas seguravam
  todas as vagas para sempre, e os 10 s do handshake/cabeçalho eram por `read`, não prazo. Agora
  `conn::Sock` aplica um **prazo total** (handshake TLS e cabeçalho HTTP: 10 s), conexão sem
  login cai após 30 s ociosa, só 8 das 16 vagas podem estar sem login e 4 por origem de rede
  (IPv4 ou /64 IPv6). Testes `idle_strangers_do_not_lock_the_operator_out`,
  `a_trickled_tls_handshake_is_cut_at_the_deadline`, `websocket_head_deadline_and_503`,
  `conn::tests::*`.
- **Requisição de 16 MiB virava `Value` antes de conferir o token** (alta). O envelope agora é
  lido com `&RawValue` (`id`, `params`); `params` só é convertido depois do token (ou, no
  `auth.login`, até 4 KiB); da rede, antes do login, a linha (e a mensagem WebSocket) vai até
  64 KiB, subindo para 16 MiB depois. Teste `params_are_parsed_only_after_the_token_check` e a
  parte "stranger" do `netns_safe_mode_drop`.
- **Limite de login furado por paralelismo e IPv6; Argon2 sem limite** (média). Falhas contam
  por origem IPv4 ou /64 IPv6; a tentativa conta ao começar (checar e contar sob a mesma trava);
  no máximo 2 verificações Argon2 ao mesmo tempo (`LOGIN_BUSY` após 5 s); mapa cheio descarta
  primeiro origens não bloqueadas, nunca `user admin`, e fica sempre ≤ 4096. Testes
  `a_full_failure_map_keeps_the_user_keys`, `parallel_and_rotated_attempts_are_all_counted`
  (16 tentativas paralelas de um /64 → 6 Argon2, 10 recusadas).
- **`localhost` mandava o token local para quem escutasse em `[::1]`** (média). `dial` resolve
  `localhost` como `127.0.0.1`, tenta todos os endereços em ordem e só envia o token local se o
  par conectado for `127.0.0.1` (único endereço em que o roteador escuta em claro). Teste
  `dial::tests::the_local_token_goes_only_to_127_0_0_1`.
- **MCP `run_task` (read-only) executava qualquer comando** (média). Agora só `tool.*` (fora
  `tool.task.*`), recusado antes de rodar. Teste `run_task_refuses_anything_but_a_tool`.
- **Um usuário derrubava as sessões dos outros** (baixa). Limite de 16 sessões por usuário no
  `Gate` e no `Logins` do engine (o 17º login tira o mais antigo **dele**); token despejado
  encerra o login em `user.active.list`. Testes `repeated_logins_do_not_evict_other_users`,
  `engine::auth::tests::repeated_logins_evict_only_the_same_user`.
- **Panic numa thread de conexão vazava a vaga e pulava o `hang_up`** (baixa). A vaga vive no
  socket (devolvida no `Drop`) e `serve_then_hang_up` roda o `hang_up` sob `catch_unwind`.
  Teste `a_panicking_connection_frees_its_slot_and_undoes_safe_mode`.
- **Erro de `accept` girava a 100 % de CPU** (baixa): pausa de 100 ms após a falha (sem teste:
  exigiria esgotar descritores).
- **Arquivo estático lido inteiro na memória, sem timeout de escrita** (baixa): arquivos vão em
  fluxo (`io::copy`) e todo socket tem timeout de escrita de 30 s.
- **Conexão WebSocket acima do limite recebia uma linha JSON, não `503`** (baixa): `503` no
  WebSocket/HTTP, linha JSON no TCP, nada no TLS (coberto em `websocket_head_deadline_and_503`).
- **`server.info` revelava versão e commit sem login pela rede** (baixa): da rede, sem login, só
  `{name, auth}`; loopback inalterado (`server_info_on_loopback_is_complete`, netns).
- **Chave TLS restaurada com 0644 ficava legível** (baixa): escrita em arquivo temporário 0600 +
  `rename`, e chave existente com bits de grupo/outros volta a 0600 com aviso. Teste
  `tls::tests::a_world_readable_key_is_made_private`.
- **MCP respondia respostas JSON-RPC e ecoava `id` objeto/array** (baixa): resposta não é
  respondida (§5), `id` não escalar dá `-32600` com `id: null` (§4). Teste
  `responses_are_not_answered_and_ids_are_scalars`.

Conferido e correto (sem mudança): ping do servidor WebSocket não é necessário (o keepalive TCP
acha o par morto); depois do login não há limite de ociosidade de propósito (MCP e GUI ficam
horas parados, o token local não expira, e o MCP `Remote` não reconecta).

Ficou para depois:

| G0.11 | Canal local por socket Unix com credencial do processo | control, daemon, cli, mcp, gui | No loopback TCP todos os usuários do sistema dividem a origem `127.0.0.1`, então um usuário local sem privilégio ainda ocupa as 8 vagas sem login (30 s cada, renovando) e atrasa a CLI/MCP/GUI locais. Servir também um socket Unix (`$COREROUTER_RUNTIME_DIR/control-<porta>.sock`, 0600) com `SO_PEERCRED` (usuário do processo como principal, sem arquivo de token) e limitar vagas sem login por UID; CLI/MCP/GUI preferem o socket; teste em namespace com dois UIDs | 6 h | aberto |
| G0.12 | Força bruta distribuída contra um nome de usuário | control | Hoje um nome de usuário atacado de muitas origens só ganha atraso (até 8 s por tentativa), nunca bloqueio (bloquear de vez deixaria qualquer um trancar o `admin`). Bloqueio curto e crescente por usuário após K falhas de M origens distintas, sem valer para loopback nem para o token local; contador em `user.active.list`/log; testes | 3 h | aberto |

## perf

### Auditoria do canal de controle (2026-10-22, **medido**)

`cargo bench -p corerouter-control --bench control`, release, AMD Ryzen AI MAX+ 395 (32 CPUs),
`--save-baseline antes` na `origin/main` (19b550e) e `--baseline antes` na branch
`stream/audit-control` (envelope com `RawValue`, `Sock` com prazo/ociosidade, keepalive):

| Benchmark | antes | depois | variação |
|---|---|---|---|
| `control/tcp/ping` | 8,20 µs | 8,13 µs | −1,8 % |
| `control/tcp/interface.list` | 54,9 µs | 55,2 µs | sem mudança (p = 0,25) |
| `control/tls/ping` | 9,20 µs | 9,07 µs | −1,4 % |
| `control/tls/interface.list` | 55,3 µs | 51,0 µs | −7,9 % |

Sem regressão: o `setsockopt` do timeout de leitura só roda quando o valor muda (depois do login
não muda mais), e o `ping` não confere token.
