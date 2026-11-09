# NTP: cliente, relógio do sistema e servidor

`/system ntp client` (G4.6, G4.6b). Comandos: `system.ntp.client.set`, `.get` e `.confirm-step`.
Janela: System › NTP Client.

`/system ntp server` (G4.6c). Comandos: `system.ntp.server.set` e `.get`. Janela: System › NTP
Server. Veja "Servidor NTP", abaixo.

## Como o relógio é acertado (G4.6b)

Cada rodada pergunta a todos os servidores e fica com a resposta de menor ida e volta. A diferença
medida passa pela disciplina (`crates/proto-ntp/src/discipline.rs`, pura), que segue a RFC 5905
§11.3, Figura 28, sem arquivo de frequência:

| Diferença | Relógio nunca acertado | Em sincronia | Pico em observação |
|---|---|---|---|
| < 128 ms | slew | slew | slew, volta a sincronia |
| 128 ms a 1000 s | salto | fica em observação (`holding-spike`) | após 900 s, salto |
| ≥ 1000 s | pede confirmação | pede confirmação | pede confirmação |

- **Pede confirmação:** `clock: awaiting-confirmation` e `pending_step_ms`. O operador roda
  `system.ntp.client.confirm-step` (ou o botão da janela); a rodada seguinte mede de novo e só salta
  se a nova medida estiver a até 60 s do que ele viu.
- **Relógio antes de 2026-01-01:** está errado com certeza (roteador sem bateria depois do boot):
  o limite de 1000 s não vale. É o único caso sem confirmação.
- **Nunca para trás de 2026-01-01:** recusado sempre, mesmo confirmado (`clock: refused`, RFC 8633
  §5.2).
- **Só o backend linux com `CAP_SYS_TIME`.** O laboratório virtual nunca toca no relógio. Sem a
  capacidade, o cliente continua medindo e `clock_error` diz o motivo.
- **`set_system_clock=no`:** só mede. Use num computador comum onde chrony ou timesyncd já cuidam
  do relógio, porque dois donos brigam. No sistema do CoreRouter não há outro dono.

### Slew por frequência

O kernel recebe só `ADJ_FREQUENCY`: o relógio anda mais rápido ou mais devagar por um tempo limitado
(até 300 ppm, por no mínimo 16 s) e volta. A mesma medida ensina o desvio do cristal (até ±200 ppm),
aplicado de forma permanente em `freq_drift_ppm`. A soma fica dentro dos ±500 ppm do kernel.

O PLL do kernel (`ADJ_OFFSET` com `STA_PLL`, como no timesyncd) não foi usado: `std`, `nix` e `rustix`
não têm `adjtimex`, o `clock-steering` não expõe `ADJ_OFFSET`, e escrever a chamada exigiria `unsafe`,
proibido fora do `dataplane-ebpf`. O `clock-steering` 0.2.1 é o crate do ntpd-rs e do statime, e o
ntpd-rs também dirige o relógio por frequência.

Limites conhecidos:

- o desvio aprendido volta a zero quando o serviço reinicia (sem arquivo de frequência);
- se o processo morrer no meio de um slew, a frequência fica como estava até a primeira correção
  depois de reiniciar;
- é um cliente SNTP: não há seleção de falsos relógios entre servidores (gap G4.6i);
- o aviso de segundo bissexto não vai para o kernel: depois do bissexto, a diferença de 1 s passa
  pelo pico de 900 s e vira salto (gap G4.6j).

## Servidores e VRF

- `servers`: até 8. Com um cliente DHCP com `use_peer_ntp`, a lista pode ficar vazia.
- `dynamic_servers`: os recebidos por DHCP (opção 42), depois dos configurados, sem repetir e com
  o total limitado a 8, porque a resposta DHCP é entrada hostil. Mudar a lista nunca faz perguntar
  mais de uma vez a cada 64 s (RFC 4330 §5).
- `vrf`: o socket fica preso ao VRF por `SO_BINDTODEVICE`. Nomes DNS são resolvidos pelo resolvedor
  do roteador, na tabela principal.
- Porta: uma nova por troca, escolhida pelo kernel, com `connect` (RFC 9109 §4).

## Servidor NTP (G4.6c)

Desligado por padrão. Responde só o cabeçalho de 48 bytes (modo 4, RFC 5905 §14, Figura 31), então a
resposta nunca é maior que a pergunta: não há amplificação.

**Quem pode perguntar (`allowed`):** cada item é um prefixo, um intervalo ou o nome de uma
**address-list** do firewall, com as entradas fixas e as dinâmicas (as de `timeout`, de regra ou de
`on_up` do PPP). O padrão é o do VyOS: loopback, link-local e redes privadas. Assim, um endereço
público da WAN só responde se o operador pedir. Quem está fora não recebe nada.

- Lista sem entradas ou que não existe: não libera ninguém e aparece em `empty_lists`. A falha fica
  do lado seguro, e uma entrada pode chegar depois, como numa regra de firewall.
- Entrada nova numa lista vale em até 2 s.
- O teste por pacote é uma busca binária em `SourceSet` (`crates/model/src/source_set.rs`), sem lock,
  reutilizável por outros serviços (gap G4.6k).

**De quem é a hora (`serving`):**

| Situação do cliente | `serving` | O que responde |
|---|---|---|
| Sincronizado, relógio corrigido | `upstream` | stratum do servidor + 1 |
| Só medindo (`clock: not-set`), diferença < 128 ms | `upstream` | idem, com a diferença somada à dispersão |
| Perdeu os servidores, pico em observação | `upstream` | segue enquanto a distância à raiz < 1 s (dispersão cresce 15 ppm: ~18 h) |
| Pede confirmação, resposta recusada, ou só medindo com diferença ≥ 128 ms | `no` (ou `local-clock`) | a hora está em dúvida |
| Nunca sincronizou, sem `use_local_clock` | `no` | silêncio |
| Sem hora boa, com `use_local_clock` | `local-clock` | `local_clock_stratum` (padrão 5), referência `LOCL` |

Com `use_local_clock`, o cliente mostra `using-local-clock` quando não tem resposta boa.

**O que nunca recebe resposta, em silêncio:** modos diferentes de 3 (6 e 7 inclusive, RFC 9327 §6),
versão fora de 1..=4, carimbo de transmissão zero, porta de origem 0, origem multicast, broadcast
ou um dos `broadcast_addresses`, tamanho que não fecha em palavras de 4 bytes (RFC 7822 §3).
Extensões são ignoradas e nunca copiadas (RFC 7822 §4). Enquanto não há hora boa o servidor fica
mudo, em vez de responder com LI 3 e stratum 16: a gap pede "só depois de sincronizado".

**Limite por origem (`rate_limit`, ligado):** média de uma pergunta a cada 2 s, com folga de 16 (cabe
o `iburst` de 8 pacotes e 32 clientes a 64 s atrás de um endereço). IPv6 conta por /64. Acima disso, um
Kiss-o'-Death RATE (RFC 5905 §7.4; LI 3, stratum 0, Origin do cliente), no máximo um a cada 10 s por
origem, e depois silêncio. A tabela é fixa (16 384 entradas de 24 bytes, ~393 KB, por leitor) e com
chave aleatória; numa colisão a origem nova toma a vaga, então um flood de origens forjadas só faz a
tabela esquecer e nunca nega quem não fez nada. O relógio do limite é monotônico: um salto no relógio
de parede não limita nem perdoa ninguém.

**Precisão:** o instante de chegada é o do kernel (`SO_TIMESTAMPNS`), sem o tempo de fila, e a
resposta sai do mesmo endereço que recebeu a pergunta (`IP_PKTINFO`), senão um cliente com `connect`
a descarta.

**Broadcast (`broadcast`):** modo 5 a cada 64 s para `broadcast_addresses`, só com hora boa, da porta
123 (RFC 9109 §4). Nada autentica: só em rede de confiança (RFC 8633 §5.5). Fora deste trabalho, como
gaps: `multicast`, `manycast`, `auth-key` e NTS.

### Próprio × ntpd-rs: números

**Medido** na VM `corerouter-lab` (8 vCPU, build release, 2026-11-09), carga por loopback com
`crates/proto-ntp/examples/ntp_load.rs` (4 threads, janela 16 por thread). Os dois sem limite de
taxa, que é o padrão do ntpd-rs:

| Servidor | Respostas/s | p50 | p99 | CPU | Memória |
|---|---|---|---|---|---|
| CoreRouter, 1 leitor | 406 870 | 158 µs | 253 µs | 102 % | dentro do daemon; ligar o servidor com 1 leitor por família somou 3,9 MB |
| CoreRouter, 2 leitores | 841 030 | 61 µs | 190 µs | 197 % | |
| CoreRouter, 4 leitores | 1 442 325 | 25 µs | 112 µs | 366 % | |
| ntpd-rs 1.9.0 (duas rodadas) | 79 278 e 120 077 | 729 e 500 µs | 1995 e 2553 µs | 124 e 141 % | processo à parte, 6 MB, 10 threads |

Por pacote, sem o socket (criterion, host, build release): montar a resposta 31 ns, limite de taxa
13 ns, checar a origem contra 60 000 entradas 40 ns. O resto do custo é o sistema, `recvmsg` e
`sendmsg`. A vazão com o limite ligado não foi medida de ponta a ponta; o limite soma 13 ns a um
pacote de ~2,4 µs. Ler uma address-list de 60 000 entradas custa 0,56 ms sob o lock do `Session`, a
cada 2 s e só quando `allowed` cita uma lista; ordenar custa 0,40 ms fora do lock.

Decisão em `docs/architecture.md`. O padrão é **1 leitor** por família: uma LAN de 10 000 clientes a
64 s são 156 perguntas/s, contra 400 000 de capacidade (**estimado** a partir do medido). Mais
leitores só gastariam mais núcleos num flood. `--ntp-server-readers` existe para quem precisar.

## Como testar

```sh
cargo test -p corerouter-proto-ntp
COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
    cargo test -p corerouter-hal-linux --test netns_clock
COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
    cargo test -p corerouter-daemon --test netns_ntp
COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
    cargo test -p corerouter-daemon --test netns_ntp_server
cargo xtask vm-lab run -- scripts/routeros-interop-l2.sh ntp
cargo xtask vm-lab run -- 'systemctl stop systemd-timesyncd chrony; COREROUTER_CLOCK_ROOT=1 cargo test -p corerouter-hal-linux --test clock_root -- --test-threads=1 --nocapture; COREROUTER_CLOCK_ROOT=1 cargo test -p corerouter-daemon --test ntp_clock_root -- --nocapture; systemctl start systemd-timesyncd'
```

Em namespace o relógio fica fora de alcance: o kernel confere `capable(CAP_SYS_TIME)` contra o
namespace de usuário inicial (`timekeeping_validate_timex`, kernel 6.18), então tudo dá `EPERM`. O
namespace de tempo não ajuda, porque desloca só `CLOCK_MONOTONIC` e `CLOCK_BOOTTIME`. Por isso a
mudança real é testada na VM do laboratório.
