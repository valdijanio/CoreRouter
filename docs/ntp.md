# NTP: cliente, relógio do sistema e servidor

`/system ntp client` (G4.6, G4.6b). Comandos: `system.ntp.client.set`, `.get` e `.confirm-step`.
Janela: System › NTP Client.

`/system clock` (G4.6p). Comando: `system.clock.print`. Janela: System › Clock, e a linha
"Clock" no alto da NTP Client. Veja "A hora do roteador", abaixo.

`/system ntp server` (G4.6c). Comandos: `system.ntp.server.set` e `.get`. Janela: System › NTP
Server. Veja "Servidor NTP", abaixo.

## Primeiro boot: ligado, só com os servidores do DHCP (G1.6zh)

Um roteador cuja config nunca foi gravada (o primeiro boot do disco instalado, e todo boot da ISO
live) nasce com o cliente NTP **ligado e sem servidor configurado**. Ele pergunta só aos
servidores que os clientes DHCP aprendem (`use_peer_ntp`, ligado por padrão; opção 42, RFC 2132
§8.3, e no DHCPv6 a opção 56, RFC 5908) e a mais ninguém: nenhum pool público vem embutido, o roteador não fala com terceiros que o
operador não indicou (RFC 8633 §6.2, RFC 4085; o NTP Pool proíbe `pool.ntp.org` como padrão de
appliance).

- **Quem liga:** o serviço `ntp-client` do daemon, na partida, roda `system.ntp.client.set
  enabled=yes` quando há `--config-dir`, nada foi restaurado (`loaded_from` vazio) e a config do
  cliente ainda é a padrão. Fica no journal e no log ("NTP Client ligado: servidores do DHCP
  (opção 42)"). O `Default` do modelo continua desligado.
- **Config já gravada não muda:** um arquivo sem a chave `ntp_client` (gravado antes disto, ou
  por quem nunca mexeu no NTP) continua significando desligado. Quem desligar depois do primeiro
  boot fica desligado.
- **Sem a quem perguntar:** `status: waiting`, `last_error: "no server to ask"`. Não é erro: é
  linha `info` no log, e a verificação de saúde `ntp` fica em aviso, "relógio não ajustado: o
  cliente NTP não tem a quem perguntar", com a ação (`system.ntp.client.set servers=…`, ou um
  cliente DHCP numa rede que entregue a opção 42). `system.ntp.client.set enabled=yes` sem
  servidor e sem cliente DHCP é aceito e responde com `warning` (antes era recusado; o estado já
  existia ao remover o último cliente DHCP).
- **O lease chega, o servidor é perguntado na hora:** a rodada que não tinha a quem perguntar não
  enviou nada, então não conta para o intervalo mínimo de 64 s (RFC 4330 §5). Medido em
  namespace: sincronizado 3 s depois do daemon subir.
- **ISO live:** `system.ntp.client.*` entrou na lista do que o live pode mudar
  (`crates/engine/src/live.rs`); antes o cliente não podia nem ser ligado ali.
- **Saúde (`ntp`):** além de "sem a quem perguntar": sem resposta dos servidores; acerto acima de
  1000 s esperando confirmação (diz quanto e como confirmar); resposta recusada; medindo mas sem
  corrigir e mais de 1 s fora; e cliente desligado com a data do roteador anterior a 2026 (placa
  sem bateria no relógio).

### De onde vem a hora antes do NTP

- **x86, com ou sem `CONFIG_RTC_HCTOSYS`:** o kernel põe a hora do CMOS no relógio do sistema já
  em `timekeeping_init` (`kernel/time/timekeeping.c` → `read_persistent_clock64`,
  `arch/x86/kernel/rtc.c` → `mach_get_cmos_time`; kernel 6.18.59). A imagem tem
  `RTC_HCTOSYS` desligado e não precisa dele: ele só repetiria a leitura quando o `rtc0`
  registra. O CMOS é lido como UTC.
- **Sem bateria no RTC:** o relógio começa em 1970 (ou na data de fábrica da placa). Abaixo de
  2026-01-01 o cliente acerta sem pedir confirmação (tabela abaixo).
- **Instalado: sincronizado, o kernel regrava o CMOS em UTC a cada ~11 min** (`sync_hw_clock`,
  `kernel/time/ntp.c`; o cliente limpa `STA_UNSYNC`). É o que se quer num disco instalado: o
  próximo boot já nasce certo.
- **ISO live: o relógio da placa fica como está (G4.6o).** O live acerta o relógio do sistema
  (salto e slew, como sempre) mas deixa `STA_UNSYNC` ligado, e o kernel 6.18 só grava o RTC com
  ele desligado (`sync_hw_clock`, linha 643, e `ntp_notify_cmos_timer`, linha 683, de
  `kernel/time/ntp.c`, pelos dois caminhos: `update_persistent_clock64` e `update_rtc`). Motivo:
  quem bootou a ISO para testar uma máquina que também tem Windows (RTC em hora local) voltaria ao
  Windows com a hora deslocada pelo fuso. O log diz uma vez "imagem live: o relógio da placa
  (RTC) fica como está". Efeito colateral: o `adjtimex` do live diz "não sincronizado"
  (`TIME_ERROR`); nada no sistema lê isso, e o servidor NTP do roteador segue o estado do cliente.
- **`clock: "not-set"` não quer dizer "relógio sem hora":** quer dizer que o cliente NTP não está
  mexendo no relógio (desligado, só medindo, ou ainda sem resposta). Com o cliente desligado o
  status inteiro vem zerado, inclusive `dynamic_servers`.

## A hora do roteador: `/system clock` (G4.6p)

`system.clock.print` mostra a hora e a data do roteador e de onde vieram. Antes não havia como ver
a hora: `system.ntp.client.get` mostra o que o cliente NTP faz, e `clock: not-set` era lido como
"relógio sem hora".

| Campo | O que é |
|---|---|
| `time`, `date` | `HH:MM:SS` e `AAAA-MM-DD`, em UTC (o formato do RouterOS 7) |
| `time_zone_name`, `gmt_offset`, `dst_active` | por enquanto sempre `UTC`, `+00:00`, `false`: não há fuso configurável (gap G4.6q) |
| `source` | `ntp` (o cliente NTP acertou o relógio nesta execução; vale mesmo depois de desligado), `rtc` (a hora do boot, lida do relógio da placa), `host` (laboratório virtual: o relógio do computador), `not-set` (antes de 2026), `unknown` |
| `ntp_server`, `last_sync` | com `source: ntp`, de quem e quando |
| `hardware_clock` | o relógio da placa (RTC), lido de `/sys/class/rtc/rtc0/since_epoch`: data, hora, `offset_secs` (RTC − sistema) e `written` |
| `hardware_clock.written` | `follows-system` (instalado e sincronizado: o kernel regrava a cada ~11 min), `left-alone` (ISO live, G4.6o), `not-written`, `none` (sem RTC) |
| `hardware_clock.local_time_offset`, `drift_secs` | quando a diferença fica a até 12 min de um fuso inteiro (meia hora, UTC−12 a UTC+14): o RTC parece estar em hora local, como o Windows o guarda, e `drift_secs` é o que sobra |

O caso que motivou: o notebook da auditoria tinha o RTC 2 h 50 min atrás (hora de Brasília, −3 h,
e 10 min de deriva). O computador de desenvolvimento, também com Windows, mostrou
`offset_secs: -10504`, `local_time_offset: "−03:00"`, `drift_secs: 296` (**medido**, backend
linux num namespace, 2026-11-12).

Como os outros fazem: o RouterOS 7 mostra `time`, `date`, `time-zone-name`, `gmt-offset` e
`dst-active`, sem a origem. O Cisco `show clock detail` diz "Time source is NTP / hardware
calendar". O Junos `show system uptime` diz "Time Source: NTP CLOCK / LOCAL CLOCK". Daqui saíram
`source` e o RTC ao lado.

Fica para gaps: o fuso (`time-zone-name`, `manual`, DST, G4.6q) e acertar a hora à mão
(`system.clock.set`, G4.6r).

## Como o relógio é acertado (G4.6b)

Cada rodada pergunta a todos os servidores e fica com a resposta de menor ida e volta. A diferença
medida passa pela disciplina (`crates/proto-ntp/src/discipline.rs`, pura), que segue a RFC 5905
§11.3, Figura 28, sem arquivo de frequência:

| Diferença | Relógio nunca acertado | Em sincronia | Pico em observação |
|---|---|---|---|
| < 128 ms | slew | slew | slew, volta a sincronia |
| 128 ms a 1000 s | salto | fica em observação (`holding-spike`) | após 900 s, salto |
| ≥ 1000 s | primeiro acerto do boot: salto (para trás, até 1 dia); depois, pede confirmação | pede confirmação | pede confirmação |

- **Pede confirmação:** `clock: awaiting-confirmation` e `pending_step_ms`. O operador roda
  `system.ntp.client.confirm-step` (ou o botão da janela); a rodada seguinte mede de novo e só salta
  se a nova medida estiver a até 60 s do que ele viu.
- **Primeiro acerto do boot (G4.6m):** a primeira sincronia de cada boot salta sem confirmação,
  para frente qualquer valor e para trás até 1 dia; acima de 1 dia para trás, pede confirmação
  como antes. É o que a RFC 8633 §5.2 permite "na partida" e o que fazem o ntpd `-g`, o chrony
  `makestep`, o systemd-timesyncd, o ntpd-rs e o RouterOS. O caso típico: relógio da placa em
  hora local (máquina com Windows) ou bateria fraca; o notebook da auditoria ficou 2 h 50 min
  atrasado esperando alguém. A primeira sincronia (salto ou slew) gasta a vez, e o limite de
  1000 s volta. A marca é o `boot_id` do kernel em `ntp-boot-step`, na pasta de execução (tmpfs
  na imagem): reiniciar o daemon no mesmo boot não abre a vez de novo. O log diz "primeiro
  acerto deste boot, sem confirmação".
- **Relógio antes de 2026-01-01:** está errado com certeza (roteador sem bateria depois do boot):
  o limite de 1000 s não vale, em qualquer momento.
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

- `servers`: até 8. A lista pode ficar vazia: o cliente usa os que um cliente DHCP com
  `use_peer_ntp` aprender (é assim que um roteador novo nasce, veja "Primeiro boot").
- `dynamic_servers`: os recebidos por DHCP, depois dos configurados, sem repetir e com o total
  limitado a 8, porque a resposta DHCP é entrada hostil. Primeiro os do DHCPv4 (opção 42), depois
  os do DHCPv6 (opção 56, abaixo). Mudar a lista nunca faz perguntar
  mais de uma vez a cada 64 s (RFC 4330 §5); a rodada que não tinha a quem perguntar não conta.
- `vrf`: o socket fica preso ao VRF por `SO_BINDTODEVICE`. Nomes DNS são resolvidos pelo resolvedor
  do roteador, na tabela principal.
- Porta: uma nova por troca, escolhida pelo kernel, com `connect` (RFC 9109 §4).

### Servidores do DHCPv6: opção 56 (G4.6n)

Numa rede só IPv6 o roteador novo aprende o servidor pelo DHCPv6. O cliente DHCPv6
(`ipv6.dhcp-client`) pede a opção 56 (NTP Server, RFC 5908) e a 31 (SNTP, RFC 4075) no Option
Request, e com `use_peer_ntp` (padrão sim, como no DHCPv4; o RouterOS 7.25 não tem a chave no
DHCPv6) entrega ao cliente NTP o que veio. `ipv6.dhcp-client.list` mostra `ntp_servers`; a janela
IPv6 › DHCPv6 Client tem "Use Peer NTP" e a linha "NTP Servers" no Status.

| Subopção (RFC 5908) | O que o cliente NTP faz |
|---|---|
| 1, endereço do servidor (§4.1) | pergunta; precisa ser unicast (multicast, `::` e `::1` são descartados) |
| 2, grupo multicast (§4.2) | mostra em `ntp_servers`, não usa: o cliente não ouve multicast (G4.6l) |
| 3, FQDN (§4.3) | resolve pelo DNS do roteador, como um nome configurado; um nome só, sem IDN |
| link-local (`fe80::`) | mostra, não usa: o cliente pergunta só por endereço, e o link-local precisa da interface ao lado |

- **Uma subopção por opção, ou várias:** a §4 manda uma só ("one, and only one") e a opção se
  repete; o dnsmasq manda todas numa opção, e o systemd-networkd e o odhcp6c leem assim. Lemos as
  duas formas. Subopção quebrada ou desconhecida é pulada; uma opção quebrada nunca derruba a
  concessão.
- **A 31 só sozinha:** a RFC 5908 §7 deprecia a opção SNTP. Os endereços dela valem só quando
  não veio nenhuma opção 56, como no systemd-networkd.
- **Limite:** no máximo 8 por mensagem e 8 servidores ao todo no cliente NTP.
- **Segurança (RFC 5908 §6):** o servidor que o DHCPv6 indica não é autenticado, igual ao da
  opção 42. Depois do primeiro acerto do boot (G4.6m), o limite de 1000 s e o piso de 2026 seguem
  valendo.
- **Laboratório:** o servidor DHCPv6 simulado entrega `2001:db8:0:N::1` na opção 56.

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
COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
    cargo test -p corerouter-daemon --test netns_ntp_first_boot   # G1.6zh: DHCP entrega o NTP
cargo xtask vm-lab run -- scripts/routeros-interop-l2.sh ntp
# clock_root confere também o RTC (G4.6o): LeaveAlone não grava, Follow grava
cargo xtask vm-lab run -- 'systemctl stop systemd-timesyncd chrony; COREROUTER_CLOCK_ROOT=1 cargo test -p corerouter-hal-linux --test clock_root -- --test-threads=1 --nocapture; COREROUTER_CLOCK_ROOT=1 cargo test -p corerouter-daemon --test ntp_clock_root -- --nocapture; systemctl start systemd-timesyncd'
```

Em namespace o relógio fica fora de alcance: o kernel confere `capable(CAP_SYS_TIME)` contra o
namespace de usuário inicial (`timekeeping_validate_timex`, kernel 6.18), então tudo dá `EPERM`. O
namespace de tempo não ajuda, porque desloca só `CLOCK_MONOTONIC` e `CLOCK_BOOTTIME`. Por isso a
mudança real é testada na VM do laboratório.
