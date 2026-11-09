# NTP: cliente e relógio do sistema

`/system ntp client` (G4.6, G4.6b). Comandos: `system.ntp.client.set`, `.get` e `.confirm-step`.
Janela: System › NTP Client.

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

## Como testar

```sh
cargo test -p corerouter-proto-ntp
COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
    cargo test -p corerouter-hal-linux --test netns_clock
COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
    cargo test -p corerouter-daemon --test netns_ntp
cargo xtask vm-lab run -- 'systemctl stop systemd-timesyncd chrony; COREROUTER_CLOCK_ROOT=1 cargo test -p corerouter-hal-linux --test clock_root -- --test-threads=1 --nocapture; COREROUTER_CLOCK_ROOT=1 cargo test -p corerouter-daemon --test ntp_clock_root -- --nocapture; systemctl start systemd-timesyncd'
```

Em namespace o relógio fica fora de alcance: o kernel confere `capable(CAP_SYS_TIME)` contra o
namespace de usuário inicial (`timekeeping_validate_timex`, kernel 6.18), então tudo dá `EPERM`. O
namespace de tempo não ajuda, porque desloca só `CLOCK_MONOTONIC` e `CLOCK_BOOTTIME`. Por isso a
mudança real é testada na VM do laboratório.
