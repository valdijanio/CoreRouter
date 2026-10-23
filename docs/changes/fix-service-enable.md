id: fix

System › Services: serviço desligado pela config ganha **Enable** e **Open settings** (relato do
usuário: "quando dou start dá o erro e não mostra startado"). Start num serviço `disabled` não
tem o que iniciar (ele já roda, ocioso, porque a config o desliga), então:

- **Start fica cinza** nesses serviços, com o motivo na dica.
- **Enable** aparece no detalhe quando ligar é só um interruptor da config (dns-server:
  `ip.dns.set allow_remote_requests=yes`; metrics: `ip.service.metrics.set enabled=yes`): um
  clique roda esse comando (journal, transação e Safe Mode como qualquer outro), e o serviço
  passa a `running` em seguida.
- **Open settings** abre a janela que configura o serviço (DNS, Adlist, Zones, DHCP Server,
  NTP, Logging) quando ligar pede valores que só o operador sabe (interface, pool, servidores).
- `system.service.print` ganha `turn_on: {id, params}|null`, o `enable` como comando quando ele
  está completo (sem `…`).

Como testar: System › Services › dns-server (disabled): Start cinza com a dica; Enable → o
serviço vira `running` e o `ip.dns.get` mostra `allow_remote_requests: true`; dhcp-server:
Open settings abre IP › DHCP Server.

Também: o e2e `hostile_lines_never_crash_or_hang_it` espera o daemon soltar as 500 conexões
fechadas de uma vez antes de conectar de novo (falhava com a máquina carregada: "too many
connections that have not logged in").
