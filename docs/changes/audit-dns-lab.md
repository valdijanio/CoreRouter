id: audit-dns-lab

Auditoria (achado do teste de ponta a ponta, `audit-e2e`): com `--backend virtual` e
`ip.dns.set allow_remote_requests=yes`, o encaminhador DNS escutava em `0.0.0.0`/`[::]` do
**host**, então a rede real da máquina chegava ao resolvedor do lab (as interfaces do lab não são
as do host, e a ACL `allowed_from` compara com as redes do lab, que podem coincidir com a LAN de
verdade). Agora o lab virtual escuta só em `127.0.0.1` e `::1`, como o CRDP do G5.4; no backend
Linux nada muda. Teste: `service::dns_server::tests::the_virtual_lab_answers_only_on_the_loopback`.
Os outros sockets do daemon que usam endereço curinga são clientes de porta efêmera (zonas,
syslog) ou só rótulo de exibição (DHCP, que no lab usa os sockets simulados) — conferidos.

Quem roda o lab num network namespace e quer o encaminhador nas interfaces do namespace (os
testes `netns_dns_*`) passa `--dns-lab-any`; no backend Linux a opção não muda nada.
