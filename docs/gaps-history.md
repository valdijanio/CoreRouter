# CoreRouter — histórico da lista de gaps

Só de acrescentar (`merge=union` no `.gitattributes`): cada PR que adiciona, muda o status ou
redefine um item de `docs/gaps.md` acrescenta **uma linha no fim**, sem editar linhas antigas.

- 2026-10-21 — lista inicial.
- 2026-10-21 — G0.2 feito: `.github/workflows/ci.yml` (ainda não rodou no GitHub; sem push).
- 2026-10-21 — G1.1 feito (VLAN, bridge, loopback, `interface.remove`); bonding separado em G1.8.
- 2026-10-21 — G0.6 feito (persistência: `running.json` + `.prev`, escrita atômica, quarentena).
- 2026-10-21 — G1.2 feito (rtnetlink: plano puro + executor com rollback, testes em netns); notas novas em G1.3 e G1.7.
- 2026-10-21 — G1.9 (tabelas estilo WinBox) adicionado e feito.
- 2026-10-21 — G0.4 feito (GUI cliente do daemon, nativo e web; WebSocket com Origin; `--web-root`).
- 2026-10-21 — G5 adicionado: descoberta de vizinhos (CRDP), LLDP + MNDP passivo e gerência em malha.
- 2026-10-21 — G1.10 (comentários inline) e G1.11 (tema claro/escuro) adicionados e feitos.
- 2026-10-21 — G5.2 Parte 1 feita (proto-lldp, proto-mndp só decodificação, LLDP/MNDP no `hal-linux`); integração com a tabela do G5.1 pendente.
- 2026-10-21 — G1.12 (maximizar/restaurar janelas internas) adicionado e feito.
- 2026-10-21 — G1.5 feito (rotas estáticas IPv4/IPv6, VRF básico, janela Routes).
- 2026-10-21 — G1.13 (VRF pela GUI) adicionado e feito.
- 2026-10-22 — G1.14 (kernel sem VRF: `Hal::features`, `ip.vrf.add` desabilitado com o motivo, CI carrega o módulo `vrf`) adicionado e feito; nota de `CONFIG_NET_VRF=y` em G1.6.
- 2026-10-22 — G1.4 feito (Safe Mode: comandos `config.safe-mode.*`, dono por conexão, timeout, sem salvar até confirmar).
- 2026-10-22 — G5.1 feito (CRDP, tabela de vizinhos, tela de conexão); G5.2 Parte 2 pode usar `Session::record_neighbor`.
- 2026-10-22 — G1.15 (teclado nos diálogos e janelas internas) adicionado e feito.
- 2026-10-22 — G1.16 (ações indisponíveis cinza com o motivo: comando ausente num daemon antigo, desabilitado pelo engine ou link fora) adicionado e feito.
- 2026-10-22 — G5.2 feito (Parte 2: LLDP/MNDP ligados à tabela de vizinhos no daemon).
- 2026-10-22 — G5.4 (CRDP do lab virtual pelo loopback, `ether1` ligada por padrão no lab) adicionado e feito.
- 2026-10-22 — G1.17 (cores dos comentários: azul no ativo, cinza no desativado, inline e coluna) adicionado e feito.
- 2026-10-22 — G5.5 (despedida da descoberta no encerramento do daemon por SIGINT/SIGTERM) adicionado e feito.
- 2026-10-22 — G1.18 (descoberta via netlink e posse dos links no `hal-linux`) adicionado e feito; G1.7 feito junto; nota nova em G1.3.
- 2026-10-22 — G0.8 feito (terminal RouterOS na GUI e na CLI, export/import); SSH pendente do G0.3.
- 2026-10-22 — G0.3 feito (autenticação, usuários/grupos e TLS no canal de controle e no WebSocket).
- 2026-10-22 — G6 adicionado (ferramentas de diagnóstico); G6.1 (tarefas) e G6.2 (ping, vários destinos, MTU) feitos; G6.3 (MTR) e G6.4 abertos.
- 2026-10-22 — G2.1 dividido em G2.1a/b/c; G2.1a (firewall base) feito.
- 2026-10-22 — G6.3 (MTR) feito.
- 2026-10-22 — G6.5 (ferramentas no terminal como no RouterOS) adicionado e feito.
- 2026-10-22 — G0.3b (primeiro acesso sem senha, estilo RouterOS 7) adicionado e feito.
- 2026-10-22 — G0.3c (tela de conexão: `admin` por padrão, token→senha em loopback, roteador antigo) adicionado e feito.
- 2026-10-22 — G1.19 (abas do diálogo de interface, só leitura) adicionado e feito; G1.20 (Ethernet configurável, SFP/DOM, teste de cabo) adicionado.
- 2026-10-22 — G4.7 (cliente DHCP: a DHCPv4, b DHCPv6+PD+RA, c resiliência) adicionado; G4.7a em andamento.
- 2026-10-22 — G4.7a feito (cliente DHCPv4 estilo RouterOS com opções recebidas, rotas 121 com VRF, servidores permitidos e histórico).
- 2026-10-22 — G0.9 (infraestrutura de benchmarks) adicionado; AGENTS.md ganha RFC original na pesquisa e a regra de desempenho (Rust puro × externo com dados).
- 2026-10-22 — G1.20 feito.
