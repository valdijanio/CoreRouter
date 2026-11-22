## O que muda

<!-- Id da gap (docs/gaps.md) e um resumo do que entra. -->

## Pesquisa

<!-- Obrigatória em feature nova (AGENTS.md, "Pesquisa antes de implementar").
     Em correção pequena, escreva "não se aplica". -->

- **MikroTik RouterOS v7** (help.mikrotik.com, links): como funciona, nomes e padrões.
- **RFCs consultadas** (quando fala protocolo; base + "Updated by" + errata, com seções):
- **Outros** (pelo menos dois: VyOS, Junos, IOS-XE, SR Linux, EOS, OPNsense/pfSense, OpenWrt, FRR, RFCs…): o que fazem melhor.
- **Adotado:**
- **Melhorias propostas** (entram agora / viram gap):
- **Fora do escopo, e por quê:**

## Desempenho

<!-- Se tocar caminho quente (pacotes, aplicar N regras/rotas, canal de controle, codecs):
     antes/depois medido com `cargo xtask bench`, e a linha em docs/perf.md. Senão: "não se aplica". -->

## Como testar

<!-- Comandos ou cliques; o que se espera ver. -->

## Verificação

- [ ] `cargo xtask ci` passa localmente
- [ ] Mudou UI: screenshot conferido (`corerouter-cli --connect … screenshot`)
- [ ] `docs/changes/<id>.md` com o log, o `status:` da gap e o `history:` (formato em `docs/changes/README.md`)
- [ ] PR com o rótulo `fila` e sem auto-merge (a fila contínua integra; não espere o CI do GitHub)
