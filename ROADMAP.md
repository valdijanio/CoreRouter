# CoreRouter — roadmap

Fonte de verdade das tarefas: `docs/gaps.md` (ids G*). Este arquivo resume fases e registra o log.

| Fase | Escopo | Gaps | Saída esperada |
|---|---|---|---|
| 0 | Motor arquitetural | — | Registro de comandos, camadas, MCP, GUI, xtask ci (**feito**, v0.1.0) |
| 1 | Core / Interfaces | G1.*, G0.2, G0.6 | Roteador L3 básico em kernel real com persistência e Safe Mode |
| 2 | Firewall / CGNAT | G2.* | nftables + CGNAT PBA; XDP para alta capacidade |
| 3 | OSPF / BGP / MPLS | G3.* | FRR orquestrado; simulador de protocolos no lab |
| 4 | Serviços e telemetria | G4.* | DNS, DHCP, PPPoE, métricas, gráficos |

Restante até uma beta de Fase 1: ~70 h de agente (**estimado**, soma de G0.2, G0.6, G1.1–G1.5).

## Log e histórico

O log do projeto (o que entrou, quando, e os números medidos) fica em `docs/log.md`; o histórico
das mudanças na lista de gaps fica em `docs/gaps-history.md`. Os dois são **só de acrescentar** e
estão marcados com `merge=union` no `.gitattributes`: o git junta as linhas de PRs paralelos
sozinho, sem conflito.
