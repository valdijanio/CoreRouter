id: fix-main-pppoe-policer

`main` vermelha (issue #202). Dois testes corrigidos:
- `pppoe_policer_accuracy` (G4.3c) media o limite do remetente, não o policer. No runner de 4 vCPUs, o AF_PACKET oferece ~1,5 Gbit/s, abaixo dos 100 × 20 Mbit/s configurados (−26%). Agora cada caso mede antes o que o remetente oferece e limita a taxa a um terço do que cada assinante recebe. A referência passou a ser por assinante: quem o policer cortou tem de receber a taxa com ±5% (tolerância mantida); quem ele não cortou tem de receber exatamente o que ofereceu. Ninguém pode passar do limite, e ao menos 90% dos assinantes têm de ser cortados (para o caso testar o policer).
- `netns_capture` `frames_both_ways_with_their_wire_length`, que é instável: até o linkwatch ver a portadora, o veth recém-ligado fica com a `noop_qdisc`, que descarta os quadros enviados. O teste agora espera o `state UP` dos dois lados, via netlink (`ip -o link`). Passou 5 vezes seguidas.
