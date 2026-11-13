id: fix-ospf-lab-glob

`scripts/ospf-stress-lab.sh`: o teardown removia os interface templates da área do laboratório com
`for id in $(…)` sem aspas, e os ids do roteador (`*E`) viravam coringa de arquivo: na fase C contra
o notebook (2026-11-13), `*E` virou `LICENSE` (a pasta do código na VM), a remoção falhou calada, o
template ficou, a área e a instância `stress` não saíram e o roteiro parou ao começar o degrau de
10 000 LSAs. Agora os ids são lidos linha a linha (`while read -r`). Conferido contra o notebook pela
fase C (`--dut remote`), com o teardown removendo template, área e instância entre os degraus.
