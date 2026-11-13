id: fix-ospf-lab-glob

`scripts/ospf-stress-lab.sh`, dois defeitos achados na fase C contra o notebook (2026-11-13):

- **Teardown com coringa:** os interface templates da área do laboratório eram removidos com
  `for id in $(…)` sem aspas, e os ids do roteador (`*E`) viravam coringa de arquivo (`*E` virou
  `LICENSE`, da pasta do código na VM). A remoção falhava calada, o template ficava, a área e a
  instância `stress` não saíam e o roteiro parava ao montar o degrau de 10 000 LSAs. Agora os ids
  são lidos linha a linha (`while read -r`).
- **Faixas do gerador sobre redes reais:** os `/32` dos nós saíam de `192.168.0.0` e as externas
  de `100.64.0.0/28`. No notebook, eles cobriram a rede de casa (`ether1`, 192.168.0.0/24) e a LAN
  de teste (`ether2`, 100.64.0.0/24). Um `/32` vence o `/24` conectado, então o notebook respondia
  à gerência pelo cabo do laboratório e ficou inacessível até o fim do teste. Agora os nós saem de
  `198.19.0.0` e as externas de `10.128.0.0/28` (198.18.0.0/15 é a faixa de benchmarking da
  RFC 2544). No modo remoto, `remote_overlap_check` recusa o teste antes de configurar qualquer
  coisa quando um endereço do roteador cai nessas faixas. Conferido com as faixas antigas: a
  checagem acusa `192.168.0.182/24` e `100.64.0.1/24`.
