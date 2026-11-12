# OSPF sob carga (G3.4m)

Laboratório de carga e estabilidade do OSPF do CoreRouter: o `ospfd` e o `zebra` do FRR 10.7.1
da imagem, comandados pelo `corerouter-daemon`, sob LSDB grande, churn de LSAs, muitos vizinhos
e operação com carga. O roteiro é `scripts/ospf-stress-lab.sh`; este documento traz os números
(**medidos**), os limites achados e os defeitos.

## Como rodar

```sh
# no host: copia a raiz da imagem para a VM e roda a bateria lá (root só dentro da VM)
scripts/ospf-stress-lab.sh --host /srv/build/os-out/<id>/build/images
# só alguns testes, ou outros degraus
scripts/ospf-stress-lab.sh --host <images> --tests lsdb,ops --steps 10000,100000
# fase C: o roteador é outra máquina, ligada por um cabo à placa <if> da VM
cargo xtask vm-lab run -- scripts/ospf-stress-lab.sh --dut remote --iface <if> \
  --target <endereço> --mgmt <cidr do lado da VM> [--dut-iface ether1] [--user admin]
```

PLACEHOLDER
