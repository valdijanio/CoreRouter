//! Seção USB da aba Hardware da interface (G1.29b): explicações em português.
pub(super) const HELP: &[(&str, &str)] = &[
    ("iface_usb.adapter", "O USB mais rápido que o adaptador suporta: a capacidade SuperSpeed do descritor BOS dele ou, sem ela, o `bcdUSB`. Um adaptador USB 3 numa porta USB 2 informa 2.10, então só a versão engana."),
    ("iface_usb.id", "Ids USB do fabricante e do produto (`idVendor:idProduct`) e a revisão do chip (`bcdDevice`). 0bda:8153 rev 3100 é um Realtek RTL8153B."),
    ("iface_usb.over_current", "Vezes que a porta cortou ou limitou a energia porque o dispositivo puxou corrente demais. Acima de zero: cabo ruim, porta fraca ou um dispositivo que precisa de hub com fonte."),
    ("iface_usb.port", "Onde o adaptador está: barramento-porta (`4-2`: barramento 4, porta 2; `4-1.3`: porta 3 do hub ligado na porta 1) e se a porta em si é USB 3 ou USB 2."),
    ("iface_usb.power", "Corrente que o dispositivo pede à porta (`bMaxPower`). A porta USB 2 fornece 500 mA, a USB 3, 900 mA."),
    ("iface_usb.power_saving", "O autosuspend deixa o núcleo USB pôr o dispositivo parado para dormir; o LPM (U1/U2) deixa o enlace USB 3 cochilar entre os pacotes. Os dois são causas conhecidas de travamento em adaptadores de rede USB: num roteador ficam desligados."),
    ("iface_usb.section", "## Adaptadores USB em produção\n\nUm adaptador Ethernet USB funciona, mas não é uma placa PCIe:\n\n- **uma fila só, sem RSS:** um núcleo faz todo o trabalho dele;\n- **latência e jitter** maiores que os de uma placa PCIe (o USB move os dados em quadros de 125 µs);\n- **travamentos conhecidos:** Tx timeout, economia de energia (LPM, autosuspend), cabo que se solta;\n- **a porta limita:** um adaptador gigabit numa porta USB 2.0 passa ~300 Mbit/s.\n\nPara WAN e gerência, prefira uma placa PCIe. A aba Hardware mostra a velocidade USB negociada e os Tx timeouts do kernel."),
    ("iface_usb.speed", "A velocidade USB que o adaptador negociou com a porta: 480 Mbps é USB 2.0, 5 Gbps é USB 3.0, 10 Gbps é USB 3.1. Fica **âmbar** quando a porta é mais lenta que o adaptador: o tráfego fica limitado sem erro nenhum. Use uma porta USB 3 (azul ou marcada SS), direto, com cabo USB 3."),
    ("iface_usb.tx_timeouts", "Vezes que o vigia do kernel (NETDEV WATCHDOG) viu a fila de transmissão do adaptador parada. A cada uma, o driver reinicia o adaptador (o tráfego para um instante). Se cresce, o adaptador está travando."),
    ("iface_usb.version", "A versão USB que o dispositivo informa no descritor (`bcdUSB`)."),
];
