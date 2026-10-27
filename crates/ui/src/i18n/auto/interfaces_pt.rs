//! Interface list labels and explanations in Portuguese.
pub(super) const LABELS: &[(&str, &str)] = &[
    ("Columns", "Colunas"),
    ("Comment", "Comentário"),
    ("Info", "Informações"),
    ("Link", "Enlace"),
    ("Name", "Nome"),
    ("Restore defaults", "Restaurar padrão"),
    ("Traffic", "Tráfego"),
    ("Type", "Tipo"),
];
pub(super) const HELP: &[(&str, &str)] = &[
    ("interfaces.columns", "Escolha as colunas exibidas neste dispositivo. O nome permanece visível. Restaurar padrão volta à seleção original. Os comentários em faixa são independentes da coluna Comment."),
    ("interfaces.info", "Relações e informações de diagnóstico conhecidas para esta interface."),
    ("interfaces.link", "Estado operacional do enlace. Uma interface desabilitada ou desconectada não é necessariamente uma falha."),
    ("interfaces.mtu", "Tamanho máximo, em bytes, do pacote IP nesta interface."),
    ("interfaces.name", "Nome da interface usado pelos comandos e pela configuração."),
    ("interfaces.rx", "Total de bytes recebidos desde a última reinicialização dos contadores."),
    ("interfaces.rx_pkt", "Total de pacotes recebidos desde a última reinicialização dos contadores."),
    ("interfaces.traffic", "Tráfego recente de recebimento e transmissão. Sem histórico, a célula fica vazia."),
    ("interfaces.tx", "Total de bytes transmitidos desde a última reinicialização dos contadores."),
    ("interfaces.tx_pkt", "Total de pacotes transmitidos desde a última reinicialização dos contadores."),
    ("interfaces.type", "Tipo informado pela plataforma; o ícone identifica o tipo configurado."),
];
