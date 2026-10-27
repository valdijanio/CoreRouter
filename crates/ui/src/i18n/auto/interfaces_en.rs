//! Interfaces list explanations.
pub(super) const HELP: &[(&str, &str)] = &[
    ("interfaces.columns", "Choose which columns appear on this device. Name remains visible. Restore defaults returns the original selection. Inline comments remain independent of the Comment column."),
    ("interfaces.info", "Relationships and diagnostic information known for this interface."),
    ("interfaces.link", "Operational link state. A disabled or disconnected interface is not necessarily a fault."),
    ("interfaces.mtu", "Maximum IP packet size in bytes for this interface."),
    ("interfaces.name", "The interface name, used by commands and configuration."),
    ("interfaces.rx", "Total bytes received since the counters were last reset."),
    ("interfaces.rx_pkt", "Total packets received since the counters were last reset."),
    ("interfaces.traffic", "Recent received and transmitted traffic. Missing history is shown as empty."),
    ("interfaces.tx", "Total bytes transmitted since the counters were last reset."),
    ("interfaces.tx_pkt", "Total packets transmitted since the counters were last reset."),
    ("interfaces.type", "The interface type reported by the platform; the icon identifies the configured kind."),
];
