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
    ("interfaces.type", "A USB adapter shows the USB icon (amber when its port is slower than the adapter; hover for the speed, port and driver). The interface type reported by the platform; the icon identifies the configured kind."),
    ("interfaces.vlan.interface", "## Interface\nThe interface the VLAN rides on: an ethernet port, a bond, a bridge or another VLAN (a C-VLAN on an S-VLAN is QinQ). RouterOS calls it `interface=`; the CoreRouter command calls it `parent`, and the terminal takes both."),
    ("interfaces.vlan.mtu", "## MTU\nThe largest IP packet on the VLAN. Empty takes the MTU of the parent, which is also the ceiling. The tag (4 bytes, 8 for QinQ) goes in the parent's L2 MTU, not here."),
    ("interfaces.vlan.name", "## Name\nThe VLAN interface's name, used in addresses, routes and the firewall. Something that says where it goes (`vlan100`, `cli-acme`) helps the next operator."),
    ("interfaces.vlan.use_service_tag", "## Use Service Tag (802.1ad)\nThe tag this VLAN puts on the frame:\n\n- **off** (default): an 802.1Q **C-tag**, TPID `0x8100`, the ordinary customer VLAN;\n- **on**: an 802.1ad **S-tag**, TPID `0x88a8`, the outer (service) tag of QinQ. The customer's C-VLAN is then a plain VLAN created on top of this one.\n\n**When to turn it on:** the transport carrier or the OLT hands over QinQ with an 0x88a8 outer tag.\n\n**Careful:** both ends must use the same TPID. With one side on 0x8100 and the other on 0x88a8 nothing passes and no error shows. Changing it means removing the VLAN and adding it again.\n\nStandard: IEEE 802.1ad (now in 802.1Q). RouterOS: `use-service-tag=yes`."),
    ("interfaces.vlan.vlan_id", "## VLAN ID\nThe 12-bit tag, 1 to 4094 (0 and 4095 are reserved). It must match the switch or the peer on the other end. The same id can exist once as a C-VLAN and once as an S-VLAN on the same parent."),
];
