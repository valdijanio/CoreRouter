//! English explanations of the access point of Interfaces › Wi-Fi (G1.30a),
//! sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "interface.wifi.clients",
        r##"## Clients
The stations associated with this access point now. Each one is a row of the Registration tab."##,
    ),
    (
        "interface.wifi.frequency",
        r##"## Frequency (access point)
The channel the access point runs on: a channel number (`36`), the frequency in MHz (`5180`) or `auto`.

**auto** (the default) picks the quietest channel of the last scan without radar detection, in the band of Band (5 GHz when the radio may start a network there). Chosen once, it stays until the settings change.

The router refuses a channel the country does not allow, a passive one (no-IR: a station may answer there, an access point may not start) and one the radio does not have. A channel with radar detection (DFS, 52 to 144) is allowed: the access point listens for a minute (ten on the weather radar channels 120 to 128) before the first beacon.

Ignored by a station."##,
    ),
    (
        "interface.wifi.mode",
        r##"## Mode
- **station**: the router joins somebody's network (an uplink, management).
- **ap**: the router announces the network; clients join it. Put it in a bridge to give the clients the LAN, or give it an address and a DHCP server to route them.

The radio does one at a time. Changing the mode of the radio this connection comes through needs Safe Mode (or force)."##,
    ),
    (
        "interface.wifi.radar",
        r##"## Radar check
On a channel with radar detection (DFS) the access point listens for radar before its first beacon: 60 s, 10 minutes on channels 120 to 128 (IEEE 802.11h, ETSI EN 301 893). Radar heard later closes the channel for 30 minutes."##,
    ),
    (
        "interface.wifi.registration.interface",
        r##"## Interface
The access point the client is associated with."##,
    ),
    (
        "interface.wifi.registration.mac",
        r##"## MAC Address
The client's address. Phones often use a random one per network (private address)."##,
    ),
    (
        "interface.wifi.registration.rate",
        r##"## Tx and Rx Rate
The rate of the last frame sent to the client (Tx) and received from it (Rx), with the mode, the MCS and the streams. It changes with the signal and the noise."##,
    ),
    (
        "interface.wifi.registration.retries",
        r##"## Retries
The share of frames to the client that had to be sent again. Amber from 10 %, red from 20 %: weak signal, interference or a crowded channel."##,
    ),
    (
        "interface.wifi.registration.security",
        r##"## Security
How the client joined: **WPA3** (SAE, with protected management frames), **WPA2** (PSK) or **open**. With security `auto` the access point offers both, and each client uses the best it has. **not authorized**: associated, still in the handshake."##,
    ),
    (
        "interface.wifi.registration.standard",
        r##"## Standard
The Wi-Fi generation the client speaks with the access point: 802.11n (Wi-Fi 4), ac (5), ax (6), be (7)."##,
    ),
    (
        "interface.wifi.registration.uptime",
        r##"## Uptime
How long the client has been associated."##,
    ),
    (
        "interface.wifi.width",
        r##"## Width (access point)
How wide the channel is: 20, 40, 80 or 160 MHz, or `auto`: 20 MHz on 2.4 GHz (40 there takes two of the three channels that do not overlap), the widest up to 80 MHz on 5 GHz.

Wider is faster near the access point and more exposed to neighbours. 160 MHz crosses radar channels on 5 GHz. Every 20 MHz channel of the block must be allowed in the country."##,
    ),
];
