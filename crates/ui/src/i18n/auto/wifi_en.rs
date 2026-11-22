//! English explanations of Interfaces › Wi-Fi (G1.30), sorted by key
//! (registered by `build.rs`).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "interface.wifi",
        r##"## What it is
A Wi-Fi radio in station mode: the router joins a Wi-Fi network as a client, for management or as an uplink (RouterOS `/interface wifi` with `mode=station`). One network per radio.

## Before applying
The window checks for you: the passphrase's length, whether the last scan heard the network, the country (a radio is not turned on without one) and whether this session comes in through this radio. The commands it will run are listed at the bottom.

## Careful
- Changing the network of the radio you manage the router through can drop your session: use **Safe Mode**, which undoes the change if the session does not come back.
- A station cannot be a bridge port: route through it."##,
    ),
    (
        "interface.wifi.band",
        r##"## What it is
Join only on this band: `2ghz`, `5ghz` or `6ghz`. Empty: whichever band the network is on, the strongest access point first.

## When to use it
A network with the same name on two bands, when you want the faster one (5 GHz) or the one that reaches farther (2.4 GHz)."##,
    ),
    (
        "interface.wifi.bssid",
        r##"## What it is
The MAC address of one access point. In the settings: join only that access point, even if another one of the same network is stronger. Empty: any.

## Careful
With the BSSID locked the radio does not roam: if that access point goes away, the link stays down."##,
    ),
    (
        "interface.wifi.channel",
        r##"## What it is
The band and the channel the access point is on, with its frequency. The station does not choose the channel: the access point does.

## Careful
In the world regulatory domain (no country set) the radio only listens on 5 GHz. Channels with radar detection (DFS) can make the access point move."##,
    ),
    (
        "interface.wifi.country",
        r##"## What it is
The country the router is in, two letters (ISO 3166-1: `BR`, `US`, `DE`). It decides the channels and the transmit power the radios may use. One country for every radio of the router.

## Why it is required
With no country the kernel uses the world domain: 5 GHz is listen-only and 2.4 GHz is limited. With the wrong country the radio transmits where it must not. So a radio is not turned on before the country is set.

## In force
What the kernel applies now. Some cards (Intel) follow their own firmware and ignore the country set here; the window says so."##,
    ),
    (
        "interface.wifi.disabled",
        r##"## What it is
The radio is off: it does not scan, does not join and does not transmit. A radio starts disabled (as in RouterOS) and is turned on once it has a network and the router has a country."##,
    ),
    (
        "interface.wifi.failure",
        r##"## What it is
Why the last attempt did not end in a link, in words:
- **wrong passphrase?** The key exchange failed. With WPA2 the access point never says the passphrase is wrong, it just stops answering: a very weak signal or a MAC filter look the same.
- **network not found.** No access point with that name and security answered the scan: out of range, another band, a hidden network without *Hidden Network*, or a channel the country does not allow.
- **refused by the access point.** With the reason it gave.
- **no answer.** Several attempts in a row ended in nothing.

The cause stays on screen while the router keeps trying."##,
    ),
    (
        "interface.wifi.hidden",
        r##"## What it is
The network does not announce its name. The radio then asks for it by name on every channel instead of waiting to hear it.

## Careful
A hidden network is not safer: the name goes in clear every time a client joins."##,
    ),
    (
        "interface.wifi.mtu",
        r##"## What it is
The largest packet the interface carries, 68 to 2304 bytes. The default 1500 is what Ethernet behind the access point carries; leave it unless you know the path takes more."##,
    ),
    (
        "interface.wifi.name",
        r##"## What it is
The radio's name: `wifi1`, `wifi2`… (as in RouterOS 7). It is tied to the card's MAC address, so it does not change from one boot to the next. Firewall rules, addresses and the DHCP client name it like any other interface."##,
    ),
    (
        "interface.wifi.networks",
        r##"## What it is
What the last scan of the radio heard: one row per access point, strongest first. **Rescan** listens again on every channel (a few seconds). **Connect…** opens the radio's settings with the network filled in; only the passphrase is left to type.

## What cannot be joined
A greyed row, with the reason: networks with 802.1X (user and password or certificate), OWE, and the old WEP and WPA/TKIP are not supported."##,
    ),
    (
        "interface.wifi.networks.security",
        r##"## What it is
What the access point offers:
- **WPA3**, **WPA2/WPA3**, **WPA2**: a passphrase. With WPA2/WPA3 the router uses WPA3.
- **open**: no encryption; anybody in range reads what is not encrypted by itself.
- **802.1X**, **OWE**, **WEP/WPA**: cannot be joined yet."##,
    ),
    (
        "interface.wifi.passphrase",
        r##"## What it is
The network's passphrase: 8 to 63 characters. With *Security* `wpa2` the 64-digit hexadecimal key is accepted too.

## How it is kept
Sealed in the configuration (encrypted with the router's key). It is never shown again: lists, the log, the journal and `/export` show `***`. Leave the field empty to keep the one the router has."##,
    ),
    (
        "interface.wifi.radio",
        r##"## What it is
The kernel driver of the card (`iwlwifi`, `mt7921e`, `rtw89_8852be`…). A card whose driver or firmware is not in the image does not show up here: see System › Resources, hardware problems."##,
    ),
    (
        "interface.wifi.rate",
        r##"## What it is
The transmit rate the driver is using now, in Mbit/s. It follows the signal: the radio lowers it when frames start to be lost. It is the rate on the air, not the throughput: expect about half of it."##,
    ),
    (
        "interface.wifi.reconnects",
        r##"## What it is
How many times the link was lost since the radio was turned on (a change you made yourself does not count). A number that keeps growing points to a weak signal, interference or an access point that restarts."##,
    ),
    (
        "interface.wifi.security",
        r##"## What it is
How the radio authenticates:
- **auto** (default): WPA3 if the access point offers it, else WPA2.
- **wpa3**: WPA3 only; never falls back.
- **wpa2**: WPA2 only, for an access point that misbehaves with WPA3.
- **open**: no passphrase and no encryption.

## Careful
On an open network anybody in range reads the traffic that is not encrypted by itself (HTTPS, TLS, a VPN). Networks with 802.1X and OWE are not supported yet."##,
    ),
    (
        "interface.wifi.signal",
        r##"## What it is
How strong the access point is heard, in dBm (closer to zero is stronger).
- **-65 dBm or better** (green): comfortable.
- **-66 to -75 dBm** (amber): works, at lower rates.
- **below -75 dBm** (red): the link drops and retries."##,
    ),
    (
        "interface.wifi.ssid",
        r##"## What it is
The network's name, 1 to 32 bytes, exactly as the access point announces it (capital letters and spaces count). Empty: the radio forgets the network and its passphrase."##,
    ),
    (
        "interface.wifi.state",
        r##"## What it is
Where the radio is:
- **connected**: on the network, with the key exchange done.
- **searching**: scanning for the network.
- **connecting**: authenticating with an access point.
- **no network**: on, with no network set.
- **no country**: enabled, but the router has no country yet; the radio stays off.
- **blocked**: turned off by a switch, the airplane-mode key or the firmware (rfkill).
- **absent**: the card is not there (unplugged, or its driver did not load).
- **disabled**: off.

A second chip says why the last attempt failed."##,
    ),
    (
        "menu.wifi",
        r##"## What it does
RouterOS `/interface wifi` in station mode: the router joins a Wi-Fi network as a client, for management or as an uplink. Each radio is an interface (`wifi1`) that addresses, the DHCP client and firewall rules name like any other.

## How CoreRouter does it
- WPA2 and WPA3 with a passphrase, and open networks with a warning.
- The passphrase is sealed in the configuration and never shown again.
- A radio is not turned on before the country is set.
- The reason of a failure in words: wrong passphrase, network not found, refused.
- Changing the network of the radio you come in through asks for Safe Mode."##,
    ),
];
