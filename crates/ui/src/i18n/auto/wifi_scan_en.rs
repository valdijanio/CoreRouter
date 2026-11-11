//! English explanations of the Networks tab views of Interfaces › Wi-Fi
//! (G1.30i), sorted by key (registered by `build.rs`).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "interface.wifi.band-filter",
        r##"## What it is
Show only the networks of one band: 2.4 GHz, 5 GHz or 6 GHz. The number on each pill is how many access points the scan heard there. It applies to the list and the channel graph."##,
    ),
    (
        "interface.wifi.group",
        r##"## What it is
Group the list by primary channel: a block per channel with the number of networks on it, strongest first. Shows at a glance which channels are crowded."##,
    ),
    (
        "interface.wifi.networks.air",
        r##"## What it is
How the other networks heard bear on this one:
- **same channel ×N**: N networks on the same primary channel.
- **overlaps ch …**: the primary channels of the networks whose channel covers part of this one. On 2.4 GHz channels less than 5 apart overlap (1 and 5 do, 1 and 6 do not), hence the habit of 1, 6 and 11.
- **shares airtime ×N**: N networks arrive strong enough that this one waits for them before it transmits.

## The rule (CCA)
A station transmits only with its primary channel idle (clear channel assessment). It defers to a Wi-Fi frame whose preamble it decodes at −82 dBm or more on its primary 20 MHz, and to any energy at −62 dBm or more (IEEE 802.11-2020 §17.3.10.6, §19.3.19.5 and §21.3.18.5). So another network shares the air:
- when this one's primary channel lies inside its channel (the same primary, or it sends wide frames over it) and it arrives at −82 dBm or more;
- when the channels only overlap (a partly overlapping 2.4 GHz channel, or it on this one's secondaries) and it arrives at −62 dBm or more: there only its energy counts.

## Careful
The level is the one this radio hears, which stands for what the access point next to it hears: an estimate."##,
    ),
    (
        "interface.wifi.networks.channel",
        r##"## What it is
The band and primary channel of the access point, with the width of the whole channel (20, 40, 80, 160 or 320 MHz) and the generation (Wi-Fi 4 to 7).

## Where it comes from
The elements the access point puts in its beacon (IEEE 802.11-2020 §9.4.2): HT Operation (40 MHz), VHT Operation (80, 160, 80+80), HE Operation with the 6 GHz information and EHT Operation (320 MHz, IEEE 802.11be-2024). A network that announces none of them is taken as 20 MHz."##,
    ),
    (
        "interface.wifi.networks.load",
        r##"## What it is
What the access point says of its own load, in the BSS Load element (IEEE 802.11): how many clients are associated and the share of time it found the channel busy (0 to 100%).

## How to read it
- up to 30%: room to spare;
- 30% to 60%: the channel already competes for time (amber);
- above 60%: congested (red).

Many home access points do not send the element: the column stays empty."##,
    ),
    (
        "interface.wifi.spectral.interference",
        r##"## What it is
What the energy of the last 10 seconds looks like, by its shape in frequency and time (RouterOS's spectral scan classes, where they fit):
- **Wi-Fi**: a block on the channel of a network heard, at its level, or a block 15 MHz or wider;
- **carrier** (cw): a signal under 1.5 MHz wide, on nearly all the time;
- **microwave oven** (mwo): between 2440 and 2480 MHz, 6 to 30 MHz wide, on about half the time and wandering;
- **Bluetooth** or **hopper** (fhss): narrow short bursts spread over 20 MHz or more;
- **unknown**: the rest above the noise.

## Careful
An estimate by shape, not an identification. Not checked on a real Atheros card."##,
    ),
    (
        "interface.wifi.spectral.range",
        r##"## What it is
What the spectral scan listens to:
- **channel in use**: the link's channel only, at the radio's resolution (about 0.3 MHz a point). It interrupts nothing.
- **2.4 GHz band** or **5 GHz band**: the whole band, swept with a scan every 4 seconds; the samples come while the radio visits each channel.

## Careful
Sweeping the band takes the radio off its channel for a moment at each scan: the link stalls meanwhile, and on an access point clients may drop (OpenWrt's Channel Analysis and airMAX M's airView warn the same)."##,
    ),
    (
        "interface.wifi.spectral.trace",
        r##"## What it is
Power per frequency, dBm, in three traces:
- **real-time**: the last quarter of a second;
- **average**: the running average;
- **peak**: the highest since the scan began.

Each point is the power of one point of the radio's FFT (about 0.3 MHz), not of the whole channel."##,
    ),
    (
        "interface.wifi.spectral.usage",
        r##"## What it is
For each 20 MHz channel, the share of the waterfall's rows in which the energy above the noise, summed over the channel, passed −82 dBm: the level at which a station would take the channel as busy if all of it were Wi-Fi (airView's "channel usage")."##,
    ),
    (
        "interface.wifi.spectral.waterfall",
        r##"## What it is
The waterfall: each row is a quarter of a second, the newest on top, and each column a frequency. The colour is the power above the noise floor: dark blue at the noise, then blue, cyan, green, yellow and red at 50 dB above. It keeps the last minute.

## How to read it
A wide, intermittent band is Wi-Fi; a thin steady line is a carrier; small scattered specks are a frequency hopper (Bluetooth); a block that comes and goes near 2.45 GHz is usually a microwave oven."##,
    ),
    (
        "interface.wifi.suggested",
        r##"## What it is
The 20 MHz channel of each band with the least on it, for when you pick the channel of an access point near here.

## How it is reckoned
For each candidate, every network whose channel covers it, weighted by how loud it is here (−95 dBm nothing, −50 dBm all) and how busy it says it is (BSS Load; half when it does not say), plus the busy share the driver measured, if any. On 2.4 GHz only 1, 6 and 11 are candidates. Channels with radar detection (DFS) lose ties and get the **DFS** pill: an access point there waits a minute before transmitting and moves if it hears radar."##,
    ),
    (
        "interface.wifi.survey",
        r##"## What it is
The share of time each channel was busy, measured by the driver itself (nl80211 survey: active and busy time per channel), like RouterOS's `frequency-scan`.

## Partial measures
Many drivers measure only the channel in use and leave the others at zero (measured on mt7925e). A channel without a measure shows a dash; the pill by the title says whether the measure is full, partial or absent."##,
    ),
    (
        "interface.wifi.view",
        r##"## What it is
Three ways to see what the radio heard:
- **List**: a row per access point, with its channel and width, the load it announces, the channels that overlap it and who shares its airtime. Filter by band, group by channel.
- **Channels**: each network as a curve over its channel's width, as tall as its signal (OpenWrt's Channel Analysis), and under it each channel's measured busy share.
- **Spectrum**: the spectral scan, like Ubiquiti's airView: waterfall, real-time trace, channel usage and the sources of interference. Only on radios with spectral scan (Qualcomm Atheros: ath9k, ath10k, ath11k); elsewhere it is off, with why.

## Careful
The list and the channels come from the scan (**Rescan**): it leaves the channel for a few milliseconds on each channel it visits. On a router that is an access point that can drop clients; on a station the link stalls for a moment."##,
    ),
];
