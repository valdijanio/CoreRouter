//! RFC 7541 Appendix C, byte for byte, and hostile blocks.

use super::*;

/// xorshift64*: the same bytes every run (a fuzz loop with no dependency).
pub(crate) fn rng(seed: u64) -> impl FnMut() -> u64 {
    let mut x = seed.max(1);
    move || {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn list(h: &[Header]) -> Vec<String> {
    h.iter().map(|(n, v)| format!("{n}: {v}")).collect()
}

/// C.4: three requests with Huffman, one decoder (the dynamic table
/// carries from one to the next).
#[test]
fn rfc7541_c4_requests_with_huffman() {
    let mut d = Decoder::default();
    let c41 = d.decode(&hex("828684418cf1e3c2e5f23a6ba0ab90f4ff")).unwrap();
    assert_eq!(
        list(&c41),
        [":method: GET", ":scheme: http", ":path: /", ":authority: www.example.com"]
    );
    assert_eq!(d.table_size(), 57, "C.4.1: table size 57");
    let c42 = d.decode(&hex("828684be5886a8eb10649cbf")).unwrap();
    assert_eq!(list(&c42).last().unwrap(), "cache-control: no-cache");
    assert_eq!(d.table_size(), 110);
    let c43 = d
        .decode(&hex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"))
        .unwrap();
    assert_eq!(
        list(&c43),
        [
            ":method: GET",
            ":scheme: https",
            ":path: /index.html",
            ":authority: www.example.com",
            "custom-key: custom-value"
        ]
    );
    assert_eq!(d.table_size(), 164);
}

/// C.6: responses with Huffman and a 256-byte table: entries are evicted.
#[test]
fn rfc7541_c6_responses_with_eviction() {
    let mut d = Decoder {
        max: 256,
        ..Decoder::default()
    };
    let r1 = d
        .decode(&hex(
            "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
        ))
        .unwrap();
    assert_eq!(
        list(&r1),
        [
            ":status: 302",
            "cache-control: private",
            "date: Mon, 21 Oct 2013 20:13:21 GMT",
            "location: https://www.example.com"
        ]
    );
    assert_eq!(d.table_size(), 222);
    let r2 = d.decode(&hex("4883640effc1c0bf")).unwrap();
    assert_eq!(list(&r2).first().unwrap(), ":status: 307");
    assert_eq!(d.table_size(), 222);
    let r3 = d
        .decode(&hex(
            "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
        ))
        .unwrap();
    assert_eq!(
        list(&r3),
        [
            ":status: 200",
            "cache-control: private",
            "date: Mon, 21 Oct 2013 20:13:22 GMT",
            "location: https://www.example.com",
            "content-encoding: gzip",
            "set-cookie: foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"
        ]
    );
    assert_eq!(d.table_size(), 215, "C.6.3: table size 215");
}

/// What we send decodes back to itself (static names and full matches).
#[test]
fn our_request_block_round_trips() {
    let h = [
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", "dns.example:8443"),
        (":path", "/dns-query"),
        ("content-type", "application/dns-message"),
        ("accept", "application/dns-message"),
        ("content-length", "33"),
        ("x-long", &"v".repeat(300)),
    ];
    let block = encode(&h);
    assert_eq!(block.first(), Some(&0x83), "C.2.4-style indexed :method POST");
    let got = Decoder::default().decode(&block).unwrap();
    let want: Vec<Header> = h.iter().map(|(n, v)| ((*n).into(), (*v).into())).collect();
    assert_eq!(got, want);
}

#[test]
fn hostile_blocks_fail_cleanly() {
    let mut d = Decoder::default();
    for (bad, why) in [
        (vec![0x80], "index 0"),
        (vec![0xff, 0x80], "truncated integer"),
        (vec![0xbf, 0x01], "index past the tables"),
        (vec![0x00, 0x05, b'a'], "truncated string"),
        // 31 + 98 + 31·128 = 4097, one over the allowed 4096.
        (vec![0x3f, 0xe2, 0x1f], "table size update above"),
        (vec![0x82, 0x20], "table size update after"),
        (vec![0xff, 0xff, 0xff, 0xff, 0xff, 0x7f], "integer too large"),
        // Zero continuation bytes: the shift grows, the value does not.
        ([vec![0xff], vec![0x80; 20], vec![0x01]].concat(), "integer too large"),
        // A Huffman string of 1 byte 0x00: bits that never finish a code.
        (vec![0x00, 0x81, 0x00, 0x00], "Huffman"),
    ] {
        let err = d.decode(&bad).unwrap_err();
        assert!(err.0.contains(why) || why == "Huffman" && err.0.contains("Huffman"), "{bad:?}: {err:?}");
    }
    // EOS inside: 30 ones then padding.
    assert!(huffman_decode(&[0xff, 0xff, 0xff, 0xff]).is_err());
    // A header list over the cap.
    let mut big = Vec::new();
    for _ in 0..200 {
        big.extend(encode(&[("x-a", &"b".repeat(100))]));
    }
    assert_eq!(d.decode(&big).unwrap_err().0, "header list too large");
}

/// Any bytes: an answer or an error, never a panic; the table stays
/// within its size (4000 random blocks, a fixed seed).
#[test]
fn arbitrary_blocks_never_panic() {
    let mut r = rng(7);
    let mut d = Decoder::default();
    for _ in 0..4000 {
        let len = usize::try_from(r() % 200).unwrap();
        let b: Vec<u8> = (0..len).map(|_| r().to_le_bytes()[0]).collect();
        let _ = d.decode(&b);
        assert!(d.table_size() <= TABLE_SIZE);
    }
}

#[test]
fn literals_round_trip() {
    let mut r = rng(11);
    for _ in 0..2000 {
        let pick = |r: &mut dyn FnMut() -> u64, set: &[u8], max: u64| -> String {
            let n = usize::try_from(r() % max).unwrap();
            (0..n)
                .map(|_| char::from(set[usize::try_from(r() % set.len() as u64).unwrap()]))
                .collect()
        };
        let name = format!("x{}", pick(&mut r, b"abcdefghijklmnopqrstuvwxyz-", 40));
        let value = pick(&mut r, &(b' '..=b'~').collect::<Vec<u8>>(), 200);
        let block = encode(&[(&name, &value)]);
        let got = Decoder::default().decode(&block).unwrap();
        assert_eq!(got, vec![(name, value)]);
    }
}
