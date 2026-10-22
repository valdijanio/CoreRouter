//! Option 82, the relay agent information (RFC 3046): sub-options, the
//! circuit id (§3.1: the port the request came in on — an OLT's PON port
//! and ONU, a switch port) and the remote id (§3.2: the subscriber's line
//! or the client's MAC). Both are opaque bytes (§3.1, §3.2: "SHOULD NOT be
//! parsed"); for people they are text when printable, hex otherwise.

/// RFC 3046 §2.0 sub-option codes.
pub const CIRCUIT_ID: u8 = 1;
pub const REMOTE_ID: u8 = 2;

/// The sub-options of an option 82 value, in order. A truncated one ends
/// the walk (hostile input).
pub fn suboptions(data: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut rest = data;
    while let [code, len, tail @ ..] = rest {
        let Some(value) = tail.get(..usize::from(*len)) else {
            break;
        };
        out.push((*code, value));
        rest = tail.get(usize::from(*len)..).unwrap_or(&[]);
    }
    out
}

/// Sub-option `code` of an option 82 value.
pub fn get(data: &[u8], code: u8) -> Option<&[u8]> {
    suboptions(data)
        .into_iter()
        .find(|(c, _)| *c == code)
        .map(|(_, v)| v)
}

/// An option 82 value with these sub-options (each at most 255 bytes;
/// the whole at most 255: RFC 3046 §2.1, a relay that cannot fit it sends
/// none). `None` when it does not fit.
pub fn build(circuit: &[u8], remote: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for (code, v) in [(CIRCUIT_ID, circuit), (REMOTE_ID, remote)] {
        if v.is_empty() {
            continue;
        }
        out.push(code);
        out.push(u8::try_from(v.len()).ok()?);
        out.extend_from_slice(v);
    }
    (!out.is_empty() && out.len() <= 255).then_some(out)
}

/// Bytes for people: the text when every byte is printable ASCII, else
/// `0x…`.
pub fn text(v: &[u8]) -> String {
    if !v.is_empty() && v.iter().all(|b| (0x20..0x7f).contains(b)) {
        String::from_utf8_lossy(v).into_owned()
    } else {
        crate::v4::hex(v)
    }
}

/// What an operator writes for an id (`agent_circuit_id`): `0x…` is bytes,
/// anything else its text.
pub fn parse(written: &str) -> Option<Vec<u8>> {
    let t = written.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(hex) = t.strip_prefix("0x") {
        return super::leases::unhex(hex).filter(|b| !b.is_empty() && b.len() <= 255);
    }
    (t.len() <= 255).then(|| t.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suboptions_round_trip() {
        // RFC 3046 §2.0's layout: code, length, value.
        let v = build(b"olt1 0/1/3:12", &[0x02, 0, 0, 0, 0, 9]).unwrap();
        assert_eq!(v[0], CIRCUIT_ID);
        assert_eq!(text(get(&v, CIRCUIT_ID).unwrap()), "olt1 0/1/3:12");
        assert_eq!(text(get(&v, REMOTE_ID).unwrap()), "0x020000000009");
        assert_eq!(get(&v, 9), None);
        assert!(build(&[], &[]).is_none());
        assert!(
            build(&[b'x'; 200], &[b'y'; 100]).is_none(),
            "over 255 bytes"
        );
        // Truncated: what fits is kept, the rest ignored.
        assert_eq!(suboptions(&[1, 2, b'a', b'b', 2, 9, 1]).len(), 1);
        for n in 0..8 {
            let _ = suboptions(&vec![1; n]);
        }
        assert_eq!(parse("0x0102").unwrap(), [1, 2]);
        assert_eq!(parse("eth3").unwrap(), b"eth3");
        assert!(parse("").is_none());
    }
}
