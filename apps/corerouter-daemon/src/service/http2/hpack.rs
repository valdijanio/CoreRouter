//! HPACK (RFC 7541) for the HTTP/2 client: a full decoder (static and
//! dynamic tables, Huffman) and the small encoder a client needs (literals
//! that never touch the server's dynamic table).
//!
//! Hostile input: every length is checked against what is left of the
//! block, integers are capped (§5.1 lets them grow without bound), the
//! header list is capped at [`MAX_LIST`] bytes, and a dynamic table size
//! update above what we allowed is an error (§6.3).

use std::collections::VecDeque;

use super::tables::{HUFFMAN, STATIC};

/// The table size we allow the server (SETTINGS_HEADER_TABLE_SIZE's
/// default, RFC 9113 §6.5.2).
pub(super) const TABLE_SIZE: usize = 4096;
/// The decoded header list at most (names + values + 32 each, §4.1),
/// like SETTINGS_MAX_HEADER_LIST_SIZE.
pub(super) const MAX_LIST: usize = 16 * 1024;
/// §4.1: each entry costs its name, its value and 32 bytes.
const ENTRY_OVERHEAD: usize = 32;

pub(super) type Header = (String, String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HpackError(pub(super) &'static str);

/// The decoder's state: the dynamic table lives across header blocks of
/// one connection.
#[derive(Debug)]
pub(super) struct Decoder {
    /// Newest first (§2.3.3: index 62 is the newest entry).
    table: VecDeque<Header>,
    size: usize,
    max: usize,
}

impl Default for Decoder {
    fn default() -> Self {
        Self {
            table: VecDeque::new(),
            size: 0,
            max: TABLE_SIZE,
        }
    }
}

impl Decoder {
    /// One header block (the HEADERS and CONTINUATION payloads together).
    pub(super) fn decode(&mut self, mut b: &[u8]) -> Result<Vec<Header>, HpackError> {
        let mut out = Vec::new();
        let mut list = 0usize;
        let mut first = true;
        while let Some(&byte) = b.first() {
            if byte & 0x80 != 0 {
                // §6.1: indexed header field.
                let (i, rest) = int(b, 7)?;
                b = rest;
                out.push(self.get(i)?);
            } else if byte & 0xc0 == 0x40 {
                // §6.2.1: literal with incremental indexing.
                let (h, rest) = self.literal(b, 6)?;
                b = rest;
                self.insert(h.clone());
                out.push(h);
            } else if byte & 0xe0 == 0x20 {
                // §6.3: dynamic table size update, only at the start of a
                // block (§4.2), never above what we allowed.
                if !first {
                    return Err(HpackError("table size update after a header"));
                }
                let (n, rest) = int(b, 5)?;
                b = rest;
                if n > TABLE_SIZE {
                    return Err(HpackError("table size update above the allowed size"));
                }
                self.max = n;
                self.evict(0);
                continue;
            } else {
                // §6.2.2 (0000) and §6.2.3 (0001): literal, not indexed.
                let (h, rest) = self.literal(b, 4)?;
                b = rest;
                out.push(h);
            }
            first = false;
            if let Some(h) = out.last() {
                list = list.saturating_add(h.0.len() + h.1.len() + ENTRY_OVERHEAD);
            }
            if list > MAX_LIST {
                return Err(HpackError("header list too large"));
            }
        }
        Ok(out)
    }

    /// §2.3.3: 1..=61 static, then the dynamic table, newest first.
    fn get(&self, i: usize) -> Result<Header, HpackError> {
        if i == 0 {
            return Err(HpackError("index 0"));
        }
        if let Some((n, v)) = STATIC.get(i - 1) {
            return Ok(((*n).to_owned(), (*v).to_owned()));
        }
        self.table
            .get(i - 1 - STATIC.len())
            .cloned()
            .ok_or(HpackError("index past the tables"))
    }

    /// A literal with a `prefix`-bit name index (0: a new name follows).
    fn literal<'a>(&self, b: &'a [u8], prefix: u8) -> Result<(Header, &'a [u8]), HpackError> {
        let (i, b) = int(b, prefix)?;
        let (name, b) = if i == 0 {
            string(b)?
        } else {
            (self.get(i)?.0, b)
        };
        let (value, b) = string(b)?;
        Ok(((name, value), b))
    }

    /// §4.4: a new entry evicts the oldest until it fits; one bigger than
    /// the table empties it and is not added.
    fn insert(&mut self, h: Header) {
        let size = h.0.len() + h.1.len() + ENTRY_OVERHEAD;
        self.evict(size);
        if size <= self.max {
            self.size += size;
            self.table.push_front(h);
        }
    }

    fn evict(&mut self, room: usize) {
        while self.size + room > self.max {
            let Some((n, v)) = self.table.pop_back() else {
                self.size = 0;
                return;
            };
            self.size = self.size.saturating_sub(n.len() + v.len() + ENTRY_OVERHEAD);
        }
    }

    #[cfg(test)]
    pub(super) fn table_size(&self) -> usize {
        self.size
    }
}

/// §5.1: an integer with an `n`-bit prefix (the first byte's other bits
/// are the caller's). Capped at 2^24: nothing a client reads is bigger.
fn int(b: &[u8], n: u8) -> Result<(usize, &[u8]), HpackError> {
    const CAP: usize = 1 << 24;
    let (&first, mut rest) = b.split_first().ok_or(HpackError("truncated integer"))?;
    let mask = (1u16 << n) - 1;
    let mut v = usize::from(u16::from(first) & mask);
    if v < usize::from(mask) {
        return Ok((v, rest));
    }
    let mut shift = 0u32;
    loop {
        let (&byte, r) = rest.split_first().ok_or(HpackError("truncated integer"))?;
        rest = r;
        // Zero continuation bytes do not make the value grow: the shift
        // has its own cap (a 2^24 value needs 4 bytes of 7 bits).
        let add = usize::from(byte & 0x7f)
            .checked_shl(shift)
            .filter(|_| shift <= 28)
            .ok_or(HpackError("integer too large"))?;
        v = v.saturating_add(add);
        if v > CAP {
            return Err(HpackError("integer too large"));
        }
        if byte & 0x80 == 0 {
            return Ok((v, rest));
        }
        shift += 7;
    }
}

/// §5.2: a string literal, raw or Huffman coded.
fn string(b: &[u8]) -> Result<(String, &[u8]), HpackError> {
    let huff = b.first().is_some_and(|f| f & 0x80 != 0);
    let (len, b) = int(b, 7)?;
    let raw = b.get(..len).ok_or(HpackError("truncated string"))?;
    let rest = b.get(len..).unwrap_or_default();
    let bytes = if huff { huffman_decode(raw)? } else { raw.to_vec() };
    // Header names and values are visible ASCII in practice; anything else
    // stays as bytes we never act on.
    Ok((String::from_utf8_lossy(&bytes).into_owned(), rest))
}

/// §5.2: the canonical code decoded bit by bit (header strings are short).
/// The padding is at most 7 bits, all ones; EOS inside is an error.
pub(super) fn huffman_decode(b: &[u8]) -> Result<Vec<u8>, HpackError> {
    let mut out = Vec::with_capacity(b.len() * 8 / 5);
    let mut code = 0u32;
    let mut bits = 0u8;
    for &byte in b {
        for k in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> k) & 1);
            bits += 1;
            if bits > 30 {
                return Err(HpackError("Huffman code too long"));
            }
            if let Some(sym) = symbol(code, bits) {
                if sym == 256 {
                    return Err(HpackError("EOS in a Huffman string"));
                }
                out.push(u8::try_from(sym).map_err(|_| HpackError("Huffman symbol"))?);
                code = 0;
                bits = 0;
            }
        }
    }
    // §5.2: what is left must be a prefix of EOS (all ones), < 8 bits.
    if bits > 7 || code != (1u32 << bits) - 1 {
        return Err(HpackError("bad Huffman padding"));
    }
    Ok(out)
}

/// The symbol whose code is `code` of `len` bits, if any: a binary search
/// among the codes of that length (a linear scan of the 257 codes at every
/// bit cost tens of µs per answer).
fn symbol(code: u32, len: u8) -> Option<usize> {
    let by_len = by_length().get(usize::from(len))?;
    let i = by_len.binary_search_by_key(&code, |&(c, _)| c).ok()?;
    by_len.get(i).map(|&(_, sym)| usize::from(sym))
}

/// The codes of each length (1..=30), sorted, with their symbols.
fn by_length() -> &'static [Vec<(u32, u16)>] {
    static TABLE: std::sync::OnceLock<Vec<Vec<(u32, u16)>>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = vec![Vec::new(); 31];
        for (sym, &(code, len)) in HUFFMAN.iter().enumerate() {
            if let (Some(v), Ok(sym)) = (t.get_mut(usize::from(len)), u16::try_from(sym)) {
                v.push((code, sym));
            }
        }
        for v in &mut t {
            v.sort_unstable();
        }
        t
    })
}

/// What a client sends: an indexed field when the static table has the
/// whole field, else a literal "without indexing" (§6.2.2) with the static
/// name when there is one, raw (not Huffman) strings. The server's view of
/// our dynamic table stays empty.
pub(super) fn encode(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(name, value) in headers {
        if let Some(i) = STATIC.iter().position(|&(n, v)| n == name && v == value) {
            put_int(&mut out, 0x80, 7, i + 1);
            continue;
        }
        match STATIC.iter().position(|&(n, _)| n == name) {
            Some(i) => put_int(&mut out, 0x00, 4, i + 1),
            None => {
                out.push(0x00);
                put_str(&mut out, name);
            }
        }
        put_str(&mut out, value);
    }
    out
}

fn put_int(out: &mut Vec<u8>, flags: u8, n: u8, mut v: usize) {
    let max = (1usize << n) - 1;
    if v < max {
        out.push(flags | u8::try_from(v).unwrap_or(0));
        return;
    }
    out.push(flags | u8::try_from(max).unwrap_or(0));
    v -= max;
    while v >= 0x80 {
        out.push(u8::try_from(v & 0x7f).unwrap_or(0) | 0x80);
        v >>= 7;
    }
    out.push(u8::try_from(v).unwrap_or(0));
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_int(out, 0x00, 7, s.len());
    out.extend_from_slice(s.as_bytes());
}

#[cfg(test)]
#[path = "hpack/tests.rs"]
pub(super) mod tests;
