//! Bounded line framing shared by the control channel and the MCP stdio server.

use std::io::{self, BufRead};

/// Largest accepted request line.
pub const MAX_REQUEST_LINE: usize = 16 * 1024 * 1024;
/// Largest accepted response line (screenshots are big).
pub const MAX_RESPONSE_LINE: usize = 256 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    Text(String),
    /// The line exceeded the limit; it was consumed and discarded.
    TooLong,
    Eof,
}

/// Read one `\n`-terminated line, never buffering more than `max` bytes.
pub fn read_line_bounded<R: BufRead>(r: &mut R, max: usize) -> io::Result<Line> {
    let mut buf: Vec<u8> = Vec::new();
    let mut too_long = false;
    loop {
        let chunk = match r.fill_buf() {
            Ok(c) => c,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if chunk.is_empty() {
            if too_long {
                return Ok(Line::TooLong);
            }
            if buf.is_empty() {
                return Ok(Line::Eof);
            }
            break;
        }
        let (piece, done) = match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => (chunk.get(..i).unwrap_or_default(), Some(i + 1)),
            None => (chunk, None),
        };
        if !too_long {
            if buf.len().saturating_add(piece.len()) > max {
                too_long = true;
                buf = Vec::new();
            } else {
                buf.extend_from_slice(piece);
            }
        }
        let used = done.unwrap_or(chunk.len());
        r.consume(used);
        if done.is_some() {
            break;
        }
    }
    if too_long {
        return Ok(Line::TooLong);
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    Ok(Line::Text(String::from_utf8_lossy(&buf).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn splits_and_limits() {
        let mut r = Cursor::new(b"abc\r\n0123456789\nxy".to_vec());
        assert_eq!(
            read_line_bounded(&mut r, 8).unwrap(),
            Line::Text("abc".into())
        );
        assert_eq!(read_line_bounded(&mut r, 8).unwrap(), Line::TooLong);
        assert_eq!(
            read_line_bounded(&mut r, 8).unwrap(),
            Line::Text("xy".into())
        );
        assert_eq!(read_line_bounded(&mut r, 8).unwrap(), Line::Eof);
    }
}
