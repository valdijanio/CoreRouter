//! A small HTTP/1.1 client over TCP or TLS (rustls), blocking, for what the
//! daemon fetches itself: adlists (G4.1d), the ClickHouse exporter (G4.4f)
//! and, later, DNS over HTTPS.
//!
//! Why not a crate's client: the router has no system resolver (no
//! `/etc/resolv.conf` in its namespace or image), so host names go through
//! the router's own resolver, which the caller passes in; and every limit
//! below is ours to choose, because the other end may be hostile (a huge
//! header, an endless chunk, a redirect loop).
//!
//! Certificates are checked against the Mozilla roots compiled in
//! (`webpki-roots`: a router image has no CA store to trust). `verify ==
//! false` (RouterOS `ssl-verify=no`) still encrypts, but accepts any
//! certificate.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

/// Longest header block read (status line and headers).
const MAX_HEAD: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;
/// Trailer lines after a chunked body (we read none of them).
const MAX_TRAILERS: usize = 64;
/// Redirects followed at most (browsers stop near 20; lists need 1–2).
pub(crate) const MAX_REDIRECTS: usize = 5;

/// `http(s)://host[:port]/path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Url {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    /// With the query; starts with `/`.
    pub path: String,
}

impl Url {
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let shown: String = text.chars().take(80).collect();
        let (tls, rest) = if let Some(r) = text.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = text.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(format!("'{shown}' is not an http:// or https:// address"));
        };
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) => (rest.get(..i).unwrap_or_default(), rest.get(i..).unwrap_or("/")),
            None => (rest, "/"),
        };
        let path = path.split('#').next().unwrap_or("/");
        let path = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        if authority.is_empty() || authority.contains('@') {
            return Err(format!("'{shown}' has no host"));
        }
        let default = if tls { 443 } else { 80 };
        // `[2001:db8::1]:8443`, `host:8080`, `host`.
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or_else(|| format!("'{shown}': bad [address]"))?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse().map_err(|_| format!("'{shown}': bad port"))?,
                None if after.is_empty() => default,
                None => return Err(format!("'{shown}': bad host")),
            };
            (h.to_owned(), port)
        } else if let Some((h, p)) = authority.rsplit_once(':') {
            (h.to_owned(), p.parse().map_err(|_| format!("'{shown}': bad port"))?)
        } else {
            (authority.to_owned(), default)
        };
        if host.is_empty() || path.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err(format!("'{shown}' has no host, or spaces in the path"));
        }
        Ok(Self {
            tls,
            host: host.to_ascii_lowercase(),
            port,
            path,
        })
    }

    /// `Location` of a redirect: absolute, or a path on the same server.
    fn join(&self, location: &str) -> Result<Self, String> {
        if location.starts_with("http://") || location.starts_with("https://") {
            return Self::parse(location);
        }
        if location.starts_with("//") {
            let scheme = if self.tls { "https:" } else { "http:" };
            return Self::parse(&format!("{scheme}{location}"));
        }
        if !location.starts_with('/') || location.bytes().any(|b| b <= b' ') {
            return Err("redirect to an odd place".into());
        }
        Ok(Self {
            path: location.to_owned(),
            ..self.clone()
        })
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The client config: Mozilla roots, or (`verify == false`) any
/// certificate. Built once each.
pub(crate) fn tls_config(verify: bool) -> Result<Arc<ClientConfig>, String> {
    static CHECKED: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();
    static ANY: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();
    let make = || -> Result<Arc<ClientConfig>, String> {
        let p = provider();
        let builder = ClientConfig::builder_with_provider(p.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS: {e}"))?;
        let config = if verify {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            builder.with_root_certificates(roots).with_no_client_auth()
        } else {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AnyCert {
                    algs: p.signature_verification_algorithms,
                }))
                .with_no_client_auth()
        };
        Ok(Arc::new(config))
    };
    let cell = if verify { &CHECKED } else { &ANY };
    cell.get_or_init(make).clone()
}

/// A client config of its own (G4.4f, the ClickHouse exporter): the
/// server checked against `ca_pem` (PEM certificates; empty: the Mozilla
/// roots) or not at all (`verify == false`), and a client certificate
/// (`client`: certificate chain and private key, PEM) for servers that log
/// in by certificate.
pub(crate) fn custom_tls_config(
    verify: bool,
    ca_pem: &str,
    client: Option<(&str, &str)>,
) -> Result<Arc<ClientConfig>, String> {
    use rustls::pki_types::PrivateKeyDer;
    use rustls::pki_types::pem::PemObject;
    let p = provider();
    let builder = ClientConfig::builder_with_provider(p.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS: {e}"))?;
    let builder = if !verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert {
                algs: p.signature_verification_algorithms,
            }))
    } else if ca_pem.trim().is_empty() {
        builder.with_root_certificates(rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
    } else {
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
            let cert = cert.map_err(|e| format!("ca_certificate: {e}"))?;
            roots
                .add(cert)
                .map_err(|e| format!("ca_certificate: {e}"))?;
        }
        if roots.is_empty() {
            return Err("ca_certificate: no certificate in the PEM text".into());
        }
        builder.with_root_certificates(roots)
    };
    let config = match client {
        None => builder.with_no_client_auth(),
        Some((cert, key)) => {
            let chain = CertificateDer::pem_slice_iter(cert.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("certificate: {e}"))?;
            if chain.is_empty() {
                return Err("certificate: no certificate in the PEM text".into());
            }
            let key = PrivateKeyDer::from_pem_slice(key.as_bytes())
                .map_err(|e| format!("private_key: {e}"))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| format!("certificate and private_key: {e}"))?
        }
    };
    Ok(Arc::new(config))
}

/// `ssl_verify=no`: the connection is still encrypted and the handshake
/// signature checked, but the certificate is not.
#[derive(Debug)]
struct AnyCert {
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// A connection, plain or TLS.
pub(crate) enum Stream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Stream {
    fn tcp(&self) -> &TcpStream {
        match self {
            Self::Plain(s) => s,
            Self::Tls(s) => &s.sock,
        }
    }

    /// Read and write wait at most until `deadline`.
    pub(crate) fn deadline(&self, deadline: Instant) -> Result<(), String> {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("timed out".into());
        }
        let s = self.tcp();
        s.set_read_timeout(Some(left)).map_err(|e| e.to_string())?;
        s.set_write_timeout(Some(left)).map_err(|e| e.to_string())
    }
}

/// Reads from a stream until `deadline`, however the bytes trickle in:
/// each read waits only for what is left (a socket timeout alone restarts
/// with every byte).
struct Timed<'a> {
    s: &'a mut Stream,
    deadline: Instant,
}

impl Read for Timed<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out"));
        }
        self.s.tcp().set_read_timeout(Some(left))?;
        self.s.read(buf)
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}

/// Connects to `addr`; with `tls`, checks the certificate for `name` (a
/// host name or an address) unless `verify` is off.
pub(crate) fn connect(
    addr: SocketAddr,
    tls: bool,
    name: &str,
    verify: bool,
    deadline: Instant,
) -> Result<Stream, String> {
    let config = if tls { Some(tls_config(verify)?) } else { None };
    connect_with(addr, config, name, deadline)
}

/// Connects to `addr`, with TLS when `tls` gives a config.
pub(crate) fn connect_with(
    addr: SocketAddr,
    tls: Option<Arc<ClientConfig>>,
    name: &str,
    deadline: Instant,
) -> Result<Stream, String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err("timed out".into());
    }
    let tcp = TcpStream::connect_timeout(&addr, left).map_err(|e| format!("{addr}: {e}"))?;
    let _ = tcp.set_nodelay(true);
    let stream = if let Some(config) = tls {
        let server =
            ServerName::try_from(name.to_owned()).map_err(|e| format!("TLS name {name}: {e}"))?;
        let conn = ClientConnection::new(config, server).map_err(|e| format!("TLS: {e}"))?;
        Stream::Tls(Box::new(StreamOwned::new(conn, tcp)))
    } else {
        Stream::Plain(tcp)
    };
    stream.deadline(deadline)?;
    let mut stream = stream;
    if let Stream::Tls(s) = &mut stream {
        while s.conn.is_handshaking() {
            let StreamOwned { conn, sock } = &mut **s;
            conn.complete_io(sock)
                .map_err(|e| format!("TLS with {name}: {e}"))?;
        }
    }
    Ok(stream)
}

/// A response: status, the headers we use, the body.
#[derive(Debug, Default)]
pub(crate) struct Response {
    pub status: u16,
    pub location: Option<String>,
    pub content_type: Option<String>,
    /// The server keeps the connection open for another request.
    pub keep_alive: bool,
    /// ClickHouse's error code (`X-ClickHouse-Exception-Code`), G4.4f.
    pub exception_code: Option<String>,
    pub body: Vec<u8>,
}

/// Sends one request and reads the response, the body at most `max` bytes.
pub(crate) fn exchange(
    s: &mut Stream,
    method: &str,
    url: &Url,
    headers: &[(&str, &str)],
    body: &[u8],
    max: usize,
    deadline: Instant,
) -> Result<Response, String> {
    s.deadline(deadline)?;
    let host = if url.host.contains(':') {
        format!("[{}]", url.host)
    } else {
        url.host.clone()
    };
    let default = if url.tls { 443 } else { 80 };
    let host = if url.port == default {
        host
    } else {
        format!("{host}:{}", url.port)
    };
    let mut req = format!(
        "{method} {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: CoreRouter/{}\r\n",
        url.path,
        env!("CARGO_PKG_VERSION")
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() || method == "POST" {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    let mut out = req.into_bytes();
    out.extend_from_slice(body);
    s.write_all(&out).map_err(|e| e.to_string())?;
    s.flush().map_err(|e| e.to_string())?;
    read_response(s, method == "HEAD", max, deadline)
}

fn read_response(
    s: &mut Stream,
    head_only: bool,
    max: usize,
    deadline: Instant,
) -> Result<Response, String> {
    let mut r = BufReader::new(Timed { s, deadline });
    // The header block, up to the blank line.
    let mut head = Vec::new();
    loop {
        if Instant::now() >= deadline {
            return Err("timed out".into());
        }
        let n = (&mut r)
            .take((MAX_HEAD + 1 - head.len().min(MAX_HEAD)) as u64)
            .read_until(b'\n', &mut head)
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed before the response".into());
        }
        if head.len() > MAX_HEAD {
            return Err(format!("response headers longer than {MAX_HEAD} bytes"));
        }
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            break;
        }
    }
    let mut hs = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut hs);
    match resp.parse(&head) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => return Err("incomplete response headers".into()),
        Err(e) => return Err(format!("bad response: {e}")),
    }
    let status = resp.code.unwrap_or(0);
    let mut out = Response {
        status,
        keep_alive: resp.version == Some(1),
        ..Response::default()
    };
    let mut length: Option<usize> = None;
    let mut chunked = false;
    for h in resp.headers.iter() {
        let v = String::from_utf8_lossy(h.value).trim().to_owned();
        match h.name.to_ascii_lowercase().as_str() {
            "content-length" => {
                length = Some(v.parse().map_err(|_| "bad Content-Length".to_owned())?);
            }
            "transfer-encoding" => chunked = v.to_ascii_lowercase().contains("chunked"),
            "location" => out.location = Some(v.chars().take(2048).collect()),
            "content-type" => out.content_type = Some(v.chars().take(128).collect()),
            "x-clickhouse-exception-code" => out.exception_code = Some(v.chars().take(16).collect()),
            "connection" => {
                let v = v.to_ascii_lowercase();
                if v.contains("close") {
                    out.keep_alive = false;
                } else if v.contains("keep-alive") {
                    out.keep_alive = true;
                }
            }
            _ => {}
        }
    }
    // RFC 9112 §6.3: no body for HEAD, 1xx, 204 and 304.
    if head_only || status < 200 || status == 204 || status == 304 {
        return Ok(out);
    }
    let too_big = || format!("body larger than {max} bytes");
    if chunked {
        loop {
            let mut line = Vec::new();
            (&mut r)
                .take(256)
                .read_until(b'\n', &mut line)
                .map_err(|e| e.to_string())?;
            let text = String::from_utf8_lossy(&line);
            let size = text.split(';').next().unwrap_or_default().trim();
            let size = usize::from_str_radix(size, 16).map_err(|_| "bad chunk size".to_owned())?;
            if size == 0 {
                // Trailers, up to the blank line (a few: an endless list
                // would hold the thread forever).
                for n in 0.. {
                    if n >= MAX_TRAILERS {
                        return Err(format!("more than {MAX_TRAILERS} trailer lines"));
                    }
                    let mut t = Vec::new();
                    let n = (&mut r)
                        .take(MAX_HEAD as u64)
                        .read_until(b'\n', &mut t)
                        .map_err(|e| e.to_string())?;
                    if n == 0 || t == b"\r\n" || t == b"\n" {
                        break;
                    }
                }
                break;
            }
            if out.body.len().saturating_add(size) > max {
                return Err(too_big());
            }
            let start = out.body.len();
            out.body.resize(start + size, 0);
            r.read_exact(out.body.get_mut(start..).unwrap_or_default())
                .map_err(|e| e.to_string())?;
            let mut crlf = Vec::new();
            (&mut r)
                .take(2)
                .read_until(b'\n', &mut crlf)
                .map_err(|e| e.to_string())?;
        }
    } else if let Some(n) = length {
        if n > max {
            return Err(too_big());
        }
        out.body.resize(n, 0);
        r.read_exact(&mut out.body).map_err(|e| e.to_string())?;
    } else {
        // Until the server closes.
        out.keep_alive = false;
        let n = (&mut r)
            .take(max as u64 + 1)
            .read_to_end(&mut out.body)
            .map_err(|e| e.to_string())?;
        if n > max {
            return Err(too_big());
        }
    }
    Ok(out)
}

/// The router itself, its LANs and link-local: places a list on the
/// Internet has no business sending the router to.
fn inward(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                // RFC 6598 shared space (CGNAT).
                || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => {
            let first = v6.segments().first().copied().unwrap_or(0);
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique local, fe80::/10 link-local.
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
        }
    }
}

/// A redirect from a server at `from` to one at `to` is followed unless it
/// points inward (loopback, LAN, link-local) from outside: an adlist server
/// (or anyone on the path of an `http://` list) must not make the router
/// fetch from its own services. A list that was inside already may move.
fn redirect_ok(from: &[IpAddr], to: &[IpAddr]) -> bool {
    from.iter().any(|ip| inward(*ip)) || !to.iter().any(|ip| inward(*ip))
}

/// GET `url`, following redirects, the body at most `max` bytes. Host
/// names go through `resolve` (the router's resolver).
pub(crate) fn get(
    url: &str,
    verify: bool,
    max: usize,
    timeout: Duration,
    resolve: &dyn Fn(&str) -> Result<Vec<IpAddr>, String>,
) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + timeout;
    let mut url = Url::parse(url)?;
    let mut first: Option<Vec<IpAddr>> = None;
    for _ in 0..=MAX_REDIRECTS {
        let addrs = match url.host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => resolve(&url.host)?,
        };
        match &first {
            None => first = Some(addrs.clone()),
            Some(f) if !redirect_ok(f, &addrs) => {
                return Err(format!("redirect to {} refused: it points inside the router or its LAN", url.host));
            }
            Some(_) => {}
        }
        let mut last = format!("{}: no address", url.host);
        let mut resp = None;
        for ip in addrs.iter().take(4) {
            let attempt = connect(SocketAddr::new(*ip, url.port), url.tls, &url.host, verify, deadline)
                .and_then(|mut s| {
                    exchange(
                        &mut s,
                        "GET",
                        &url,
                        &[("Accept-Encoding", "identity"), ("Connection", "close")],
                        &[],
                        max,
                        deadline,
                    )
                });
            match attempt {
                Ok(r) => {
                    resp = Some(r);
                    break;
                }
                Err(e) => last = e,
            }
        }
        let Some(resp) = resp else {
            return Err(last);
        };
        match resp.status {
            200..=299 => return Ok(resp.body),
            301 | 302 | 303 | 307 | 308 => {
                let to = resp.location.ok_or("redirect without Location")?;
                let next = url.join(&to)?;
                // Never from https down to http.
                if url.tls && !next.tls {
                    return Err("redirect from https to http refused".into());
                }
                url = next;
            }
            s => return Err(format!("HTTP {s}")),
        }
    }
    Err(format!("more than {MAX_REDIRECTS} redirects"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn urls() {
        let u = Url::parse("https://Raw.Example/x/hosts?x=1#frag").unwrap();
        assert_eq!((u.tls, u.host.as_str(), u.port, u.path.as_str()), (true, "raw.example", 443, "/x/hosts?x=1"));
        let u = Url::parse("http://[2001:db8::1]:8080").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("2001:db8::1", 8080, "/"));
        for bad in ["ftp://x/", "https://", "https://u@h/", "http://h:99999/", "http://h/a b"] {
            assert!(Url::parse(bad).is_err(), "{bad}");
        }
        let base = Url::parse("https://a.example/one").unwrap();
        assert_eq!(base.join("/two").unwrap().path, "/two");
        assert_eq!(base.join("//b.example/x").unwrap().host, "b.example");
        assert!(base.join("two").is_err());
    }

    /// Serves `replies` to successive connections on a local port.
    pub(crate) fn serve(replies: Vec<Vec<u8>>) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        thread::spawn(move || {
            for reply in replies {
                let (mut s, _) = l.accept().unwrap();
                let mut buf = [0u8; 4096];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
                let _ = s.write_all(&reply);
            }
        });
        port
    }

    fn no_dns(_: &str) -> Result<Vec<IpAddr>, String> {
        Ok(vec!["127.0.0.1".parse().unwrap()])
    }

    #[test]
    fn get_lengths_chunks_redirects_and_limits() {
        let port = serve(vec![
            b"HTTP/1.1 302 Found\r\nLocation: /real\r\nContent-Length: 0\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;x=y\r\n world\r\n0\r\n\r\n".to_vec(),
        ]);
        let t = Duration::from_secs(5);
        let body = get(&format!("http://lists.test:{port}/start"), true, 100, t, &no_dns).unwrap();
        assert_eq!(body, b"hello world");
        let port = serve(vec![b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world".to_vec()]);
        let err = get(&format!("http://127.0.0.1:{port}/"), true, 5, t, &no_dns).unwrap_err();
        assert!(err.contains("larger than 5"), "{err}");
        let port = serve(vec![b"HTTP/1.0 200 OK\r\n\r\nuntil close".to_vec()]);
        assert_eq!(get(&format!("http://127.0.0.1:{port}/"), true, 100, t, &no_dns).unwrap(), b"until close");
        let port = serve(vec![b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()]);
        assert_eq!(get(&format!("http://127.0.0.1:{port}/"), true, 100, t, &no_dns).unwrap_err(), "HTTP 404");
        let loop_reply = b"HTTP/1.1 301 Moved\r\nLocation: /again\r\nContent-Length: 0\r\n\r\n".to_vec();
        let port = serve(vec![loop_reply; MAX_REDIRECTS + 1]);
        let err = get(&format!("http://127.0.0.1:{port}/"), true, 100, t, &no_dns).unwrap_err();
        assert!(err.contains("redirects"), "{err}");
        let huge = format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD)).into_bytes();
        let port = serve(vec![huge]);
        let err = get(&format!("http://127.0.0.1:{port}/"), true, 100, t, &no_dns).unwrap_err();
        assert!(err.contains("headers longer"), "{err}");
    }

    /// A server that sends a chunked header, then one byte every 200 ms:
    /// the whole exchange still ends at the deadline.
    #[test]
    fn a_slow_server_never_outlives_the_deadline() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1000\r\n");
            for _ in 0..100 {
                if s.write_all(b"x").is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(200));
            }
        });
        let t = std::time::Instant::now();
        let err = get(&format!("http://127.0.0.1:{port}/"), true, 1 << 20, Duration::from_secs(1), &no_dns)
            .unwrap_err();
        assert!(t.elapsed() < Duration::from_millis(1600), "{:?}: {err}", t.elapsed());
    }

    /// Endless trailer lines end the response with an error.
    #[test]
    fn endless_trailers_are_refused() {
        let mut reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n".to_vec();
        for _ in 0..10_000 {
            reply.extend_from_slice(b"X: y\r\n");
        }
        let port = serve(vec![reply]);
        let err = get(&format!("http://127.0.0.1:{port}/"), true, 100, Duration::from_secs(5), &no_dns)
            .unwrap_err();
        assert!(err.contains("trailer"), "{err}");
    }

    /// A redirect from a public server into the router or its LAN is not
    /// followed (the router would fetch from its own namespace).
    #[test]
    fn redirects_inward_are_refused() {
        let public: IpAddr = "198.51.100.7".parse().unwrap();
        let home: IpAddr = "127.0.0.1".parse().unwrap();
        let lan: IpAddr = "192.168.88.1".parse().unwrap();
        assert!(!redirect_ok(&[public], &[home]));
        assert!(!redirect_ok(&[public], &[lan]));
        assert!(!redirect_ok(&[public], &["fe80::1".parse().unwrap()]));
        assert!(!redirect_ok(&[public], &["::ffff:127.0.0.1".parse().unwrap()]));
        assert!(redirect_ok(&[public], &["203.0.113.9".parse().unwrap()]));
        // A list that was inside to begin with may move inside.
        assert!(redirect_ok(&[lan], &[home]));
    }

    /// A TLS server with a self-signed certificate for `localhost`,
    /// answering each connection with `reply`.
    pub(crate) fn serve_tls(reply: Vec<u8>, conns: usize) -> u16 {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert = CertificateDer::from(ck.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
        let config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let config = Arc::new(config);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        thread::spawn(move || {
            for _ in 0..conns {
                let Ok((tcp, _)) = l.accept() else { return };
                let conn = rustls::ServerConnection::new(config.clone()).unwrap();
                let mut s = StreamOwned::new(conn, tcp);
                let mut buf = [0u8; 4096];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = s.write_all(&reply);
                let _ = s.flush();
                s.conn.send_close_notify();
                let _ = s.conn.complete_io(&mut s.sock);
            }
        });
        port
    }

    #[test]
    fn tls_with_and_without_verification() {
        let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
        let port = serve_tls(reply, 2);
        let t = Duration::from_secs(5);
        let url = format!("https://localhost:{port}/list");
        let err = get(&url, true, 100, t, &no_dns).unwrap_err();
        assert!(err.contains("TLS") && err.to_lowercase().contains("cert"), "{err}");
        assert_eq!(get(&url, false, 100, t, &no_dns).unwrap(), b"ok", "ssl_verify=no");
    }
}
