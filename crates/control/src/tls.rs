//! TLS for the control channel and the WebSocket (G0.3): `rustls` with the
//! `ring` provider, no OpenSSL.
//!
//! The router makes its own self-signed certificate the first time
//! ([`load_or_create`]: `tls-cert.pem`, and `tls-key.pem` with mode 0600, in
//! the config directory). There is no CA to check it against, so clients
//! pin it the SSH way: the first connection shows its SHA-256
//! [`fingerprint`] and asks; [`crate::known_hosts`] remembers the answer;
//! a different certificate later is refused ([`connect`] fails before a
//! single byte of the login is sent). Signatures in the handshake are
//! still verified, so a man in the middle cannot reuse a pinned
//! certificate without its key.

use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ring::digest::{SHA256, digest};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, ServerConfig,
    ServerConnection, SignatureScheme, StreamOwned,
};

pub const CERT_FILE: &str = "tls-cert.pem";
pub const KEY_FILE: &str = "tls-key.pem";
/// Longest PEM file read.
const MAX_PEM: u64 = 64 * 1024;
/// Time a peer gets to finish the TLS handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Name sent in SNI. Clients pin the certificate, so it is not checked.
const SERVER_NAME: &str = "corerouter";

pub type ServerStream = StreamOwned<ServerConnection, TcpStream>;
pub type ClientStream = StreamOwned<ClientConnection, TcpStream>;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// `SHA256:AB:CD:…` of a DER certificate, as browsers show it.
pub fn fingerprint(der: &[u8]) -> String {
    let hex: Vec<String> = digest(&SHA256, der)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    format!("SHA256:{}", hex.join(":"))
}

/// The router's TLS identity.
#[derive(Clone)]
pub struct ServerIdentity {
    pub config: Arc<ServerConfig>,
    pub fingerprint: String,
}

impl std::fmt::Debug for ServerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerIdentity")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    fs::File::open(path)?.take(MAX_PEM).read_to_end(&mut out)?;
    Ok(out)
}

/// Load the certificate and key from `dir`, or make and save new ones.
/// Returns the identity and whether it was just created.
pub fn load_or_create(dir: &Path) -> Result<(ServerIdentity, bool), String> {
    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);
    let created = !(cert_path.exists() && key_path.exists());
    if created {
        let (cert_pem, key_pem) = generate()?;
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        write_private(&key_path, key_pem.as_bytes())
            .map_err(|e| format!("{}: {e}", key_path.display()))?;
        fs::write(&cert_path, cert_pem).map_err(|e| format!("{}: {e}", cert_path.display()))?;
    }
    let cert = read_bounded(&cert_path).map_err(|e| format!("{}: {e}", cert_path.display()))?;
    let key = read_bounded(&key_path).map_err(|e| format!("{}: {e}", key_path.display()))?;
    Ok((identity_from_pem(&cert, &key)?, created))
}

/// A new self-signed certificate and its key, as PEM.
pub fn generate() -> Result<(String, String), String> {
    let names = vec![SERVER_NAME.to_owned(), "localhost".to_owned()];
    let ck = rcgen::generate_simple_self_signed(names).map_err(|e| format!("certificate: {e}"))?;
    Ok((ck.cert.pem(), ck.signing_key.serialize_pem()))
}

/// Server identity from PEM bytes.
pub fn identity_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<ServerIdentity, String> {
    let cert = CertificateDer::from_pem_slice(cert_pem).map_err(|e| format!("certificate: {e}"))?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| format!("private key: {e}"))?;
    let fingerprint = fingerprint(cert.as_ref());
    let config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| format!("certificate/key: {e}"))?;
    Ok(ServerIdentity {
        config: Arc::new(config),
        fingerprint,
    })
}

fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

/// Run the server side of the handshake on an accepted connection.
pub fn accept(tcp: TcpStream, config: Arc<ServerConfig>) -> io::Result<ServerStream> {
    tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    tcp.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let conn = ServerConnection::new(config).map_err(io::Error::other)?;
    let mut s = StreamOwned::new(conn, tcp);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock)?;
    }
    s.sock.set_read_timeout(None)?;
    s.sock.set_write_timeout(None)?;
    Ok(s)
}

/// Accepts any certificate, remembers its fingerprint, and refuses it when
/// it is not the `expected` one.
#[derive(Debug)]
struct Pinning {
    expected: Option<String>,
    seen: Mutex<Option<String>>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Pinning {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp = fingerprint(end_entity.as_ref());
        let ok = self.expected.as_ref().is_none_or(|e| *e == fp);
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = Some(fp);
        if ok {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
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

/// Why a TLS connection was not made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    /// The router shows another certificate than the one remembered.
    Changed {
        expected: String,
        seen: String,
    },
    Other(String),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Changed { expected, seen } => write!(
                f,
                "REFUSED: the router's TLS certificate CHANGED. Remembered {expected}, \
                 now {seen}. Someone may be intercepting the connection, or the router \
                 was reinstalled. If you know why it changed, remove its line from the \
                 known hosts file and connect again."
            ),
            Self::Other(e) => f.write_str(e),
        }
    }
}

/// Client side of the handshake over `tcp`, pinned to `expected` (or to
/// whatever the router shows when `None`). Returns the stream and the
/// fingerprint seen.
pub fn connect(tcp: TcpStream, expected: Option<&str>) -> Result<(ClientStream, String), TlsError> {
    let other = |e: &dyn std::fmt::Display| TlsError::Other(format!("TLS: {e}"));
    let provider = provider();
    let pin = Arc::new(Pinning {
        expected: expected.map(str::to_owned),
        seen: Mutex::new(None),
        algs: provider.signature_verification_algorithms,
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| other(&e))?
        .dangerous()
        .with_custom_certificate_verifier(pin.clone())
        .with_no_client_auth();
    let name = ServerName::try_from(SERVER_NAME).map_err(|e| other(&e))?;
    let conn = ClientConnection::new(Arc::new(config), name).map_err(|e| other(&e))?;
    let mut s = StreamOwned::new(conn, tcp);
    let seen = || {
        pin.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    };
    while s.conn.is_handshaking() {
        if let Err(e) = s.conn.complete_io(&mut s.sock) {
            return Err(match (expected, seen()) {
                (Some(want), Some(got)) if want != got => TlsError::Changed {
                    expected: want.to_owned(),
                    seen: got,
                },
                _ => other(&e),
            });
        }
    }
    let fp = seen().ok_or_else(|| TlsError::Other("TLS: the router sent no certificate".into()))?;
    Ok((s, fp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn echo_server(id: &ServerIdentity) -> std::net::SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let cfg = id.config.clone();
        thread::spawn(move || {
            for c in l.incoming() {
                let cfg = cfg.clone();
                thread::spawn(move || {
                    if let Ok(mut s) = accept(c.unwrap(), cfg) {
                        let mut b = [0u8; 5];
                        if s.read_exact(&mut b).is_ok() {
                            let _ = s.write_all(&b);
                            let _ = s.flush();
                        }
                    }
                });
            }
        });
        addr
    }

    #[test]
    fn pinned_handshake_end_to_end() {
        let (cert, key) = generate().unwrap();
        let id = identity_from_pem(cert.as_bytes(), key.as_bytes()).unwrap();
        assert!(id.fingerprint.starts_with("SHA256:") && id.fingerprint.len() == 7 + 95);
        let addr = echo_server(&id);

        // First time: whatever the router shows, and we learn it.
        let (mut s, fp) = connect(TcpStream::connect(addr).unwrap(), None).unwrap();
        assert_eq!(fp, id.fingerprint);
        s.write_all(b"hello").unwrap();
        let mut b = [0u8; 5];
        s.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"hello");

        // Same certificate: fine.
        assert!(connect(TcpStream::connect(addr).unwrap(), Some(&fp)).is_ok());

        // Another one: refused, with both fingerprints.
        let wrong = "SHA256:00".to_owned();
        match connect(TcpStream::connect(addr).unwrap(), Some(&wrong)) {
            Err(TlsError::Changed { expected, seen }) => {
                assert_eq!((expected, seen), (wrong, fp));
            }
            other => panic!("expected Changed, got {:?}", other.map(|(_, f)| f)),
        }
    }

    #[test]
    fn files_are_created_once_and_key_is_private() {
        let dir = std::env::temp_dir().join(format!("cr-tls-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (a, created) = load_or_create(&dir).unwrap();
        assert!(created);
        let (b, created) = load_or_create(&dir).unwrap();
        assert!(!created);
        assert_eq!(a.fingerprint, b.fingerprint);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join(KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::write(dir.join(CERT_FILE), "junk").unwrap();
        assert!(load_or_create(&dir).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
