//! X.509 for `/certificate` (G1.6zs): read what a PEM certificate says
//! (names, validity, key, fingerprints), make a self-signed one, and check a
//! private key against its certificate the way the TLS servers load them.
//!
//! Reading is pure Rust (`x509-parser`) and works in the browser lab too;
//! making keys and checking them use `rcgen`/`rustls` with `ring`, which the
//! browser lab does not build (no random source there either): those return
//! an error in wasm32.
//!
//! The input is hostile (an imported PEM): sizes are bounded before parsing
//! (`corerouter_model::certificate`), errors quote at most a few bytes of it.

use base64::Engine as _;
use corerouter_model::certificate::{MAX_CHAIN, MAX_KEY_BYTES, MAX_PEM_BYTES};
use sha2::{Digest, Sha256};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::pem::Pem;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

/// What the services' clients look at, read from the first certificate of
/// the PEM (the rest is its chain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub common_name: String,
    pub issuer: String,
    /// Issued by itself (subject = issuer).
    pub self_signed: bool,
    /// A CA certificate (basicConstraints CA:TRUE).
    pub ca: bool,
    /// `DNS:router.lan`, `IP:192.168.88.1`, `email:…`, as RouterOS writes them.
    pub subject_alt_names: Vec<String>,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    /// `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `ed25519`…
    pub key_type: String,
    /// `SHA256:AB:CD:…` of the DER certificate, as browsers show it.
    pub fingerprint: String,
    /// Base64 SHA-256 of the SubjectPublicKeyInfo: the pin of RFC 7858 §4.2
    /// (and HPKP's `pin-sha256`), what a DoT client configures.
    pub spki_pin: String,
    pub serial: String,
    /// Certificates in the PEM (1 = no chain).
    pub chain: usize,
}

fn quote(text: &str) -> String {
    text.chars().take(40).collect()
}

/// The DER certificates of a PEM, in order. Other blocks (a key pasted in
/// the same box) are an error, not ignored: the operator meant something.
pub fn ders(pem: &str) -> Result<Vec<Vec<u8>>, String> {
    if pem.len() > MAX_PEM_BYTES {
        return Err(format!("certificate: over {MAX_PEM_BYTES} bytes"));
    }
    if !pem.contains("-----BEGIN ") {
        let shown = quote(pem.trim());
        return Err(format!("certificate: no '-----BEGIN CERTIFICATE-----' block in '{shown}'"));
    }
    let mut out = Vec::new();
    for block in Pem::iter_from_buffer(pem.as_bytes()) {
        let block = block.map_err(|e| format!("certificate: not PEM ({e})"))?;
        if block.label != "CERTIFICATE" {
            return Err(format!(
                "certificate: a '{}' block where a CERTIFICATE was expected (the key goes in private_key)",
                quote(&block.label)
            ));
        }
        out.push(block.contents);
        if out.len() > MAX_CHAIN {
            return Err(format!("certificate: more than {MAX_CHAIN} certificates in the chain"));
        }
    }
    if out.is_empty() {
        let shown = quote(pem.trim());
        return Err(format!(
            "certificate: no '-----BEGIN CERTIFICATE-----' block in '{shown}'"
        ));
    }
    Ok(out)
}

fn hex_colons(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

fn key_type(cert: &X509Certificate<'_>) -> String {
    let spki = &cert.tbs_certificate.subject_pki;
    match spki.parsed() {
        Ok(PublicKey::RSA(k)) => format!("rsa-{}", k.key_size()),
        Ok(PublicKey::EC(_)) => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|o| o.to_id_string())
                .unwrap_or_default();
            match curve.as_str() {
                "1.2.840.10045.3.1.7" => "ecdsa-p256".into(),
                "1.3.132.0.34" => "ecdsa-p384".into(),
                "1.3.132.0.35" => "ecdsa-p521".into(),
                _ => "ecdsa".into(),
            }
        }
        _ => match spki.algorithm.algorithm.to_id_string().as_str() {
            "1.3.101.112" => "ed25519".into(),
            "1.3.101.113" => "ed448".into(),
            other => other.to_owned(),
        },
    }
}

fn first_cn(name: &x509_parser::x509::X509Name<'_>) -> String {
    name.iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| name.to_string())
}

/// What the first certificate of `pem` says.
pub fn inspect(pem: &str) -> Result<Info, String> {
    let chain = ders(pem)?;
    let der = chain.first().ok_or("certificate: empty")?;
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| format!("certificate: not X.509 ({e})"))?;
    let mut sans = Vec::new();
    let mut ca = false;
    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                for n in &san.general_names {
                    match n {
                        GeneralName::DNSName(d) => sans.push(format!("DNS:{d}")),
                        GeneralName::RFC822Name(m) => sans.push(format!("email:{m}")),
                        GeneralName::IPAddress(b) => {
                            let ip = match b.len() {
                                4 => <[u8; 4]>::try_from(*b).ok().map(std::net::IpAddr::from),
                                16 => <[u8; 16]>::try_from(*b).ok().map(std::net::IpAddr::from),
                                _ => None,
                            };
                            if let Some(ip) = ip {
                                sans.push(format!("IP:{ip}"));
                            }
                        }
                        _ => {}
                    }
                }
            }
            ParsedExtension::BasicConstraints(bc) => ca = bc.ca,
            _ => {}
        }
    }
    let subject = &cert.tbs_certificate.subject;
    let issuer = &cert.tbs_certificate.issuer;
    // Subject = issuer is what a client sees: no CA vouches for it.
    let self_signed = subject == issuer;
    let spki_der = cert.tbs_certificate.subject_pki.raw;
    Ok(Info {
        common_name: first_cn(subject),
        issuer: first_cn(issuer),
        self_signed,
        ca,
        subject_alt_names: sans,
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        key_type: key_type(&cert),
        fingerprint: format!("SHA256:{}", hex_colons(&Sha256::digest(der))),
        spki_pin: base64::engine::general_purpose::STANDARD.encode(Sha256::digest(spki_der)),
        serial: cert.tbs_certificate.raw_serial_as_string(),
        chain: chain.len(),
    })
}

impl Info {
    /// Whether a client asking for `name` (a host name or an IP literal)
    /// accepts this certificate: RFC 6125 §6.4 for names (one `*` only as
    /// the whole leftmost label), an exact iPAddress entry for an address
    /// (RFC 9462 §4.2: the IP must be in subjectAltName, never the CN).
    pub fn covers(&self, name: &str) -> bool {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Ok(ip) = name.parse::<std::net::IpAddr>() {
            return self.subject_alt_names.iter().any(|s| {
                s.strip_prefix("IP:")
                    .and_then(|t| t.parse::<std::net::IpAddr>().ok())
                    .is_some_and(|a| a.to_canonical() == ip.to_canonical())
            });
        }
        self.subject_alt_names.iter().filter_map(|s| s.strip_prefix("DNS:")).any(|d| {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            match d.strip_prefix("*.") {
                Some(rest) => name
                    .split_once('.')
                    .is_some_and(|(label, parent)| !label.is_empty() && parent == rest),
                None => d == name,
            }
        })
    }
}

/// What `certificate.add` makes.
#[derive(Debug, Clone)]
pub struct NewCert {
    pub common_name: String,
    /// `DNS:` and `IP:` entries.
    pub subject_alt_names: Vec<String>,
    /// `ecdsa-p256` or `ecdsa-p384`.
    pub key_type: String,
    pub days_valid: u32,
    /// Now, unix seconds (the engine's clock, `Hal::now_unix`).
    pub now: u64,
}

/// Year, month, day of a day count since 1970-01-01 (H. Hinnant's
/// `civil_from_days`, proleptic Gregorian).
fn civil(days: i64) -> (i32, u8, u8) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (
        i32::try_from(y).unwrap_or(9999),
        u8::try_from(m).unwrap_or(1),
        u8::try_from(d).unwrap_or(1),
    )
}

/// Year, month, day of unix time `t` (UTC).
pub fn civil_day(t: i64) -> (i32, u8, u8) {
    civil(t.div_euclid(86_400))
}

/// A self-signed server certificate and its PKCS#8 key, both PEM.
///
/// - valid from the day before `now` (a client whose clock is behind still
///   accepts it) for `days_valid` days;
/// - a random 128-bit serial: browsers refuse a second certificate with
///   the same issuer and serial (Firefox `SEC_ERROR_REUSED_ISSUER_AND_SERIAL`),
///   which a router that makes several with its identity as CN would hit;
/// - a server certificate, not a CA (basicConstraints CA:FALSE, key usage
///   digitalSignature, extended key usage serverAuth), as the daemon's own.
#[cfg(not(target_arch = "wasm32"))]
pub fn generate(n: &NewCert) -> Result<(String, String), String> {
    use rcgen::{DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType};
    let err = |e: rcgen::Error| format!("certificate: {e}");
    let alg = match n.key_type.as_str() {
        "ecdsa-p256" => &rcgen::PKCS_ECDSA_P256_SHA256,
        "ecdsa-p384" => &rcgen::PKCS_ECDSA_P384_SHA384,
        other => return Err(format!("key_type: '{}' cannot be made here", quote(other))),
    };
    let mut params = rcgen::CertificateParams::default();
    for s in &n.subject_alt_names {
        let san = if let Some(ip) = s.strip_prefix("IP:") {
            SanType::IpAddress(ip.parse().map_err(|_| format!("subject_alt_name: '{}' is not an address", quote(ip)))?)
        } else if let Some(d) = s.strip_prefix("DNS:") {
            SanType::DnsName(d.to_owned().try_into().map_err(err)?)
        } else {
            return Err(format!("subject_alt_name: '{}' needs DNS: or IP:", quote(s)));
        };
        params.subject_alt_names.push(san);
    }
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, n.common_name.clone());
    let today = i64::try_from(n.now / 86_400).unwrap_or(0);
    let (y, m, d) = civil(today - 1);
    params.not_before = rcgen::date_time_ymd(y, m, d);
    let (y, m, d) = civil(today + i64::from(n.days_valid));
    params.not_after = rcgen::date_time_ymd(y, m, d);
    let mut serial = [0u8; 16];
    crate::auth::random_bytes(&mut serial)?;
    // A positive INTEGER (RFC 5280 §4.1.2.2): the top bit clear.
    if let Some(b) = serial.first_mut() {
        *b &= 0x7f;
    }
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate_for(alg).map_err(err)?;
    let cert = params.self_signed(&key).map_err(err)?;
    Ok((cert.pem(), key.serialize_pem()))
}

#[cfg(target_arch = "wasm32")]
pub fn generate(_: &NewCert) -> Result<(String, String), String> {
    Err("certificates cannot be made in the browser lab (no random source)".into())
}

/// Checks that `key_pem` is a private key rustls serves with (PKCS#8,
/// PKCS#1 RSA or SEC1 EC; RSA, ECDSA P-256/P-384, Ed25519) and that it
/// belongs to the first certificate of `cert_pem`, the way the TLS servers
/// load them. The key text is never quoted in an error.
#[cfg(not(target_arch = "wasm32"))]
pub fn check_pair(cert_pem: &str, key_pem: &str) -> Result<(), String> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    if key_pem.len() > MAX_KEY_BYTES {
        return Err(format!("private_key: over {MAX_KEY_BYTES} bytes"));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|_| {
        "private_key: no PEM private key (BEGIN PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY; an encrypted key must be decrypted first)".to_owned()
    })?;
    let signer = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| format!("private_key: not a key TLS can use ({e})"))?;
    let chain: Vec<CertificateDer<'static>> =
        ders(cert_pem)?.into_iter().map(CertificateDer::from).collect();
    rustls::sign::CertifiedKey::new(chain, signer)
        .keys_match()
        .map_err(|e| match e {
            rustls::Error::InconsistentKeys(_) => {
                "private_key: it is not the key of this certificate".to_owned()
            }
            other => format!("certificate: {other}"),
        })
}

#[cfg(target_arch = "wasm32")]
pub fn check_pair(cert_pem: &str, key_pem: &str) -> Result<(), String> {
    // The browser lab reads but does not load keys: bounds only.
    ders(cert_pem)?;
    if key_pem.len() > MAX_KEY_BYTES {
        return Err(format!("private_key: over {MAX_KEY_BYTES} bytes"));
    }
    Ok(())
}

/// The certificate and key a service serves with, from the **running**
/// config (what the daemon follows): `None` when `name` is empty (the
/// router's own).
pub fn served(s: &mut crate::Session, name: &str) -> std::result::Result<Option<(String, String)>, String> {
    if name.is_empty() {
        return Ok(None);
    }
    let Some(c) = s.store().running().system.certificates.get(name).cloned() else {
        return Err(format!("certificate {name} is not in /certificate"));
    };
    let k = crate::sealing::key(s)?;
    let key = k.open(&c.private_key).ok_or_else(|| format!("certificate {name} has no private key"))?;
    Ok(Some((c.certificate, key)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(sans: &[&str]) -> (String, String) {
        generate(&NewCert {
            common_name: "router.lan".into(),
            subject_alt_names: sans.iter().map(|s| (*s).to_owned()).collect(),
            key_type: "ecdsa-p256".into(),
            days_valid: 825,
            now: 1_794_441_600, // 2026-11-12
        })
        .unwrap()
    }

    #[test]
    fn a_generated_certificate_reads_back() {
        let (cert, key) = make(&["DNS:router.lan", "IP:192.168.88.1", "IP:fd00::1"]);
        let i = inspect(&cert).unwrap();
        assert_eq!(i.common_name, "router.lan");
        assert!(i.self_signed);
        assert!(!i.ca);
        assert_eq!(i.key_type, "ecdsa-p256");
        assert_eq!(i.subject_alt_names, ["DNS:router.lan", "IP:192.168.88.1", "IP:fd00::1"]);
        // The day before, for 825 days.
        assert_eq!(i.not_before, 1_794_441_600 - 86_400);
        assert_eq!(i.not_after, 1_794_441_600 + 825 * 86_400);
        assert!(i.fingerprint.starts_with("SHA256:") && i.fingerprint.len() == 7 + 32 * 3 - 1);
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(&i.spki_pin).unwrap().len(), 32);
        assert_eq!(i.chain, 1);
        check_pair(&cert, &key).unwrap();
        assert!(i.covers("router.lan") && i.covers("ROUTER.LAN.") && i.covers("192.168.88.1"));
        assert!(!i.covers("192.168.88.2") && !i.covers("other.lan"));
        // Two certificates never share a serial.
        let (other, _) = make(&["DNS:router.lan"]);
        assert_ne!(inspect(&other).unwrap().serial, i.serial);
    }

    #[test]
    fn a_key_of_another_certificate_is_refused() {
        let (cert, _) = make(&["DNS:a.lan"]);
        let (_, other_key) = make(&["DNS:a.lan"]);
        let e = check_pair(&cert, &other_key).unwrap_err();
        assert!(e.contains("not the key of this certificate"), "{e}");
        let e = check_pair(&cert, "garbage").unwrap_err();
        assert!(e.starts_with("private_key:"), "{e}");
    }

    #[test]
    fn wildcards_cover_one_label() {
        let i = Info {
            common_name: String::new(),
            issuer: String::new(),
            self_signed: false,
            ca: false,
            subject_alt_names: vec!["DNS:*.example.net".into()],
            not_before: 0,
            not_after: 0,
            key_type: String::new(),
            fingerprint: String::new(),
            spki_pin: String::new(),
            serial: String::new(),
            chain: 1,
        };
        assert!(i.covers("dns.example.net"));
        assert!(!i.covers("example.net") && !i.covers("a.b.example.net"));
    }

    #[test]
    fn bad_pem_is_an_error_that_quotes_little() {
        assert!(inspect("").is_err());
        let e = inspect(&"x".repeat(200)).unwrap_err();
        assert!(e.len() < 120, "{e}");
        let (_, key) = make(&["DNS:a.lan"]);
        let e = inspect(&key).unwrap_err();
        assert!(e.contains("PRIVATE KEY"), "{e}");
        let junk = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert!(inspect(junk).is_err());
        assert!(inspect(&"a".repeat(MAX_PEM_BYTES + 1)).unwrap_err().contains("over"));
    }

    #[test]
    fn days_convert_like_the_calendar() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(20_769), (2026, 11, 12));
        assert_eq!(civil(11_016), (2000, 2, 29));
        assert_eq!(civil(-1), (1969, 12, 31));
    }

    proptest::proptest! {
        /// Hostile input (an imported PEM) never panics the parser.
        #[test]
        fn any_text_is_an_answer_not_a_panic(s in ".{0,400}", body in proptest::collection::vec(proptest::num::u8::ANY, 0..600)) {
            let _ = inspect(&s);
            let b64 = base64::engine::general_purpose::STANDARD.encode(&body);
            let pem = format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n");
            let _ = inspect(&pem);
            let _ = check_pair(&pem, &s);
        }
    }
}
