//! English explanations of System › Certificates (G1.6zs), scope `certificates`, sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    ("certificates.certificate", "## Certificate\n\nThe certificate as PEM (`-----BEGIN CERTIFICATE-----`), then the rest of its chain (the intermediates), as a CA or `certbot` hands them out (`fullchain.pem`). The router sends the whole chain, so clients need nothing else."),
    ("certificates.common_name", "## Common Name\n\nThe CN of the subject. Blank: the router's identity. Clients do not match names against it (RFC 6125, RFC 8310 §8.1): the names that count are the **Subject Alt Names**."),
    ("certificates.days_valid", "## Days Valid\n\nHow long the certificate lasts, counted from the day before today (a client whose clock is a little behind still accepts it). Default 825: Apple devices refuse TLS server certificates valid for longer. RouterOS defaults to 365."),
    ("certificates.expires", "## Expires\n\nThe last day it is valid and the days left. **expiring**: under 30 days; **expired**: clients that check it refuse it."),
    ("certificates.import", "## Import Certificate\n\nBrings a certificate made elsewhere (a CA, Let's Encrypt, your company PKI): paste the PEM of the certificate with its chain and the PEM of its private key (not encrypted: PKCS#8, RSA or EC). The router checks that the key belongs to the certificate before saving. Without a key it is kept, but no service can serve with it."),
    ("certificates.key_type", "## Key Type\n\nThe key made for it: **ecdsa-p256** (default, the fastest handshake: ~0.1 ms of CPU, measured) or **ecdsa-p384**. RSA keys are not made here (import one): a handshake with RSA-2048 costs about 5 times more CPU."),
    ("certificates.name", "## Name\n\nHow services name it (`certificate=<name>`): letters, digits, `-`, `_`, `.`. A rename follows into the services that use it."),
    ("certificates.private_key", "## Private Key\n\nThe PEM of the certificate's private key. It is stored sealed (encrypted with a key kept outside the config): no copy of the config, revision or export shows it, and only group `full` can export it."),
    ("certificates.state", "## State\n\n**valid**; **expiring** (under 30 days); **expired**; **not-yet-valid** (check the router's clock); **invalid** (the stored PEM cannot be read). The chip **self-signed** marks a certificate no CA vouches for; **no key**, one without its private key."),
    ("certificates.subject_alt_name", "## Subject Alt Names\n\nThe names and addresses clients accept it for: `DNS:router.lan`, `IP:192.168.88.1`, comma-separated (a bare name or address takes its prefix). Blank: the router's identity and every address it has now; they are not remade when an address changes.\n\n## Careful\nA client that reaches the router by IP needs that IP here (RFC 9462 §4.2, how Windows and iOS discover encrypted DNS)."),
    ("certificates.used_by", "## Used By\n\nThe services that serve with it. A certificate in use cannot be removed: pick another one in the service first."),
];
