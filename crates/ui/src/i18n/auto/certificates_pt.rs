//! Portuguese labels and explanations of System › Certificates (G1.6zs), sorted by key.

/// Labels: (English, Portuguese).
pub(super) const LABELS: &[(&str, &str)] = &[
    ("Add Certificate…", "Adicionar certificado…"),
    ("Certificates", "Certificados"),
    ("Common Name", "Nome comum"),
    ("Copy PEM", "Copiar PEM"),
    ("Expires", "Vence"),
    ("Fingerprint", "Impressão digital"),
    ("Import…", "Importar…"),
    ("Issuer", "Emissor"),
    ("Key", "Chave"),
    ("Name", "Nome"),
    ("No certificates. + makes a self-signed one; Import… takes yours (PEM).", "Nenhum certificado. + faz um autoassinado; Importar… recebe o seu (PEM)."),
    ("SPKI Pin (SHA-256)", "Pin SPKI (SHA-256)"),
    ("Select a certificate to see its fingerprint and pin.", "Selecione um certificado para ver a impressão digital e o pin."),
    ("Serial", "Série"),
    ("State", "Estado"),
    ("Subject Alt Names", "Nomes alternativos"),
    ("Used By", "Usado por"),
    ("Valid From", "Válido desde"),
    ("copied (PEM, without the key)", "copiado (PEM, sem a chave)"),
    ("expired", "vencido"),
    ("expiring", "vencendo"),
    ("invalid", "inválido"),
    ("no key", "sem chave"),
    ("not-yet-valid", "ainda não vale"),
    ("self-signed", "autoassinado"),
    ("valid", "válido"),
    ("warning", "aviso"),
];

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    ("certificates.certificate", "## Certificado\n\nO certificado em PEM (`-----BEGIN CERTIFICATE-----`) e depois o resto da cadeia (os intermediários), como a CA ou o `certbot` entregam (`fullchain.pem`). O roteador manda a cadeia inteira, então o cliente não precisa de mais nada."),
    ("certificates.common_name", "## Nome comum\n\nO CN do sujeito. Em branco: a identidade do roteador. Os clientes não conferem nomes nele (RFC 6125, RFC 8310 §8.1): os nomes que valem são os **Subject Alt Names**."),
    ("certificates.days_valid", "## Dias de validade\n\nQuanto o certificado dura, contado a partir de ontem (um cliente com o relógio um pouco atrasado ainda o aceita). Padrão 825: os aparelhos Apple recusam certificado de servidor TLS válido por mais tempo. O RouterOS usa 365."),
    ("certificates.expires", "## Vence\n\nO último dia em que vale e os dias que faltam. **expiring**: menos de 30 dias; **expired**: os clientes que conferem o recusam."),
    ("certificates.import", "## Importar certificado\n\nTraz um certificado feito fora (uma CA, o Let's Encrypt, a PKI da empresa): cole o PEM do certificado com a cadeia e o PEM da chave privada (sem senha: PKCS#8, RSA ou EC). O roteador confere que a chave é desse certificado antes de gravar. Sem chave ele fica guardado, mas nenhum serviço atende com ele."),
    ("certificates.key_type", "## Tipo de chave\n\nA chave feita para ele: **ecdsa-p256** (padrão, o handshake mais rápido: ~0,1 ms de CPU, medido) ou **ecdsa-p384**. Chave RSA não se faz aqui (importe uma): um handshake com RSA-2048 gasta umas 5 vezes mais CPU."),
    ("certificates.name", "## Nome\n\nComo os serviços o chamam (`certificate=<nome>`): letras, dígitos, `-`, `_`, `.`. Renomear leva o nome novo aos serviços que o usam."),
    ("certificates.private_key", "## Chave privada\n\nO PEM da chave privada do certificado. Fica selada (cifrada com uma chave guardada fora da config): nenhuma cópia da config, revisão ou export a mostra, e só o grupo `full` a exporta."),
    ("certificates.state", "## Estado\n\n**valid**; **expiring** (menos de 30 dias); **expired**; **not-yet-valid** (confira o relógio do roteador); **invalid** (o PEM guardado não se lê). O selo **self-signed** marca um certificado que nenhuma CA assina; **no key**, um sem a chave privada."),
    ("certificates.subject_alt_name", "## Nomes alternativos\n\nOs nomes e endereços para os quais o cliente o aceita: `DNS:router.lan`, `IP:192.168.88.1`, separados por vírgula (nome ou endereço sem prefixo ganha o seu). Em branco: a identidade do roteador e todos os endereços que ele tem agora; não são refeitos quando um endereço muda.\n\n## Cuidado\nUm cliente que chega ao roteador pelo IP precisa desse IP aqui (RFC 9462 §4.2, como o Windows e o iOS descobrem o DNS cifrado)."),
    ("certificates.used_by", "## Usado por\n\nOs serviços que atendem com ele. Um certificado em uso não se remove: escolha outro no serviço antes."),
];
