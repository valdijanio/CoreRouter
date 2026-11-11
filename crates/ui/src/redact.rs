//! What the GUI's log and status bar show of a command's result: secrets
//! (a TSIG key's `secret`, G4.1c-3; a password; a private key; a Wi-Fi
//! passphrase, G1.30) replaced, so
//! they never stay on screen or in the log history. A window that needs
//! the value (Show Secret) gets it from the reply itself, not the log.

use serde_json::Value;

const WORDS: [&str; 5] = ["secret", "password", "private", "token", "passphrase"];

/// `v` with every value under a secret-looking key replaced.
pub(crate) fn redacted(v: &Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, val)| {
                    let hide = WORDS.iter().any(|w| k.contains(w)) && !val.is_null();
                    let shown = if hide { Value::String("•••".into()) } else { redacted(val) };
                    (k.clone(), shown)
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(redacted).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn secrets_are_hidden_everywhere() {
        let v = json!([{"name": "ddns", "secret": "AAAA", "zones": ["x"]}, {"inner": {"password_hash": "h"}}]);
        assert_eq!(
            redacted(&v),
            json!([{"name": "ddns", "secret": "•••", "zones": ["x"]}, {"inner": {"password_hash": "•••"}}])
        );
        let wifi = json!({"name": "wifi1", "ssid": "Casa", "passphrase": "uma-senha-qualquer"});
        assert_eq!(redacted(&wifi), json!({"name": "wifi1", "ssid": "Casa", "passphrase": "•••"}));
    }
}
