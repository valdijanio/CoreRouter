//! Juniper (ERX, vendor 4874) service activation, parse only.
//!
//! Juniper BNGs take `ERX-Service-Activate` (type 65, tagged) and
//! `ERX-Service-Deactivate` (66) with a service name and optional
//! parameters: `svc-rate(10m,20m)`. The tag orders several activations
//! (one per service session). Billing systems built for Juniper send these;
//! G4.3d maps them to a CoreRouter profile.

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceActivation<'a> {
    pub name: &'a str,
    pub args: Vec<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ServiceError {
    #[error("empty service name")]
    EmptyName,
    #[error("service name has characters other than letters, digits, '-', '_' and '.'")]
    BadName,
    #[error("parameter list is not closed with ')'")]
    Unclosed,
    #[error("more than 16 parameters")]
    TooManyArgs,
}

/// Parse `name` or `name(arg,arg,…)`. Spaces around arguments are trimmed.
pub fn parse_service(s: &str) -> Result<ServiceActivation<'_>, ServiceError> {
    let s = s.trim();
    let (name, args) = match s.split_once('(') {
        None => (s, Vec::new()),
        Some((name, rest)) => {
            let inner = rest.strip_suffix(')').ok_or(ServiceError::Unclosed)?;
            let args: Vec<&str> = if inner.trim().is_empty() {
                Vec::new()
            } else {
                inner.split(',').map(str::trim).collect()
            };
            if args.len() > 16 {
                return Err(ServiceError::TooManyArgs);
            }
            (name.trim(), args)
        }
    };
    if name.is_empty() {
        return Err(ServiceError::EmptyName);
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(ServiceError::BadName);
    }
    Ok(ServiceActivation { name, args })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_names_and_arguments() {
        let s = parse_service("svc-rate(10m, 20m)").unwrap();
        assert_eq!((s.name, s.args), ("svc-rate", vec!["10m", "20m"]));
        assert_eq!(parse_service("gold").unwrap().args, Vec::<&str>::new());
        assert_eq!(parse_service("x()").unwrap().args, Vec::<&str>::new());
        assert_eq!(parse_service("x(1"), Err(ServiceError::Unclosed));
        assert_eq!(parse_service("(1)"), Err(ServiceError::EmptyName));
        assert_eq!(parse_service("a b"), Err(ServiceError::BadName));
    }

    proptest! {
        #[test]
        fn never_panics(s in "\\PC{0,200}") {
            let _ = parse_service(&s);
        }
    }
}
