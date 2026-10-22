use corerouter_model::{Issue, StoreError};

/// Every message is written for a human *and* an agent: it says what went
/// wrong and, where possible, what to do next.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum EngineError {
    #[error("unknown command '{id}'{}; see list_commands", hint(.suggestion))]
    UnknownCommand {
        id: String,
        suggestion: Option<String>,
    },
    #[error("command '{id}' is disabled: {reason}")]
    Disabled { id: String, reason: String },
    #[error("unknown parameter '{param}'{}", hint(.suggestion))]
    UnknownParam {
        param: String,
        suggestion: Option<String>,
    },
    #[error("parameter '{param}': {reason}")]
    BadParam { param: String, reason: String },
    #[error("validation failed: {}", join(.0))]
    Validation(Vec<Issue>),
    #[error("{0}")]
    Store(#[from] StoreError),
    #[error("data plane: {0}")]
    Hal(String),
    #[error("batch step {step} failed: {error}")]
    Batch {
        step: usize,
        error: Box<EngineError>,
    },
    #[error("internal error in '{0}'; state was rolled back")]
    Internal(String),
}

impl EngineError {
    pub fn bad(param: &str, reason: impl Into<String>) -> Self {
        Self::BadParam {
            param: param.to_owned(),
            reason: reason.into(),
        }
    }
}

fn hint(s: &Option<String>) -> String {
    s.as_ref()
        .map(|s| format!("; did you mean '{s}'?"))
        .unwrap_or_default()
}

fn join(issues: &[Issue]) -> String {
    issues
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// Closest candidate by edit distance, if it is close enough to be a typo.
pub fn suggest<'a>(input: &str, candidates: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let input: String = input.chars().take(128).collect();
    let max = (input.chars().count() / 3).max(2);
    candidates
        .into_iter()
        .map(|c| (levenshtein(&input, c), c))
        .filter(|(d, _)| *d <= max)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c.to_owned())
}

fn levenshtein(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = Vec::with_capacity(b.len() + 1);
        cur.push(i + 1);
        for (j, cb) in b.iter().enumerate() {
            let sub = prev.get(j).copied().unwrap_or(usize::MAX) + usize::from(ca != *cb);
            let del = prev
                .get(j + 1)
                .copied()
                .unwrap_or(usize::MAX)
                .saturating_add(1);
            let ins = cur.get(j).copied().unwrap_or(usize::MAX).saturating_add(1);
            cur.push(sub.min(del).min(ins));
        }
        prev = cur;
    }
    prev.last().copied().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggests_typos() {
        assert_eq!(
            suggest("adress", ["address", "interface"]),
            Some("address".into())
        );
        assert_eq!(suggest("zzzzzz", ["address"]), None);
    }
}
