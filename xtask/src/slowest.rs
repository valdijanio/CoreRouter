//! G0.30: the test-time budget. The `test` step writes nextest's JUnit
//! report (`.config/nextest.toml`); this reads it back and prints the
//! slowest tests at the end of every `cargo xtask ci`, so a slow test is
//! seen the day it lands instead of when the gate has doubled.

use std::path::{Path, PathBuf};

/// One test's wall time, from a `<testcase>` of the JUnit report.
#[derive(Debug, Clone, PartialEq)]
pub struct TestTime {
    /// nextest's binary id (`corerouter-engine::it`, `corerouter-hal`).
    pub binary: String,
    /// The test path inside the binary (`cmd::ip::adds_an_address`).
    pub name: String,
    pub secs: f64,
}

impl TestTime {
    pub fn full_name(&self) -> String {
        format!("{} {}", self.binary, self.name)
    }
}

/// Where nextest writes the JUnit report of `profile`: its store is
/// `target/nextest` under the workspace, whatever `CARGO_TARGET_DIR` says.
pub fn junit_path(root: &Path, profile: &str) -> PathBuf {
    root.join("target/nextest").join(profile).join("junit.xml")
}

/// The `<testcase>`s of a nextest JUnit report (a retried test keeps the
/// time of its last run, as nextest writes it).
pub fn parse_junit(xml: &str) -> Vec<TestTime> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(at) = rest.find("<testcase ") {
        let Some(tail) = rest.get(at + "<testcase ".len()..) else {
            break;
        };
        let end = tail.find('>').unwrap_or(tail.len());
        let tag = tail.get(..end).unwrap_or("");
        let (Some(name), Some(binary), Some(time)) =
            (attr(tag, "name"), attr(tag, "classname"), attr(tag, "time"))
        else {
            rest = tail;
            continue;
        };
        if let Ok(secs) = time.parse::<f64>() {
            out.push(TestTime {
                binary: unescape(&binary),
                name: unescape(&name),
                secs,
            });
        }
        rest = tail;
    }
    out
}

/// `key="value"` of an XML start tag (attribute names are whole words).
fn attr(tag: &str, key: &str) -> Option<String> {
    let mut from = 0;
    while let Some(i) = tag.get(from..)?.find(key) {
        let at = from + i;
        let before_ok = at == 0 || tag.as_bytes().get(at - 1).is_some_and(|b| *b == b' ');
        let after = tag.get(at + key.len()..)?;
        if before_ok && let Some(v) = after.strip_prefix("=\"") {
            return v.find('"').and_then(|e| v.get(..e)).map(str::to_owned);
        }
        from = at + key.len();
    }
    None
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The report printed after the `test` step: totals and the `top` slowest.
pub fn report(tests: &[TestTime], top: usize) -> String {
    let mut sorted: Vec<&TestTime> = tests.iter().collect();
    sorted.sort_by(|a, b| b.secs.total_cmp(&a.secs).then_with(|| a.name.cmp(&b.name)));
    let total: f64 = tests.iter().map(|t| t.secs).sum();
    let over = |s: f64| tests.iter().filter(|t| t.secs > s).count();
    let top_sum: f64 = sorted.iter().take(top).map(|t| t.secs).sum();
    let mut out = format!(
        "slowest tests: {} tests, {total:.1} s of test time in all; {} over 1 s, {} over 5 s; \
         the {} below are {:.0}% of it\n",
        tests.len(),
        over(1.0),
        over(5.0),
        top.min(sorted.len()),
        if total > 0.0 {
            top_sum * 100.0 / total
        } else {
            0.0
        },
    );
    for t in sorted.iter().take(top) {
        out.push_str(&format!("  {:>7.2} s  {}\n", t.secs, t.full_name()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="3" failures="0" errors="0" uuid="x" timestamp="t" time="3.1">
    <testsuite name="corerouter-engine::it" tests="2" disabled="0" errors="0" failures="0">
        <testcase name="cmd::ip::adds" classname="corerouter-engine::it" timestamp="t" time="0.012">
        </testcase>
        <testcase name="slow::&lt;waits&gt;" classname="corerouter-engine::it" timestamp="t" time="2.500"/>
    </testsuite>
    <testsuite name="corerouter-hal" tests="1">
        <testcase name="virt::x" classname="corerouter-hal" timestamp="t" time="0.600"><flakyFailure/></testcase>
    </testsuite>
</testsuites>"#;

    #[test]
    fn reads_every_testcase() {
        let t = parse_junit(XML);
        assert_eq!(t.len(), 3);
        assert_eq!(t[1].name, "slow::<waits>");
        assert_eq!(t[1].binary, "corerouter-engine::it");
        assert!((t[1].secs - 2.5).abs() < 1e-9);
        assert_eq!(t[2].full_name(), "corerouter-hal virt::x");
        assert!(parse_junit("<testcase name=\"x\"").is_empty());
        assert!(parse_junit("").is_empty());
    }

    #[test]
    fn attributes_match_whole_names() {
        let tag = r#"classname="a" name="b" time="1""#;
        assert_eq!(attr(tag, "name").as_deref(), Some("b"));
        assert_eq!(attr(tag, "classname").as_deref(), Some("a"));
        assert_eq!(attr(tag, "nam"), None);
    }

    #[test]
    fn report_lists_the_slowest_first() {
        let r = report(&parse_junit(XML), 2);
        assert!(r.starts_with("slowest tests: 3 tests, 3.1 s"), "{r}");
        assert!(r.contains("1 over 1 s, 0 over 5 s"), "{r}");
        let lines: Vec<&str> = r.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[1].ends_with("slow::<waits>"), "{r}");
        assert!(lines[2].ends_with("virt::x"), "{r}");
    }
}
