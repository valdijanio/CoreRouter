//! Line diff of two rulesets (G2.1c, the Diff tab): what `nft` would hold
//! after the commit against what it holds now.
//!
//! Common head and tail are cut first (a firewall change touches a few
//! lines of a long table); the middle is a longest-common-subsequence diff
//! when it is small enough, else every old line out and every new line in
//! (still correct, only less tidy). Bounded: at most [`MAX_CELLS`]
//! comparisons, whatever the input.

/// One line of the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Line<'a> {
    Same(&'a str),
    Removed(&'a str),
    Added(&'a str),
}

impl Line<'_> {
    pub fn op(self) -> &'static str {
        match self {
            Line::Same(_) => " ",
            Line::Removed(_) => "-",
            Line::Added(_) => "+",
        }
    }

    pub fn text(&self) -> &str {
        match self {
            Line::Same(t) | Line::Removed(t) | Line::Added(t) => t,
        }
    }
}

/// LCS table size above which the middle is shown as removed + added
/// (4 M cells ≈ 16 MB of u32, a few ms; **estimado**).
pub const MAX_CELLS: usize = 4_000_000;

/// The diff of `old` and `new`, line by line.
pub fn lines<'a>(old: &'a str, new: &'a str) -> Vec<Line<'a>> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let head = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let a_rest = a.get(head..).unwrap_or(&[]);
    let b_rest = b.get(head..).unwrap_or(&[]);
    let tail = a_rest
        .iter()
        .rev()
        .zip(b_rest.iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let a_mid = a_rest.get(..a_rest.len() - tail).unwrap_or(&[]);
    let b_mid = b_rest.get(..b_rest.len() - tail).unwrap_or(&[]);

    let mut out: Vec<Line<'a>> = a.iter().take(head).map(|l| Line::Same(l)).collect();
    if a_mid.len().saturating_mul(b_mid.len()) <= MAX_CELLS {
        out.extend(lcs(a_mid, b_mid));
    } else {
        out.extend(a_mid.iter().map(|l| Line::Removed(l)));
        out.extend(b_mid.iter().map(|l| Line::Added(l)));
    }
    out.extend(
        a_rest
            .get(a_rest.len() - tail..)
            .unwrap_or(&[])
            .iter()
            .map(|l| Line::Same(l)),
    );
    out
}

fn lcs<'a>(a: &[&'a str], b: &[&'a str]) -> Vec<Line<'a>> {
    let (n, m) = (a.len(), b.len());
    let w = m + 1;
    // len[i][j]: LCS of a[i..] and b[j..].
    let mut len = vec![0u32; (n + 1) * w];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            let v = if a.get(i) == b.get(j) {
                len.get((i + 1) * w + j + 1).copied().unwrap_or(0) + 1
            } else {
                let down = len.get((i + 1) * w + j).copied().unwrap_or(0);
                let right = len.get(i * w + j + 1).copied().unwrap_or(0);
                down.max(right)
            };
            if let Some(c) = len.get_mut(i * w + j) {
                *c = v;
            }
        }
    }
    let at = |i: usize, j: usize| len.get(i * w + j).copied().unwrap_or(0);
    let mut out = Vec::with_capacity(n + m);
    let (mut i, mut j) = (0, 0);
    while i < n || j < m {
        match (a.get(i), b.get(j)) {
            (Some(x), Some(y)) if x == y => {
                out.push(Line::Same(x));
                i += 1;
                j += 1;
            }
            (Some(x), Some(_)) if at(i + 1, j) >= at(i, j + 1) => {
                out.push(Line::Removed(x));
                i += 1;
            }
            (_, Some(y)) => {
                out.push(Line::Added(y));
                j += 1;
            }
            (Some(x), None) => {
                out.push(Line::Removed(x));
                i += 1;
            }
            (None, None) => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn show(d: &[Line<'_>]) -> String {
        d.iter()
            .map(|l| format!("{}{}\n", l.op(), l.text()))
            .collect()
    }

    #[test]
    fn a_changed_rule_is_one_minus_one_plus() {
        let old = "table {\n a\n b\n c\n}";
        let new = "table {\n a\n B\n c\n d\n}";
        assert_eq!(
            show(&lines(old, new)),
            " table {\n  a\n- b\n+ B\n  c\n+ d\n }\n"
        );
        assert!(
            lines("x\ny", "x\ny")
                .iter()
                .all(|l| matches!(l, Line::Same(_)))
        );
        assert_eq!(show(&lines("", "a")), "+a\n");
    }

    proptest! {
        /// Removing the `+` lines gives the old text, removing the `-`
        /// lines gives the new one, whatever the input.
        #[test]
        fn diff_rebuilds_both_sides(
            old in proptest::collection::vec("[abc]{0,2}", 0..30),
            new in proptest::collection::vec("[abc]{0,2}", 0..30),
        ) {
            let (o, n) = (old.join("\n"), new.join("\n"));
            let d = lines(&o, &n);
            let back_old: Vec<&str> = d.iter().filter(|l| !matches!(l, Line::Added(_))).map(Line::text).collect();
            let back_new: Vec<&str> = d.iter().filter(|l| !matches!(l, Line::Removed(_))).map(Line::text).collect();
            prop_assert_eq!(back_old, o.lines().collect::<Vec<_>>());
            prop_assert_eq!(back_new, n.lines().collect::<Vec<_>>());
        }
    }
}
