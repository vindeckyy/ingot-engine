//! `.dockerignore`-style ignore patterns with anchored, negated, and
//! glob (`*`/`?`/`**`/`[...]`) semantics.
//!
//! Rules implemented (matching Docker's documented behavior):
//! - Blank lines and `#` comments are skipped (`\#` escapes a literal `#`).
//! - A leading `!` negates the pattern (`\!` escapes a literal `!`).
//! - A trailing `/` marks a directory-only pattern (matches the dir and
//!   everything beneath it).
//! - A pattern containing `/` (other than the trailing one) is anchored
//!   to the context root; otherwise it matches the basename at any depth.
//! - `*` spans any run of non-separator chars, `?` one such char, `**`
//!   spans separators too, `[...]` is a character class.
//! - The LAST matching pattern decides, evaluated against the full
//!   path: a negation re-includes files even under an excluded
//!   directory (matching what the Docker CLI sends).

/// One parsed ignore pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pattern {
    /// Match components (never empty).
    parts: Vec<String>,
    /// Anchored to the context root.
    anchored: bool,
    /// Matches directories only (and everything beneath them).
    dir_only: bool,
    /// Negated (`!`) pattern: re-includes.
    negated: bool,
}

/// A parsed ignore file; cheap to clone and share.
#[derive(Debug, Clone, Default)]
pub struct IgnorePatterns {
    patterns: Vec<Pattern>,
}

/// Parse ignore-file content into matchable patterns.
pub fn parse_ignore(content: &str) -> IgnorePatterns {
    let mut patterns = Vec::new();
    for raw in content.lines() {
        // Trailing whitespace is insignificant unless escaped; leading
        // whitespace is kept (Docker trims both ends — mirror that).
        let mut line = raw.trim().to_string();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut negated = false;
        if let Some(rest) = line.strip_prefix('!') {
            negated = true;
            line = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("\\#") {
            line = format!("#{rest}");
        } else if let Some(rest) = line.strip_prefix("\\!") {
            line = format!("!{rest}");
        }
        if line.is_empty() {
            continue;
        }
        let mut dir_only = line.ends_with('/');
        line = line.trim_end_matches('/').to_string();
        if line.is_empty() {
            continue;
        }
        let mut anchored = line.starts_with('/') || line.contains('/');
        line = line.trim_start_matches('/').to_string();
        if line.is_empty() {
            continue;
        }
        let mut parts: Vec<String> = line.split('/').map(|s| s.to_string()).collect();
        // A leading `**/` means "at any depth": drop it and unanchor.
        // A trailing `/**` means "everything beneath": drop it and treat
        // the rest as directory-only. A bare `**` matches everything.
        while parts.first().map(String::as_str) == Some("**") {
            parts.remove(0);
            anchored = false;
        }
        while parts.last().map(String::as_str) == Some("**") {
            parts.pop();
            dir_only = true;
        }
        if parts.is_empty() {
            parts.push("**".to_string());
            anchored = false;
        }
        patterns.push(Pattern {
            parts,
            anchored,
            dir_only,
            negated,
        });
    }
    IgnorePatterns { patterns }
}

impl IgnorePatterns {
    /// True when no usable pattern was parsed.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// True when the file holds at least one negating (`!`) pattern.
    /// Walkers use this to decide whether an excluded directory must
    /// still be descended: a negation may re-include something beneath it.
    pub fn has_negations(&self) -> bool {
        self.patterns.iter().any(|p| p.negated)
    }

    /// Decide whether `rel` (slash-separated, relative to the context
    /// root, no leading `./`) is excluded. `is_dir` tells whether the
    /// path itself is a directory. Only the last matching pattern counts,
    /// evaluated against the full path — a negation re-includes files
    /// even under an excluded directory.
    pub fn is_excluded(&self, rel: &str, is_dir: bool) -> bool {
        let rel = rel.trim_start_matches("./");
        if rel.is_empty() {
            return false;
        }
        let comps: Vec<&str> = rel.split('/').collect();
        matches!(self.last_verdict(&comps, is_dir), Some(false))
    }

    /// Verdict of the LAST pattern matching `comps`: Some(true) =
    /// negated (re-include), Some(false) = excluded, None = no match.
    fn last_verdict(&self, comps: &[&str], is_dir: bool) -> Option<bool> {
        let mut verdict = None;
        for p in &self.patterns {
            if p.matches(comps, is_dir) {
                verdict = Some(p.negated);
            }
        }
        verdict
    }
}

impl Pattern {
    fn matches(&self, comps: &[&str], is_dir: bool) -> bool {
        if self.anchored {
            // Anchored: the pattern must match from the root (a `**`
            // inside still spans components). A dir-only pattern also
            // matches everything beneath the directory.
            if self.dir_only {
                (1..=comps.len()).any(|end| {
                    match_parts(&self.parts, &comps[..end]) && (end < comps.len() || is_dir)
                })
            } else {
                match_parts(&self.parts, comps)
            }
        } else {
            // Unanchored: the pattern may match at any depth — try every
            // trailing suffix of the component list.
            (0..comps.len()).any(|start| {
                let suffix = &comps[start..];
                if self.dir_only {
                    self.parts.len() <= suffix.len()
                        && match_parts(&self.parts, &suffix[..self.parts.len()])
                        && (self.parts.len() < suffix.len() || is_dir)
                } else {
                    match_parts(&self.parts, suffix)
                }
            })
        }
    }
}

/// Match pattern components against path components (`**` spans
/// component boundaries, everything else stays within one component).
fn match_parts(pat: &[String], path: &[&str]) -> bool {
    if pat.is_empty() {
        return path.is_empty();
    }
    if pat[0] == "**" {
        // `**` swallows zero or more components.
        for skip in 0..=path.len() {
            if match_parts(&pat[1..], &path[skip..]) {
                return true;
            }
        }
        return false;
    }
    if path.is_empty() {
        return false;
    }
    if !match_component(&pat[0], path[0]) {
        return false;
    }
    match_parts(&pat[1..], &path[1..])
}

/// Match one pattern component against one path component: `*`, `?`,
/// and `[...]` classes; never spans `/` (already split).
fn match_component(pat: &str, name: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let n: Vec<char> = name.chars().collect();
    match_comp(&p, &n)
}

fn match_comp(p: &[char], n: &[char]) -> bool {
    if p.is_empty() {
        return n.is_empty();
    }
    match p[0] {
        '*' => {
            // `*` spans any run of (possibly zero) chars.
            for skip in 0..=n.len() {
                if match_comp(&p[1..], &n[skip..]) {
                    return true;
                }
            }
            false
        }
        '?' => !n.is_empty() && match_comp(&p[1..], &n[1..]),
        '[' => {
            if n.is_empty() {
                return false;
            }
            match (parse_class(p), n[0]) {
                (Some((matched, rest)), c) if matched(c) => match_comp(rest, &n[1..]),
                _ => false,
            }
        }
        '\\' if p.len() > 1 => !n.is_empty() && p[1] == n[0] && match_comp(&p[2..], &n[1..]),
        c => !n.is_empty() && c == n[0] && match_comp(&p[1..], &n[1..]),
    }
}

/// Parse a `[...]` class at the head of `p`. Returns a membership
/// predicate plus the pattern remainder after `]`. `None` on malformed
/// (unclosed) classes — those never match.
fn parse_class(p: &[char]) -> Option<(impl Fn(char) -> bool, &[char])> {
    let mut i = 1;
    let mut negate = false;
    if i < p.len() && (p[i] == '^' || p[i] == '!') {
        negate = true;
        i += 1;
    }
    let mut members: Vec<(char, char)> = Vec::new();
    let mut singles: Vec<char> = Vec::new();
    // A `]` first is literal.
    if i < p.len() && p[i] == ']' {
        singles.push(']');
        i += 1;
    }
    while i < p.len() && p[i] != ']' {
        if p[i] == '\\' && i + 1 < p.len() {
            singles.push(p[i + 1]);
            i += 2;
        } else if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
            members.push((p[i], p[i + 2]));
            i += 3;
        } else {
            singles.push(p[i]);
            i += 1;
        }
    }
    if i >= p.len() {
        return None; // unclosed
    }
    let rest = &p[i + 1..];
    Some((
        move |c: char| {
            let hit = singles.contains(&c) || members.iter().any(|&(lo, hi)| lo <= c && c <= hi);
            hit != negate
        },
        rest,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn excluded(patterns: &str, rel: &str, is_dir: bool) -> bool {
        parse_ignore(patterns).is_excluded(rel, is_dir)
    }

    #[test]
    fn basics_comments_and_blanks() {
        let ig = parse_ignore("# comment\n\n   \n*.log\n");
        assert!(ig.is_excluded("a.log", false));
        assert!(!ig.is_excluded("a.txt", false));
        assert!(!ig.is_empty());
        assert!(parse_ignore("# only\n\n").is_empty());
    }

    #[test]
    fn unanchored_matches_at_any_depth() {
        assert!(excluded("*.log", "a.log", false));
        assert!(excluded("*.log", "sub/dir/a.log", false));
        assert!(!excluded("*.log", "sub/dir/a.txt", false));
        assert!(!excluded("build", "sub/build2/x", false));
        assert!(excluded("build", "sub/build", true));
    }

    #[test]
    fn anchored_patterns() {
        assert!(excluded("/root-only", "root-only", false));
        assert!(!excluded("/root-only", "sub/root-only", false));
        assert!(excluded("a/b", "a/b", false));
        assert!(!excluded("a/b", "x/a/b", false));
        assert!(excluded("doc/*.md", "doc/a.md", false));
        assert!(!excluded("doc/*.md", "doc/sub/a.md", false));
    }

    #[test]
    fn dir_only_and_beneath() {
        assert!(excluded("logs/", "logs", true));
        assert!(excluded("logs/", "logs/a.txt", false));
        assert!(excluded("logs/", "logs/sub/a.txt", false));
        // Unanchored dir patterns apply at any depth.
        assert!(excluded("logs/", "other/logs/a.txt", false));
        assert!(!excluded("logs/", "other/blah/a.txt", false));
        // A file that merely shares the directory's name is kept; the
        // directory itself (and everything under it) is excluded.
        assert!(!excluded("logs/", "logs", false));
        assert!(excluded("logs/", "logs", true));
    }

    #[test]
    fn negation_last_match_wins() {
        let pats = "*.log\n!important.log\n";
        assert!(excluded(pats, "a.log", false));
        assert!(!excluded(pats, "important.log", false));
        let pats = "*.log\n!important.log\n*.log\n";
        assert!(excluded(pats, "important.log", false));
    }

    #[test]
    fn negation_reincludes_under_excluded_dir() {
        // Last match wins on the full path: Docker re-includes files
        // under an excluded directory when negated (verified against the
        // real Docker CLI's context filtering).
        let pats = "secrets/\n!secrets/keep.txt\n";
        assert!(!excluded(pats, "secrets/keep.txt", false));
        assert!(excluded(pats, "secrets/other.txt", false));
        assert!(excluded(pats, "secrets", true));
    }

    #[test]
    fn stars_and_classes() {
        assert!(excluded("file-??", "file-ab", false));
        assert!(!excluded("file-??", "file-abc", false));
        assert!(excluded("data[0-9]", "data5", false));
        assert!(!excluded("data[0-9]", "datax", false));
        assert!(excluded("**/gen", "a/b/gen", false));
        assert!(excluded("a/**/z", "a/z", false));
        assert!(excluded("a/**/z", "a/x/y/z", false));
        assert!(!excluded("a/**/z", "a/x/y", false));
    }

    #[test]
    fn star_does_not_cross_separator_when_anchored() {
        assert!(!excluded("a/*.txt", "a/b/c.txt", false));
        assert!(excluded("a/*.txt", "a/c.txt", false));
    }
}
