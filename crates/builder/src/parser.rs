//! Dockerfile parser: continuations, comments, JSON exec form, heredocs,
//! variable expansion for the instructions that need it.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    /// Upper-cased verb (FROM, RUN, COPY, ...).
    pub verb: String,
    /// Raw arguments (shell form kept as one string when applicable).
    pub args: String,
    /// JSON exec form args (when the instruction used ["a","b"] syntax).
    pub json_args: Option<Vec<String>>,
    /// Flags like --from=stage / --chown=u:g parsed from the front of args.
    pub flags: Vec<(String, String)>,
    /// Heredoc documents attached to this instruction.
    pub heredocs: Vec<Heredoc>,
    /// Line in the Dockerfile where the instruction starts (1-based).
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heredoc {
    /// Redirection target, e.g. `/etc/nginx/nginx.conf` (or empty for RUN's stdin).
    pub target: String,
    pub content: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Dockerfile {
    pub instructions: Vec<Instruction>,
}

impl Dockerfile {
    /// First FROM's base image.
    pub fn base_image(&self) -> Option<&str> {
        self.instructions.iter().find(|i| i.verb == "FROM").map(|i| {
            // FROM <image> [AS name] — skip flags
            let words: Vec<&str> = i.args.split_whitespace().collect();
            words.first().copied().unwrap_or("")
        })
    }

    /// Resolve ARG defaults for expansion.
    pub fn arg_defaults(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for i in &self.instructions {
            if i.verb == "ARG" && i.line == 0 {
                continue; // unreachable
            }
            if i.verb == "ARG" && self.is_global_arg(i) {
                if let Some((k, v)) = i.args.split_once('=') {
                    out.push((k.trim().to_string(), v.trim().trim_matches('"').to_string()));
                }
            }
        }
        out
    }

    fn is_global_arg(&self, i: &Instruction) -> bool {
        // An ARG before the first FROM is global.
        let mut seen_from = false;
        for inst in &self.instructions {
            if inst.verb == "FROM" {
                seen_from = true;
            }
            if std::ptr::eq(inst, i) {
                return !seen_from;
            }
        }
        false
    }
}

/// Parse a Dockerfile body into instructions.
pub fn parse(content: &str) -> Result<Dockerfile> {
    let mut instructions = Vec::new();
    let mut logical = String::new();
    let mut start_line = 0usize;
    let mut heredoc_delims: Vec<String> = Vec::new();

    for (idx, raw) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim_end();

        // Inside a heredoc: collect verbatim until the delimiter.
        if !heredoc_delims.is_empty() {
            logical.push('\n');
            logical.push_str(raw);
            let last = heredoc_delims.last().cloned().unwrap_or_default();
            if raw.trim_end() == last {
                heredoc_delims.pop();
                if heredoc_delims.is_empty() {
                    flush(&mut logical, start_line, &mut instructions, true)?;
                }
            }
            continue;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if start_line == 0 {
            start_line = line_no;
            logical.clear();
        }
        logical.push_str(line);

        // Continuation?
        if logical.trim_end().ends_with('\\') {
            logical.pop();
            logical.push(' ');
            continue;
        }

        // Heredocs: <<EOF or <<'EOF' anywhere in the line.
        let delims = extract_heredoc_delims(&logical);
        if !delims.is_empty() {
            heredoc_delims = delims;
            continue;
        }

        flush(&mut logical, start_line, &mut instructions, false)?;
        start_line = 0;
    }
    if !logical.trim().is_empty() && start_line != 0 {
        flush(&mut logical, start_line, &mut instructions, false)?;
    }

    if instructions.is_empty() {
        return Err(anyhow!("the Dockerfile contains no instructions"));
    }
    if instructions.first().map(|i| i.verb.clone()) != Some("FROM".into()) {
        return Err(anyhow!("Dockerfile must begin with FROM"));
    }
    Ok(Dockerfile { instructions })
}

fn flush(
    logical: &mut String,
    start_line: usize,
    instructions: &mut Vec<Instruction>,
    has_heredoc: bool,
) -> Result<()> {
    let text = logical.trim().to_string();
    logical.clear();
    if text.is_empty() {
        return Ok(());
    }
    // Heredoc bodies ride after the instruction line; split them off.
    let (head, heredocs) = if has_heredoc {
        split_heredocs(&text)
    } else {
        (text.clone(), Vec::new())
    };

    let (verb, rest) = head
        .split_once(char::is_whitespace)
        .ok_or_else(|| anyhow!("malformed instruction: {head}"))?;
    let verb = verb.to_uppercase();
    let rest = rest.trim().to_string();

    let (flags, rest) = split_flags(&rest);
    let json_args = parse_json_form(&rest);

    instructions.push(Instruction {
        verb,
        args: rest,
        json_args,
        flags,
        heredocs,
        line: start_line,
    });
    Ok(())
}

fn extract_heredoc_delims(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' && i + 1 < bytes.len() && bytes[i + 1] == b'<' {
            let mut j = i + 2;
            if j < bytes.len() && bytes[j] == b'-' {
                j += 1;
            }
            let quote = if j < bytes.len() && (bytes[j] == b'"' || bytes[j] == b'\'') {
                let q = bytes[j];
                j += 1;
                Some(q)
            } else {
                None
            };
            let start = j;
            while j < bytes.len() {
                let c = bytes[j];
                let terminated = quote.map(|q| c == q).unwrap_or(c.is_ascii_whitespace());
                if terminated {
                    break;
                }
                j += 1;
            }
            let delim = line[start..j].to_string();
            if !delim.is_empty() {
                out.push(delim);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

fn split_heredocs(text: &str) -> (String, Vec<Heredoc>) {
    let mut lines = text.lines();
    let head_line = lines.next().unwrap_or("").to_string();
    let body: Vec<&str> = lines.collect();
    let delims = extract_heredoc_delims(&head_line);
    let mut heredocs = Vec::new();
    if !delims.is_empty() {
        // Each heredoc block is terminated by its delimiter line in order.
        let mut remaining: Vec<&str> = body;
        for delim in &delims {
            let mut content = Vec::new();
            let mut target = String::new();
            loop {
                let Some(l) = remaining.first().copied() else { break };
                remaining.remove(0);
                if l.trim_end() == delim.as_str() {
                    break;
                }
                content.push(l.to_string());
            }
            heredocs.push(Heredoc { target, content: content.join("\n") });
            let _ = target;
        }
    }
    (head_line, heredocs)
}

/// Split leading `--flag=value` tokens from the args.
fn split_flags(args: &str) -> (Vec<(String, String)>, String) {
    let mut flags = Vec::new();
    let mut rest = args.trim().to_string();
    loop {
        if !rest.starts_with("--") {
            break;
        }
        let Some(space) = rest.find(char::is_whitespace) else { break };
        let tok = rest[..space].to_string();
        rest = rest[space..].trim().to_string();
        if let Some((k, v)) = tok[2..].split_once('=') {
            flags.push((k.to_string(), v.to_string()));
        } else {
            flags.push((tok[2..].to_string(), String::new()));
        }
    }
    (flags, rest)
}

/// Detect the JSON exec form: ["cmd","arg",...]
pub fn parse_json_form(args: &str) -> Option<Vec<String>> {
    let t = args.trim();
    if !t.starts_with('[') {
        return None;
    }
    let v: Vec<String> = serde_json::from_str(t).ok()?;
    Some(v)
}

/// Expand $VAR / ${VAR} using the provided environment (build args + ENV).
pub fn expand_vars(input: &str, env: &[(String, String)]) -> String {
    let mut out = String::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '$' && i + 1 < chars.len() {
            if chars[i + 1] == '{' {
                if let Some(close) = chars[i + 2..].iter().position(|&c| c == '}') {
                    let name: String = chars[i + 2..i + 2 + close].iter().collect();
                    // ${VAR:-default} / ${VAR:+alt}
                    let (var, default) = match name.split_once(":-") {
                        Some((v, d)) => (v.to_string(), Some(d.to_string())),
                        None => (name.clone(), None),
                    };
                    let val = env.iter().find(|(k, _)| *k == var).map(|(_, v)| v.clone());
                    match val.or(default) {
                        Some(v) => out.push_str(&v),
                        None => {}
                    }
                    i += 2 + close + 1;
                    continue;
                }
            } else if chars[i + 1].is_alphabetic() || chars[i + 1] == '_' {
                let mut j = i + 1;
                while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                let name: String = chars[i + 1..j].iter().collect();
                if let Some((_, v)) = env.iter().find(|(k, _)| *k == name) {
                    out.push_str(v);
                }
                i = j;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_dockerfile() {
        let df = parse("FROM busybox\n\n# comment\nRUN echo one \\\n  && echo two\nCMD [\"echo\",\"hi\"]").unwrap();
        assert_eq!(df.instructions.len(), 3);
        assert_eq!(df.instructions[1].verb, "RUN");
        assert_eq!(df.instructions[1].args.trim().split_whitespace().collect::<Vec<_>>().join(" "), "echo one && echo two");
        assert_eq!(df.instructions[2].json_args.as_deref(), Some(&["echo".to_string(), "hi".to_string()][..]));
    }

    #[test]
    fn json_and_flags() {
        let df = parse("FROM busybox\nCOPY --from=x --chown=1:1 a b").unwrap();
        let i = &df.instructions[1];
        assert_eq!(i.flags[0], ("from".into(), "x".into()));
        assert_eq!(i.flags[1], ("chown".into(), "1:1".into()));
        assert_eq!(i.args, "a b");
    }

    #[test]
    fn var_expansion() {
        let env = vec![("V".to_string(), "val".to_string())];
        assert_eq!(expand_vars("$V-${V:-d}", &env), "val-val");
        assert_eq!(expand_vars("${MISS:-def}", &env), "def");
        assert_eq!(expand_vars("a$b", &env), "a");
    }
}
