//! Wordlist loading for path discovery.
//!
//! A wordlist is the whole input to brute forcing, so the parsing rules are
//! kept boring and predictable: one candidate per line, `#` comments and blank
//! lines dropped, surrounding whitespace trimmed, a leading `/` optional, and
//! duplicates removed while preserving the file's order. Nothing is lowercased
//! -- paths are case-sensitive on most servers, and a wordlist that says
//! `Admin` means `Admin`.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};

/// Shipped so the feature works with no external file. Small on purpose.
pub const BUILTIN: &str = include_str!("wordlists/common.txt");

/// Refuse absurd inputs rather than letting a mistyped `--wordlist` (a binary,
/// or a 10M-line list) turn into an unbounded request volume against a target.
pub const MAX_WORDS: usize = 200_000;

/// Parse wordlist text into ordered, deduplicated candidates.
pub fn parse(text: &str) -> Vec<String> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // A wordlist entry is joined onto a directory URL, so a leading slash
        // would make it absolute and silently discard the directory.
        let word = line.trim_start_matches('/');
        // A trailing slash is the caller asking for a directory; keep it, it is
        // meaningful when the candidate is joined.
        if word.is_empty() || !is_safe_path_segment(word) {
            continue;
        }
        if seen.insert(word) {
            out.push(word.to_string());
            if out.len() >= MAX_WORDS {
                break;
            }
        }
    }
    out
}

/// Reject entries that would escape the directory being probed or that cannot
/// appear in a URL path. `..` is the one that matters: a wordlist containing
/// `../../etc` would probe outside the scope the operator authorized.
fn is_safe_path_segment(word: &str) -> bool {
    if word.len() > 512 {
        return false;
    }
    if word.split('/').any(|seg| seg == ".." || seg == ".") {
        return false;
    }
    // Control characters, spaces and URL delimiters would either break the join
    // or change which URL is being requested.
    !word
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '?' | '#' | '\\'))
}

pub fn load(path: Option<&Path>) -> Result<Vec<String>> {
    let words = match path {
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .with_context(|| format!("reading wordlist {}", p.display()))?;
            parse(&text)
        }
        None => parse(BUILTIN),
    };
    if words.is_empty() {
        anyhow::bail!(
            "wordlist is empty after parsing{}",
            path.map(|p| format!(" ({})", p.display()))
                .unwrap_or_default()
        );
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_blanks_and_leading_slashes_are_handled() {
        let w = parse("# comment\n\n  admin \n/api\nadmin\n\t/v1/users\n");
        assert_eq!(w, vec!["admin", "api", "v1/users"], "deduped, order kept");
    }

    #[test]
    fn traversal_and_junk_entries_are_dropped() {
        // The important one: a wordlist must not be able to walk out of the
        // directory -- or the host -- the operator authorized.
        let w = parse("../etc/passwd\n./x\na/../../b\nok\nwith space\nq?x=1\nfrag#ment\n");
        assert_eq!(w, vec!["ok"]);
    }

    #[test]
    fn trailing_slash_is_preserved() {
        assert_eq!(parse("admin/\n"), vec!["admin/"]);
    }

    #[test]
    fn the_builtin_list_parses_and_is_not_empty() {
        let w = parse(BUILTIN);
        assert!(w.len() > 100, "built-in list should be useful: {}", w.len());
        assert!(w.iter().any(|x| x == "admin"));
        assert!(w.iter().all(|x| !x.starts_with('/')));
    }

    #[test]
    fn oversized_lists_are_truncated_not_accepted_whole() {
        let text: String = (0..MAX_WORDS + 500).map(|i| format!("w{i}\n")).collect();
        assert_eq!(parse(&text).len(), MAX_WORDS);
    }
}
