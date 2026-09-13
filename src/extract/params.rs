use std::collections::HashSet;
use url::Url;
use crate::model::{ParamRecord, ParamSource};

pub fn classify(value: &str) -> &'static str {
    let v = value.trim();
    if v.is_empty() {
        return "empty";
    }
    if matches!(
        v.to_ascii_lowercase().as_str(),
        "true" | "false" | "on" | "off" | "yes" | "no"
    ) {
        return "boolean";
    }
    if v.len() <= 20 && v.chars().all(|c| c.is_ascii_digit()) {
        return "numeric";
    }
    // `v.len() > 1` matters: without it a lone `-` has an empty tail, every
    // character of which is trivially a digit, and classifies as numeric.
    if v.starts_with('-')
        && v.len() > 1
        && v.len() <= 21
        && v[1..].chars().all(|c| c.is_ascii_digit())
    {
        return "numeric";
    }
    if is_uuid(v) {
        return "uuid";
    }
    if is_date(v) {
        return "date";
    }
    if v.contains('@') && v.contains('.') && !v.contains(' ') && v.len() < 254 {
        return "email";
    }
    if v.starts_with("http://") || v.starts_with("https://") || v.starts_with("//") {
        return "url";
    }
    if v.contains('/') || v.contains('\\') {
        return "path";
    }
    if (v.starts_with('{') && v.ends_with('}')) || (v.starts_with('[') && v.ends_with(']')) {
        return "json";
    }
    if v.len() >= 16 && v.chars().all(|c| c.is_ascii_hexdigit()) {
        return "hex";
    }
    if v.len() >= 24
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '=' | '.' | '+' | '/'))
    {
        return "token";
    }
    if v.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return "alnum";
    }
    "opaque"
}



fn is_uuid(v: &str) -> bool {
    let b = v.as_bytes();
    b.len() == 36
        && [8usize, 13, 18, 23].iter().all(|&i| b[i] == b'-')
        && v.chars()
            .enumerate()
            .all(|(i, c)| matches!(i, 8 | 13 | 18 | 23) || c.is_ascii_hexdigit())
}
fn is_date(v: &str) -> bool {
    // YYYY-MM-DD
    let head = v.split(['T', ' ']).next().unwrap_or("");
    let parts: Vec<&str> = head.split('-').collect();
    parts.len() == 3
        && parts[0].len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

pub fn from_url(url: &Url, source: ParamSource) -> Vec<ParamRecord> {
    let mut seen: HashSet<(String, &'static str)> = HashSet::new();
    let mut out = Vec::new();
    for (name, value) in url.query_pairs() {
        let name = name.into_owned();
        if name.is_empty() {
            continue;
        }
        let shape = classify(&value);
        if seen.insert((name.clone(), shape)) {
            out.push(ParamRecord {
                name,
                shape: shape.to_string(),
                source,
            });
        }
    }
    out
}





#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes() {
        assert_eq!(classify(""), "empty");
        assert_eq!(classify("42"), "numeric");
        assert_eq!(classify("-42"), "numeric");
        assert_eq!(classify("true"), "boolean");
        assert_eq!(classify("3f2504e0-4f89-11d3-9a0c-0305e82c3301"), "uuid");
        assert_eq!(classify("2024-01-31"), "date");
        assert_eq!(classify("2024-01-31T12:00:00"), "date");
        assert_eq!(classify("a@b.com"), "email");
        assert_eq!(classify("https://x.test/cb"), "url");
        assert_eq!(classify("//evil.test"), "url");
        assert_eq!(classify("../../etc/passwd"), "path");
        assert_eq!(classify(r#"{"a":1}"#), "json");
        assert_eq!(classify("deadbeefdeadbeef"), "hex");
        assert_eq!(classify("eyJhbGciOiJIUzI1NiJ9.abcdefghijklm"), "token");
        assert_eq!(classify("blue"), "alnum");
        assert_eq!(classify("hello world!"), "opaque");
    }

    #[test]
    fn url_params_dedupe_by_name_and_shape() {
        let u = Url::parse("https://e.com/s?id=1&id=2&id=abc&q=&empty").unwrap();
        let p = from_url(&u, ParamSource::SelfUrl);
        let names: Vec<_> = p
            .iter()
            .map(|r| (r.name.as_str(), r.shape.as_str()))
            .collect();
        assert!(names.contains(&("id", "numeric")));
        assert!(names.contains(&("id", "alnum")));
        assert!(names.contains(&("q", "empty")));
        // `id=1` and `id=2` share a shape and collapse to one row.
        assert_eq!(
            p.iter()
                .filter(|r| r.name == "id" && r.shape == "numeric")
                .count(),
            1
        );
    }
}
