use reqwest::header::HeaderMap;
use crate::config::{REDACTED_HEADERS, SECURITY_HEADERS};
use crate::model::HeaderRecord;

pub fn capture(headers: &HeaderMap) -> Vec<HeaderRecord> {
    headers
        .iter()
        .map(|(name, value)| {
            let name = name.as_str().to_ascii_lowercase();
            let value = if REDACTED_HEADERS.contains(&name.as_str()) {
                // Presence is a finding; the value is a credential.
                Some("<redacted>".to_string())
            } else {
                value.to_str().ok().map(|v| v.to_string())
            };
            HeaderRecord { name, value }
        })
        .collect()
}
pub fn missing_security_headers(headers: &[HeaderRecord]) -> Vec<&'static str> {
    SECURITY_HEADERS
        .iter()
        .copied()
        .filter(|expected| !headers.iter().any(|h| h.name == *expected))
        .collect()
}
pub fn content_type(headers: &HeaderMap) -> Option<String> {
    headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_ascii_lowercase())
}
pub fn set_cookie_values(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|v| v.to_string())
        .collect()
}





#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn credential_headers_are_redacted_but_recorded() {
        let mut h = HeaderMap::new();
        h.insert(
            "Set-Cookie",
            HeaderValue::from_static("sid=SECRET; HttpOnly"),
        );
        h.insert("X-Frame-Options", HeaderValue::from_static("DENY"));

        let captured = capture(&h);
        let cookie = captured.iter().find(|r| r.name == "set-cookie").unwrap();
        assert_eq!(cookie.value.as_deref(), Some("<redacted>"));
        let xfo = captured
            .iter()
            .find(|r| r.name == "x-frame-options")
            .unwrap();
        assert_eq!(xfo.value.as_deref(), Some("DENY"));
    }

    #[test]
    fn missing_headers_are_listed() {
        let mut h = HeaderMap::new();
        h.insert(
            "Content-Security-Policy",
            HeaderValue::from_static("default-src 'self'"),
        );
        let missing = missing_security_headers(&capture(&h));
        assert!(!missing.contains(&"content-security-policy"));
        assert!(missing.contains(&"strict-transport-security"));
        assert!(missing.contains(&"x-frame-options"));
    }
}
