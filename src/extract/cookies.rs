use crate::model::CookieRecord;

pub fn parse_set_cookie(header: &str) -> Option<CookieRecord> {
    let mut parts = header.split(';');
    let pair = parts.next()?.trim();
    let (name, _value) = pair.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let mut rec = CookieRecord {
        name: name.to_string(),
        ..Default::default()
    };
    for attr in parts {
        let attr = attr.trim();
        let (key, value) = match attr.split_once('=') {
            Some((k, v)) => (k.trim(), Some(v.trim())),
            None => (attr, None),
        };
        match key.to_ascii_lowercase().as_str() {
            "httponly" => rec.http_only = true,
            "secure" => rec.secure = true,
            "samesite" => rec.same_site = value.map(|v| v.to_string()),
            "domain" => rec.domain = value.map(|v| v.to_string()),
            "path" => rec.path = value.map(|v| v.to_string()),
            "expires" => rec.has_expiry = true,
            "max-age" => rec.has_expiry = true,
            _ => {}
        }
    }
    Some(rec)
}





#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_are_captured_and_value_is_not() {
        let c = parse_set_cookie(
            "sessionid=SECRETVALUE123; Path=/; Domain=.e.com; HttpOnly; Secure; SameSite=Strict; Max-Age=3600",
        )
        .unwrap();
        assert_eq!(c.name, "sessionid");
        assert!(c.http_only && c.secure && c.has_expiry);
        assert_eq!(c.same_site.as_deref(), Some("Strict"));
        assert_eq!(c.path.as_deref(), Some("/"));
        let debug = format!("{c:?}");
        assert!(!debug.contains("SECRETVALUE123"));
    }

    #[test]
    fn missing_flags_default_false() {
        let c = parse_set_cookie("plain=abc").unwrap();
        assert!(!c.http_only && !c.secure && !c.has_expiry);
        assert_eq!(c.same_site, None);
    }

    #[test]
    fn values_containing_equals_are_handled() {
        let c = parse_set_cookie("jwt=aaa=bb.cc=dd; HttpOnly").unwrap();
        assert_eq!(c.name, "jwt");
        assert!(c.http_only);
    }
}
