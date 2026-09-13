use std::sync::LazyLock;
use scraper::{ElementRef, Html, Selector};
use sha2::{Digest, Sha256};
use crate::model::{FormInput, LinkType};

fn sel(s: &str) -> Selector {
    Selector::parse(s).expect("static selector is valid")
}
static TITLE: LazyLock<Selector> = LazyLock::new(|| sel("title"));
static BASE: LazyLock<Selector> = LazyLock::new(|| sel("base[href]"));
static ANCHOR: LazyLock<Selector> = LazyLock::new(|| sel("a[href], area[href]"));
static FRAME: LazyLock<Selector> = LazyLock::new(|| sel("iframe[src], frame[src]"));
static FORM: LazyLock<Selector> = LazyLock::new(|| sel("form"));
static SCRIPT: LazyLock<Selector> = LazyLock::new(|| sel("script"));
static META_REFRESH: LazyLock<Selector> = LazyLock::new(|| sel(r#"meta[http-equiv="refresh" i]"#));
static FIELD: LazyLock<Selector> = LazyLock::new(|| sel("input, textarea, select, button"));
static OWNED_FIELD: LazyLock<Selector> = LazyLock::new(|| sel("[form]"));
static SELECTED_OPTION: LazyLock<Selector> = LazyLock::new(|| sel("option[selected]"));

#[derive(Debug, Default)]
pub struct RawExtract {
    pub title: Option<String>,
    pub base_href: Option<String>,
    pub links: Vec<(String, LinkType)>,
    pub forms: Vec<RawForm>,
    pub scripts: Vec<RawScript>,
}
#[derive(Debug)]
pub struct RawForm {
    pub action: Option<String>,
    pub method: String,
    pub enctype: Option<String>,
    pub name: Option<String>,
    pub dom_id: Option<String>,
    pub inputs: Vec<FormInput>,
}
#[derive(Debug)]
pub struct RawScript {
    pub src: Option<String>,
    pub integrity: Option<String>,
    pub crossorigin: Option<String>,
    pub body_sha256: Option<String>,
    pub body_bytes: Option<i64>,
}
const MAX_TITLE_LEN: usize = 300;
const MAX_NEST_DEPTH: usize = 256;
const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];
fn limit_nesting(html: &str) -> &str {
    let b = html.as_bytes();
    let mut depth: usize = 0;
    let mut i = 0;

    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        // `<!-- ... -->`, `<!doctype>`, `<![CDATA[`: not elements, and a comment
        // may legally contain `<` that would otherwise be miscounted.
        if b[i..].starts_with(b"<!--") {
            match find(b, i + 4, b"-->") {
                Some(end) => i = end + 3,
                None => return html,
            }
            continue;
        }
        if b[i..].starts_with(b"<!") || b[i..].starts_with(b"<?") {
            match find(b, i + 2, b">") {
                Some(end) => i = end + 1,
                None => return html,
            }
            continue;
        }

        let closing = b.get(i + 1) == Some(&b'/');
        let name_start = if closing { i + 2 } else { i + 1 };
        if !b.get(name_start).is_some_and(|c| c.is_ascii_alphabetic()) {
            i += 1;
            continue;
        }
        let mut name_end = name_start;
        while name_end < b.len() && (b[name_end].is_ascii_alphanumeric() || b[name_end] == b'-') {
            name_end += 1;
        }
        let name = html[name_start..name_end].to_ascii_lowercase();

        let Some(tag_end) = find(b, name_end, b">") else {
            return html;
        };
        let self_closing = tag_end > 0 && b[tag_end - 1] == b'/';

        if closing {
            depth = depth.saturating_sub(1);
        } else if !self_closing && !VOID_ELEMENTS.contains(&name.as_str()) {
            depth += 1;
            if depth > MAX_NEST_DEPTH {
                tracing::debug!(
                    depth,
                    offset = i,
                    "nesting limit reached; truncating document"
                );
                // `<` is ASCII, so this index is always a char boundary.
                return &html[..i];
            }
        }
        i = tag_end + 1;
    }
    html
}

fn find(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from >= haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

pub fn extract(html: &str) -> RawExtract {
    let doc = Html::parse_document(limit_nesting(html));

    let title = doc.select(&TITLE).next().map(|e| {
        let t: String = e.text().collect();
        let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
        if t.chars().count() > MAX_TITLE_LEN {
            t.chars().take(MAX_TITLE_LEN).collect()
        } else {
            t
        }
    });

    let base_href = doc
        .select(&BASE)
        .next()
        .and_then(|e| e.attr("href"))
        .map(str::to_string);

    let mut links: Vec<(String, LinkType)> = Vec::new();
    for el in doc.select(&ANCHOR) {
        if let Some(href) = el.attr("href") {
            push_link(&mut links, href, LinkType::Anchor);
        }
    }
    for el in doc.select(&FRAME) {
        if let Some(src) = el.attr("src") {
            push_link(&mut links, src, LinkType::Iframe);
        }
    }
    for el in doc.select(&META_REFRESH) {
        if let Some(target) = el.attr("content").and_then(parse_meta_refresh) {
            push_link(&mut links, &target, LinkType::Redirect);
        }
    }
    let mut adopted: Vec<(String, ElementRef<'_>)> = Vec::new();
    for el in doc.select(&OWNED_FIELD) {
        if let Some(owner) = el.attr("form")
            && FIELD.matches(&el)
        {
            adopted.push((owner.to_string(), el));
        }
    }

    let mut forms = Vec::new();
    for form in doc.select(&FORM) {
        let dom_id = form.attr("id").map(str::to_string);
        let mut inputs: Vec<FormInput> = form.select(&FIELD).map(read_field).collect();
        if let Some(id) = dom_id.as_deref() {
            inputs.extend(
                adopted
                    .iter()
                    .filter(|(owner, _)| owner == id)
                    .map(|(_, el)| read_field(*el)),
            );
        }

        let action = form.attr("action").map(str::to_string);
        if let Some(a) = action.as_deref() {
            push_link(&mut links, a, LinkType::FormAction);
        }

        forms.push(RawForm {
            action,
            method: form
                .attr("method")
                .map(|m| m.trim().to_ascii_uppercase())
                .filter(|m| m == "POST" || m == "GET" || m == "DIALOG")
                .unwrap_or_else(|| "GET".to_string()),
            enctype: form.attr("enctype").map(|e| e.trim().to_ascii_lowercase()),
            name: form.attr("name").map(str::to_string),
            dom_id,
            inputs,
        });
    }

    let mut scripts = Vec::new();
    for el in doc.select(&SCRIPT) {
        let src = el.attr("src").map(str::to_string);
        if let Some(s) = src.as_deref() {
            push_link(&mut links, s, LinkType::ScriptSrc);
        }
        let (body_sha256, body_bytes) = if src.is_none() {
            let body: String = el.text().collect();
            let trimmed = body.trim();
            if trimmed.is_empty() {
                (None, None)
            } else {
                (
                    Some(sha256_hex(trimmed.as_bytes())),
                    Some(trimmed.len() as i64),
                )
            }
        } else {
            (None, None)
        };
        scripts.push(RawScript {
            src,
            integrity: el.attr("integrity").map(str::to_string),
            crossorigin: el.attr("crossorigin").map(str::to_string),
            body_sha256,
            body_bytes,
        });
    }

    RawExtract {
        title,
        base_href,
        links,
        forms,
        scripts,
    }
}

fn push_link(out: &mut Vec<(String, LinkType)>, href: &str, kind: LinkType) {
    let href = href.trim();
    if href.is_empty() || href.starts_with('#') {
        return;
    }
    out.push((href.to_string(), kind));
}

fn read_field(el: ElementRef<'_>) -> FormInput {
    let tag = el.value().name();
    let input_type = match tag {
        "input" => el
            .attr("type")
            .map(|t| t.trim().to_ascii_lowercase())
            .unwrap_or_else(|| "text".to_string()),
        other => other.to_string(),
    };

    let has_default_value = match tag {
        "textarea" => !el.text().collect::<String>().trim().is_empty(),
        "select" => el.select(&SELECTED_OPTION).next().is_some(),
        _ => el.attr("value").is_some_and(|v| !v.is_empty()),
    };

    FormInput {
        name: el
            .attr("name")
            .map(str::to_string)
            .filter(|n| !n.is_empty()),
        input_type,
        required: el.attr("required").is_some(),
        has_default_value,
        max_length: el
            .attr("maxlength")
            .and_then(|m| m.trim().parse::<i64>().ok()),
    }
}
/// `content="0; url=/next"` -> `/next`
fn parse_meta_refresh(content: &str) -> Option<String> {
    let (_, rest) = content.split_once(';')?;
    let rest = rest.trim();
    let value = rest
        .get(..4)
        .filter(|p| p.eq_ignore_ascii_case("url="))
        .map(|_| &rest[4..])?;
    let value = value.trim().trim_matches(['"', '\'']);
    (!value.is_empty()).then(|| value.to_string())
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}







#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r##"
      <html><head><title>  Login   Page </title><base href="/app/">
      <meta http-equiv="Refresh" content="0; url=/welcome">
      <script src="https://cdn.test/a.js" integrity="sha384-x" crossorigin="anonymous"></script>
      <script>var a = 1;</script>
      </head><body>
      <a href="/about">About</a><a href="#top">skip</a><a href="javascript:void(0)">js</a>
      <iframe src="/embed"></iframe>
      <form id="login" action="/auth" method="post" enctype="multipart/form-data">
        <input name="user" type="text" required maxlength="64">
        <input name="pass" type="password">
        <input name="csrf" type="hidden" value="TOKENVALUE">
        <textarea name="note">hi</textarea>
        <select name="role"><option selected>admin</option></select>
        <input type="submit" value="Go">
      </form>
      <input name="outside" type="file" form="login">
      </body></html>
    "##;

    /// Every selector is a compile-time constant, but `Selector::parse` is a
    /// runtime call: a typo panics on first use and poisons the `LazyLock` for
    /// every later caller. One test makes that a build failure instead.
    #[test]
    fn every_static_selector_parses() {
        LazyLock::force(&TITLE);
        LazyLock::force(&BASE);
        LazyLock::force(&ANCHOR);
        LazyLock::force(&FRAME);
        LazyLock::force(&FORM);
        LazyLock::force(&SCRIPT);
        LazyLock::force(&META_REFRESH);
        LazyLock::force(&FIELD);
        LazyLock::force(&OWNED_FIELD);
        LazyLock::force(&SELECTED_OPTION);
    }

    #[test]
    fn title_base_and_links() {
        let e = extract(PAGE);
        assert_eq!(e.title.as_deref(), Some("Login Page"));
        assert_eq!(e.base_href.as_deref(), Some("/app/"));
        let hrefs: Vec<&str> = e.links.iter().map(|(h, _)| h.as_str()).collect();
        assert!(hrefs.contains(&"/about"));
        assert!(hrefs.contains(&"/embed"));
        assert!(hrefs.contains(&"/welcome"), "meta refresh target");
        // Fragment-only links are navigation, not new pages.
        assert!(!hrefs.iter().any(|h| h.starts_with('#')));
        // `javascript:` survives extraction and is rejected later by Scope.
        assert!(hrefs.contains(&"javascript:void(0)"));
    }

    #[test]
    fn form_fields_including_adopted_ones() {
        let e = extract(PAGE);
        let f = &e.forms[0];
        assert_eq!(f.method, "POST");
        assert_eq!(f.action.as_deref(), Some("/auth"));
        assert_eq!(f.enctype.as_deref(), Some("multipart/form-data"));

        let by_name = |n: &str| {
            f.inputs
                .iter()
                .find(|i| i.name.as_deref() == Some(n))
                .unwrap()
        };
        assert_eq!(by_name("user").input_type, "text");
        assert!(by_name("user").required);
        assert_eq!(by_name("user").max_length, Some(64));
        assert_eq!(by_name("pass").input_type, "password");
        assert_eq!(by_name("note").input_type, "textarea");
        assert!(by_name("note").has_default_value);
        assert!(by_name("role").has_default_value);
        // `form="login"` on an element outside the <form> element.
        assert_eq!(by_name("outside").input_type, "file");
    }

    #[test]
    fn hidden_field_values_are_not_retained() {
        let e = extract(PAGE);
        let csrf = e.forms[0]
            .inputs
            .iter()
            .find(|i| i.name.as_deref() == Some("csrf"))
            .unwrap();
        assert!(csrf.has_default_value);
        assert!(!format!("{csrf:?}").contains("TOKENVALUE"));
    }

    #[test]
    fn scripts_external_and_inline() {
        let e = extract(PAGE);
        let ext = e.scripts.iter().find(|s| s.src.is_some()).unwrap();
        assert_eq!(ext.integrity.as_deref(), Some("sha384-x"));
        let inline = e.scripts.iter().find(|s| s.src.is_none()).unwrap();
        assert_eq!(inline.body_bytes, Some("var a = 1;".len() as i64));
        assert_eq!(inline.body_sha256.as_ref().unwrap().len(), 64);
        assert!(!format!("{inline:?}").contains("var a = 1"));
    }

    #[test]
    fn method_defaults_to_get_and_junk_methods_are_ignored() {
        let e = extract(r#"<form action="/a"></form><form method="PUT" action="/b"></form>"#);
        assert_eq!(e.forms[0].method, "GET");
        assert_eq!(e.forms[1].method, "GET");
    }
}
