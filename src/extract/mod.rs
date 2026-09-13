//! Turns a fetched response into the owned, scope-annotated data the storage
//! layer writes.

pub mod cookies;
pub mod headers;
pub mod html;
pub mod params;

use std::collections::HashSet;

use url::Url;

use crate::model::{FormRecord, LinkRecord, LinkType, ParamRecord, ParamSource, ScriptRecord};
use crate::scope::{Scope, normalize};

/// A single page can only contribute so much before it is a denial-of-service
/// vector against *us*. Pages beyond these bounds are truncated, not rejected.
const MAX_LINKS_PER_PAGE: usize = 5_000;
const MAX_FORMS_PER_PAGE: usize = 500;
const MAX_SCRIPTS_PER_PAGE: usize = 500;

#[derive(Debug, Default)]
pub struct Resolved {
    pub title: Option<String>,
    pub links: Vec<LinkRecord>,
    pub forms: Vec<FormRecord>,
    pub scripts: Vec<ScriptRecord>,
    pub params: Vec<ParamRecord>,
}

/// Resolve every relative reference against the page (honouring `<base href>`),
/// normalize it, and decide whether it is in scope.
pub fn resolve(raw: html::RawExtract, page_url: &Url, scope: &Scope) -> Resolved {
    let base = raw
        .base_href
        .as_deref()
        .and_then(|b| page_url.join(b).ok())
        .unwrap_or_else(|| page_url.clone());

    let page_host = page_url.host_str().map(|h| h.to_ascii_lowercase());
    let title = raw.title;

    let mut links = Vec::new();
    let mut seen_links: HashSet<(String, LinkType)> = HashSet::new();
    for (href, kind) in raw.links.into_iter().take(MAX_LINKS_PER_PAGE) {
        // A relative href that will not resolve is not an error worth reporting;
        // real pages carry plenty of them.
        let Ok(joined) = base.join(&href) else {
            continue;
        };
        // `javascript:`, `mailto:`, `tel:` and `data:` are not pages and must
        // not become nodes in the link graph. They are dropped here rather than
        // at the frontier so they never reach storage either.
        if !matches!(joined.scheme(), "http" | "https") {
            continue;
        }
        let url = normalize(&joined);
        if !seen_links.insert((url.as_str().to_string(), kind)) {
            continue;
        }
        links.push(LinkRecord {
            in_scope: scope.contains(&url),
            url,
            link_type: kind,
        });
    }

    let mut forms = Vec::new();
    for f in raw.forms.into_iter().take(MAX_FORMS_PER_PAGE) {
        let action_url = f
            .action
            .as_deref()
            .and_then(|a| base.join(a).ok())
            .map(|u| normalize(&u));
        let cross_origin = match (&action_url, &page_host) {
            (Some(a), Some(h)) => a.host_str().map(|x| x.to_ascii_lowercase()).as_ref() != Some(h),
            _ => false,
        };
        forms.push(FormRecord {
            action: action_url.map(|u| u.to_string()),
            method: f.method,
            enctype: f.enctype,
            name: f.name,
            dom_id: f.dom_id,
            cross_origin,
            inputs: f.inputs,
        });
    }

    let mut scripts = Vec::new();
    for s in raw.scripts.into_iter().take(MAX_SCRIPTS_PER_PAGE) {
        let resolved_src = s.src.as_deref().and_then(|src| base.join(src).ok());
        let host = resolved_src
            .as_ref()
            .and_then(|u| u.host_str())
            .map(|h| h.to_ascii_lowercase());
        let third_party = match (&host, &page_host) {
            (Some(h), Some(p)) => h != p,
            _ => false,
        };
        scripts.push(ScriptRecord {
            src: resolved_src.map(|u| u.to_string()),
            host,
            third_party,
            integrity: s.integrity,
            crossorigin: s.crossorigin,
            body_sha256: s.body_sha256,
            body_bytes: s.body_bytes,
        });
    }

    // Parameter catalog: the page's own query string, plus every parameter
    // carried by a link or a form action discovered on it.
    let mut params: Vec<ParamRecord> = params::from_url(page_url, ParamSource::SelfUrl);
    let mut seen: HashSet<ParamRecord> = params.iter().cloned().collect();
    for l in &links {
        for p in params::from_url(&l.url, ParamSource::Link) {
            if seen.insert(p.clone()) {
                params.push(p);
            }
        }
    }
    for f in &forms {
        let Some(action) = f.action.as_deref().and_then(|a| Url::parse(a).ok()) else {
            continue;
        };
        for p in params::from_url(&action, ParamSource::Form) {
            if seen.insert(p.clone()) {
                params.push(p);
            }
        }
    }

    Resolved {
        title,
        links,
        forms,
        scripts,
        params,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::ScopePolicy;

    fn scope_for(seed: &str) -> Scope {
        Scope::new(&Url::parse(seed).unwrap(), ScopePolicy::Host, &[]).unwrap()
    }

    #[test]
    fn relative_links_resolve_against_base_href() {
        let page = Url::parse("https://e.com/docs/index.html").unwrap();
        let raw = html::extract(r#"<base href="/app/"><a href="x.html">x</a>"#);
        let r = resolve(raw, &page, &scope_for("https://e.com/"));
        assert_eq!(r.links[0].url.as_str(), "https://e.com/app/x.html");
    }

    #[test]
    fn relative_links_resolve_against_page_without_base() {
        let page = Url::parse("https://e.com/docs/index.html").unwrap();
        let raw = html::extract(r#"<a href="x.html">x</a><a href="../up.html">u</a>"#);
        let r = resolve(raw, &page, &scope_for("https://e.com/"));
        let urls: Vec<&str> = r.links.iter().map(|l| l.url.as_str()).collect();
        assert!(urls.contains(&"https://e.com/docs/x.html"));
        assert!(urls.contains(&"https://e.com/up.html"));
    }

    #[test]
    fn out_of_scope_links_are_recorded_but_flagged() {
        let page = Url::parse("https://e.com/").unwrap();
        let raw = html::extract(r#"<a href="https://other.test/x">o</a><a href="/in">i</a>"#);
        let r = resolve(raw, &page, &scope_for("https://e.com/"));
        let ext = r
            .links
            .iter()
            .find(|l| l.url.host_str() == Some("other.test"))
            .unwrap();
        assert!(!ext.in_scope, "third-party links are kept as surface data");
        let int = r.links.iter().find(|l| l.url.path() == "/in").unwrap();
        assert!(int.in_scope);
    }

    #[test]
    fn non_fetchable_schemes_never_become_graph_nodes() {
        let page = Url::parse("https://e.com/").unwrap();
        let raw = html::extract(
            r#"<a href="javascript:alert(1)">x</a><a href="mailto:a@e.com">m</a>
               <a href="data:text/html,x">d</a><a href="/real">r</a>"#,
        );
        let r = resolve(raw, &page, &scope_for("https://e.com/"));
        assert_eq!(r.links.len(), 1);
        assert_eq!(r.links[0].url.path(), "/real");
    }

    #[test]
    fn cross_origin_form_action_is_flagged() {
        let page = Url::parse("https://e.com/login").unwrap();
        let raw =
            html::extract(r#"<form action="https://sso.other.test/post" method="post"></form>"#);
        let r = resolve(raw, &page, &scope_for("https://e.com/"));
        assert!(r.forms[0].cross_origin);
    }

    #[test]
    fn third_party_scripts_are_flagged() {
        let page = Url::parse("https://e.com/").unwrap();
        let raw = html::extract(
            r#"<script src="https://cdn.other.test/a.js"></script><script src="/own.js"></script>"#,
        );
        let r = resolve(raw, &page, &scope_for("https://e.com/"));
        assert!(
            r.scripts
                .iter()
                .any(|s| s.third_party && s.host.as_deref() == Some("cdn.other.test"))
        );
        assert!(r.scripts.iter().any(|s| !s.third_party));
    }

    #[test]
    fn params_are_collected_from_page_and_links() {
        let page = Url::parse("https://e.com/s?q=hello").unwrap();
        let raw = html::extract(r#"<a href="/item?id=42&ref=https://x.test">i</a>"#);
        let r = resolve(raw, &page, &scope_for("https://e.com/"));
        let has = |n: &str, s: &str| r.params.iter().any(|p| p.name == n && p.shape == s);
        assert!(has("q", "alnum"));
        assert!(has("id", "numeric"));
        assert!(has("ref", "url"));
    }
}
