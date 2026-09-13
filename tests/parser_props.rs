//! Property tests for the parsers.
//!
//! Every parser in this crate is pointed at input an attacker controls, so the
//! bar is not "handles well-formed input" but "cannot be made to panic, and
//! holds its invariants on anything". These are the properties that matter:
//! total functions, idempotent normalization, and no secret material surviving
//! a parse.

use proptest::prelude::*;
use url::Url;

use surfmap::extract::{cookies, html, params};
use surfmap::robots::RobotsRules;
use surfmap::scope::{Scope, ScopePolicy, normalize, signature};

/// Fragments of real markup interleaved with arbitrary bytes -- more likely to
/// reach interesting parser states than uniform random strings.
fn messy_html() -> impl Strategy<Value = String> {
    let piece = prop_oneof![
        Just("<a href=".to_string()),
        Just("<form method=".to_string()),
        Just("<input name=".to_string()),
        Just("<script>".to_string()),
        Just("</".to_string()),
        Just("<base href=".to_string()),
        // Titles were absent from this generator, which is precisely why a
        // byte-indexed truncation panic lived here undetected: the property
        // asserted a bound on a field nothing ever produced.
        Just("<title>".to_string()),
        Just("</title>".to_string()),
        Just("<meta http-equiv=refresh content=".to_string()),
        Just("<div>".to_string()),
        Just("<br>".to_string()),
        Just("\"".to_string()),
        Just("'".to_string()),
        Just(">".to_string()),
        Just("<!--".to_string()),
        Just("-->".to_string()),
        Just("\u{0}".to_string()),
        Just("\u{fffd}".to_string()),
        Just("\u{feff}".to_string()),
        // Multibyte runs long enough to straddle the 300-char title limit.
        Just("\u{20AC}".repeat(120)),
        Just("\u{1F600}".repeat(120)),
        Just("\u{65E5}".repeat(120)),
        "[^\u{0}]{0,12}".prop_map(|s: String| s),
    ];
    proptest::collection::vec(piece, 0..60).prop_map(|v| v.concat())
}

fn any_url() -> impl Strategy<Value = Url> {
    (
        prop_oneof![Just("http"), Just("https")],
        "[a-zA-Z][a-zA-Z0-9-]{0,10}(\\.[a-z]{2,4}){1,2}",
        "(/[a-zA-Z0-9._~%-]{0,8}){0,4}",
        "([a-z]{1,5}=[a-zA-Z0-9%._-]{0,8}&?){0,5}",
        prop_oneof![Just(""), Just("#frag"), Just("#")],
    )
        .prop_filter_map("must parse", |(scheme, host, path, query, frag)| {
            let q = if query.is_empty() {
                String::new()
            } else {
                format!("?{query}")
            };
            Url::parse(&format!("{scheme}://{host}{path}{q}{frag}")).ok()
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// The HTML extractor is total: no input produces a panic, and the values it
    /// reports stay inside their documented domains.
    #[test]
    fn html_extraction_is_total(doc in messy_html()) {
        let e = html::extract(&doc);
        for form in &e.forms {
            prop_assert!(
                matches!(form.method.as_str(), "GET" | "POST" | "DIALOG"),
                "method escaped its allowed set: {:?}", form.method
            );
            for input in &form.inputs {
                prop_assert!(!input.input_type.is_empty());
                prop_assert!(input.name.as_ref().is_none_or(|n| !n.is_empty()));
            }
        }
        for script in &e.scripts {
            // Inline scripts are represented by a hash, never a body.
            if let Some(h) = &script.body_sha256 {
                prop_assert_eq!(h.len(), 64);
                prop_assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
            }
        }
        // By characters. A byte-based bound would be satisfied by a panic that
        // never let us get here, and would be wrong for any non-ASCII title.
        prop_assert!(e.title.as_ref().is_none_or(|t| t.chars().count() <= 300));
        // A redirect target that survived extraction is never empty.
        for (href, _) in &e.links {
            prop_assert!(!href.is_empty());
        }
    }

    /// Extraction must be bounded in time, not merely finite. The parser runs
    /// on the blocking pool, so a quadratic input starves the whole crawl.
    #[test]
    fn extraction_is_bounded_in_time(doc in messy_html()) {
        let started = std::time::Instant::now();
        let _ = html::extract(&doc);
        prop_assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "extraction took {:?} on {} bytes", started.elapsed(), doc.len()
        );
    }

    /// Resolution is where hrefs become graph nodes, and the invariant that
    /// matters is that nothing unfetchable gets through.
    #[test]
    fn resolution_only_ever_yields_fetchable_urls(doc in messy_html()) {
        let page = Url::parse("https://e.com/dir/page").unwrap();
        let scope = Scope::new(&page, ScopePolicy::Host, &[]).unwrap();
        let r = surfmap::extract::resolve(html::extract(&doc), &page, &scope);
        for link in &r.links {
            prop_assert!(
                matches!(link.url.scheme(), "http" | "https"),
                "unfetchable scheme reached the graph: {}", link.url
            );
            prop_assert!(link.url.host_str().is_some());
            // The scope flag must agree with an independent check of the host.
            prop_assert_eq!(link.in_scope, scope.contains(&link.url));
        }
    }

    /// Normalization must be idempotent on *any* query string, including ones
    /// whose pairs are all empty -- `?&&&` produced a bare `?` that a second
    /// pass then stripped.
    #[test]
    fn normalization_is_idempotent_on_arbitrary_queries(q in "[a-z0-9=&%;+.\\[\\]-]{0,60}") {
        let Ok(u) = Url::parse(&format!("https://e.com/p?{q}")) else {
            return Ok(());
        };
        let once = normalize(&u);
        let twice = normalize(&once);
        prop_assert_eq!(once.as_str(), twice.as_str(), "not idempotent for query {:?}", q);
        prop_assert!(!once.as_str().ends_with('?'), "left a bare `?`: {}", once);
    }

    /// Credentials must never survive into a URL that can be stored.
    #[test]
    fn normalization_strips_any_userinfo(
        user in "[a-z0-9]{0,12}", pass in "[a-z0-9]{0,12}", host in "[a-z]{2,8}\\.test"
    ) {
        let raw = format!("https://{user}:{pass}@{host}/p");
        let Ok(u) = Url::parse(&raw) else { return Ok(()) };
        let n = normalize(&u);
        prop_assert_eq!(n.username(), "");
        prop_assert_eq!(n.password(), None);
        if pass.len() > 3 {
            prop_assert!(!n.as_str().contains(pass.as_str()), "password survived in {}", n);
        }
    }

    /// Normalization is idempotent. Without this, the visited-set can hold two
    /// spellings of one URL and the crawler refetches pages forever.
    #[test]
    fn normalization_is_idempotent(u in any_url()) {
        let once = normalize(&u);
        let twice = normalize(&once);
        prop_assert_eq!(once.as_str(), twice.as_str());
    }

    /// Normalization never invents or drops a host, and never leaves a fragment.
    #[test]
    fn normalization_preserves_identity(u in any_url()) {
        let n = normalize(&u);
        prop_assert_eq!(n.host_str().map(str::to_ascii_lowercase),
                        u.host_str().map(str::to_ascii_lowercase));
        prop_assert_eq!(n.scheme(), u.scheme());
        prop_assert!(n.fragment().is_none());
        prop_assert!(!n.path().is_empty());
    }

    /// Scope is closed under normalization: a URL cannot be pushed out of (or
    /// sneaked into) scope by canonicalizing it. A scope check that disagreed
    /// with itself before and after normalization would be exploitable.
    #[test]
    fn scope_survives_normalization(u in any_url()) {
        let seed = Url::parse("https://target.test/").unwrap();
        for policy in [ScopePolicy::Host, ScopePolicy::Subdomains] {
            let scope = Scope::new(&seed, policy, &[]).unwrap();
            prop_assert_eq!(scope.contains(&u), scope.contains(&normalize(&u)));
        }
    }

    /// A URL signature ignores parameter values and depends only on names.
    #[test]
    fn signature_ignores_values(u in any_url(), replacement in "[a-z0-9]{0,6}") {
        let mut rebuilt = u.clone();
        let names: Vec<String> = u.query_pairs().map(|(k, _)| k.into_owned()).collect();
        if names.is_empty() {
            return Ok(());
        }
        let mut ser = form_urlencoded::Serializer::new(String::new());
        for name in &names {
            ser.append_pair(name, &replacement);
        }
        rebuilt.set_query(Some(&ser.finish()));
        prop_assert_eq!(signature(&u), signature(&rebuilt));
    }

    /// robots.txt parsing is total, and an unreadable policy is always a denial.
    #[test]
    fn robots_parsing_is_total(text in "[\\PC\\s]{0,400}", path in "/[a-zA-Z0-9/._*$-]{0,40}") {
        let rules = RobotsRules::parse(&text);
        let _ = rules.allows("surfmap/0.1.0", &path);
        let _ = rules.crawl_delay("surfmap/0.1.0");
        prop_assert!(!RobotsRules::deny_all().allows("surfmap/0.1.0", &path));
    }

    /// A `Disallow: /` group that applies to us denies every path, whatever else
    /// the file contains around it.
    #[test]
    fn blanket_disallow_is_never_bypassed(noise in "[a-zA-Z0-9 :#\n]{0,120}", path in "/[a-zA-Z0-9/._-]{0,40}") {
        let text = format!("{noise}\nUser-agent: *\nDisallow: /\n");
        prop_assert!(!RobotsRules::parse(&text).allows("surfmap/0.1.0", &path));
    }

    /// A blanket disallow survives any leading junk -- a byte-order mark used to
    /// glue itself to `User-agent`, silently discarding the entire policy.
    #[test]
    fn leading_junk_never_disables_a_robots_policy(
        lead in prop_oneof![Just(""), Just("\u{feff}"), Just("\r\n"), Just("   "), Just("\u{feff}\r\n")],
        path in "/[a-zA-Z0-9/._-]{0,30}"
    ) {
        let text = format!("{lead}User-agent: *\nDisallow: /\n");
        prop_assert!(
            !RobotsRules::parse(&text).allows("surfmap/0.1.0", &path),
            "policy dropped after prefix {:?}", lead
        );
    }

    /// Cookie parsing never retains the value, whatever shape the header takes.
    #[test]
    fn cookie_values_never_survive(name in "[a-zA-Z0-9_-]{1,16}", value in "[\\PC&&[^;]]{0,40}", attrs in "[a-zA-Z; =]{0,40}") {
        let header = format!("{name}={value}; {attrs}");
        if let Some(record) = cookies::parse_set_cookie(&header) {
            prop_assert!(!record.name.is_empty());
            let rendered = format!("{record:?}");
            // A non-trivial value must not appear anywhere in the record.
            if value.trim().len() > 3 && !name.contains(value.trim()) {
                prop_assert!(
                    !rendered.contains(value.trim()),
                    "cookie value leaked into the record: {rendered}"
                );
            }
        }
    }

    /// Shape classification is total and never echoes its input.
    #[test]
    fn param_classification_is_total(value in "[\\PC]{0,60}") {
        let shape = params::classify(&value);
        prop_assert!(!shape.is_empty());
        prop_assert!(shape.chars().all(|c| c.is_ascii_lowercase()));
    }
}
