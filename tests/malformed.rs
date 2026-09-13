//! Stress tests for malformed and hostile input to the extractor.
//!
//! Everything here is pointed at input an attacker chooses. The bar is not
//! "produces good output" but "cannot be made to panic, cannot be made to burn
//! unbounded CPU, and never retains something it promised not to".
//!
//! Engine-level hostility -- lying `Content-Length`, redirect loops, truncated
//! bodies -- lives in `hostile_engine.rs`, which needs a server that can speak
//! broken HTTP.

use std::time::{Duration, Instant};

use surfmap::extract::html::RawExtract;
use surfmap::extract::{cookies, headers, html, params};
use surfmap::model::ParamSource;
use surfmap::robots::RobotsRules;
use surfmap::scope::{Scope, ScopePolicy, normalize, signature};
use url::Url;

/// Extraction must finish well inside this. The parser runs on the blocking
/// pool, so an input that takes minutes is a denial of service against the
/// crawler even though it never crashes.
const BUDGET: Duration = Duration::from_secs(5);

fn extract_within_budget(label: &str, doc: &str) -> RawExtract {
    let started = Instant::now();
    let out = html::extract(doc);
    let elapsed = started.elapsed();
    assert!(
        elapsed < BUDGET,
        "{label}: extraction took {elapsed:?} for {} bytes -- unbounded work on \
         attacker-controlled input",
        doc.len()
    );
    out
}

// ---------------------------------------------------------------------------
// Titles
// ---------------------------------------------------------------------------

/// `String::truncate` is byte-indexed and panics off a char boundary. A title
/// long enough to truncate, in any script that is not ASCII, lands there --
/// and the panic loses the whole page's extraction, not just its title.
#[test]
fn long_titles_in_every_script_survive_truncation() {
    // Each of these has a different byte-per-char width, and the prefixes shift
    // the limit on and off a char boundary.
    let scripts = [
        ("latin", "é"),
        ("greek", "λ"),
        ("cyrillic", "д"),
        ("euro-sign", "€"),
        ("japanese", "日"),
        ("emoji", "😀"),
        ("combining", "é"), // e + U+0301
        ("rtl", "ع"),
    ];
    for (name, ch) in scripts {
        for prefix in ["", "a", "ab", "abc"] {
            let title = format!("{prefix}{}", ch.repeat(400));
            let doc = format!("<html><head><title>{title}</title></head><body><a href=/x>l</a>");
            let e = extract_within_budget(name, &doc);
            let got = e.title.unwrap_or_default();
            assert!(
                got.chars().count() <= 300,
                "{name}/{prefix:?}: title not truncated ({} chars)",
                got.chars().count()
            );
            assert!(!got.is_empty(), "{name}/{prefix:?}: title lost entirely");
            // The rest of the page must still be extracted.
            assert_eq!(e.links.len(), 1, "{name}/{prefix:?}: extraction was lost");
        }
    }
}

#[test]
fn titles_made_only_of_whitespace_and_controls_do_not_break() {
    for junk in [
        "<title>   \t\n  </title>",
        "<title>\u{0}\u{0}\u{0}</title>",
        "<title>\u{feff}</title>",
        "<title></title>",
        "<title>\u{200b}\u{200b}</title>",
    ] {
        let e = extract_within_budget("blank title", junk);
        let _ = e.title.map(|t| t.chars().count());
    }
}

// ---------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------

/// `Html::parse_document` is quadratic in nesting depth. Left unbounded, a
/// document well inside the default body cap costs minutes of CPU per page.
#[test]
fn pathological_nesting_is_bounded() {
    for n in [10_000usize, 50_000, 200_000] {
        let doc = "<div>".repeat(n);
        extract_within_budget(&format!("{n} nested divs"), &doc);
    }
    // Mixed with closes, and with content the parser must still reach.
    let doc = format!(
        "{}<a href=/x>y</a>{}",
        "<span>".repeat(100_000),
        "</span>".repeat(50_000)
    );
    extract_within_budget("deep spans around a link", &doc);
}

/// The nesting guard must not fire on markup real sites produce. 256 is far
/// past anything a template engine emits; a page nested 60 deep is ordinary.
#[test]
fn realistic_nesting_is_untouched() {
    for depth in [1usize, 10, 60, 200] {
        let doc = format!(
            "<html><body>{}<form action=/a><input name=q></form><a href=/deep>x</a>{}</body></html>",
            "<div>".repeat(depth),
            "</div>".repeat(depth)
        );
        let e = extract_within_budget(&format!("depth {depth}"), &doc);
        assert_eq!(e.forms.len(), 1, "form lost at depth {depth}");
        assert!(
            e.links.iter().any(|(h, _)| h == "/deep"),
            "link lost at depth {depth}"
        );
    }
}

/// A run of void elements is not nesting, and must not be counted as such.
#[test]
fn void_elements_do_not_count_as_depth() {
    let doc = format!("{}<a href=/after>x</a>", "<br>".repeat(5_000));
    let e = extract_within_budget("5000 br", &doc);
    assert!(
        e.links.iter().any(|(h, _)| h == "/after"),
        "a run of <br> was mistaken for 5000 levels of nesting"
    );
    let doc = format!("{}<a href=/after>x</a>", "<img src=/i.png>".repeat(5_000));
    let e = extract_within_budget("5000 img", &doc);
    assert!(e.links.iter().any(|(h, _)| h == "/after"));
}

/// Comments and doctypes may contain `<`, which a naive depth scan would count.
#[test]
fn comments_and_doctypes_do_not_confuse_the_depth_scan() {
    let doc = format!(
        "<!doctype html><!-- {} --><a href=/after>x</a>",
        "<div>".repeat(2_000)
    );
    let e = extract_within_budget("divs inside a comment", &doc);
    assert!(
        e.links.iter().any(|(h, _)| h == "/after"),
        "markup inside a comment was counted as nesting"
    );
    // Unterminated comment: must not loop or index out of bounds.
    extract_within_budget(
        "unterminated comment",
        &format!("<!-- {}", "<div>".repeat(1_000)),
    );
    extract_within_budget("unterminated tag", &format!("<div {}", "a".repeat(10_000)));
    extract_within_budget("bare lt", &"<".repeat(50_000));
    extract_within_budget("lt slash", &"</".repeat(50_000));
}

#[test]
fn enormous_documents_stay_within_their_per_page_caps() {
    let doc: String = (0..20_000)
        .map(|i| {
            format!(
                "<a href=/link{i}>l</a><form action=/f{i}></form><script src=/s{i}.js></script>"
            )
        })
        .collect();
    let e = extract_within_budget("20k of everything", &doc);
    // The caps live in extract::resolve, but the raw extractor must at least
    // return in time and produce coherent records.
    let page = Url::parse("https://e.com/").unwrap();
    let scope = Scope::new(&page, ScopePolicy::Host, &[]).unwrap();
    let r = surfmap::extract::resolve(e, &page, &scope);
    assert!(
        r.links.len() <= 5_000,
        "link cap not applied: {}",
        r.links.len()
    );
    assert!(
        r.forms.len() <= 500,
        "form cap not applied: {}",
        r.forms.len()
    );
    assert!(
        r.scripts.len() <= 500,
        "script cap not applied: {}",
        r.scripts.len()
    );
}

#[test]
fn a_single_enormous_attribute_does_not_blow_up() {
    for size in [1_000usize, 100_000, 1_000_000] {
        let doc = format!("<a href=\"{}\">x</a>", "a".repeat(size));
        extract_within_budget(&format!("{size}-byte href"), &doc);
        let doc = format!(
            "<input name=\"{}\" value=\"{}\">",
            "n".repeat(size),
            "v".repeat(size)
        );
        extract_within_budget(&format!("{size}-byte input attrs"), &doc);
    }
}

// ---------------------------------------------------------------------------
// Attributes and values
// ---------------------------------------------------------------------------

#[test]
fn numeric_attributes_reject_nonsense_without_panicking() {
    let e = extract_within_budget(
        "maxlength",
        "<form>\
           <input name=a maxlength=99999999999999999999999>\
           <input name=b maxlength=-5>\
           <input name=c maxlength=€>\
           <input name=d maxlength=>\
           <input name=e maxlength=\" 12 \">\
         </form>",
    );
    let by = |n: &str| {
        e.forms[0]
            .inputs
            .iter()
            .find(|i| i.name.as_deref() == Some(n))
            .unwrap()
    };
    assert_eq!(by("a").max_length, None, "overflow must not wrap");
    assert_eq!(by("b").max_length, Some(-5), "parsed, even if meaningless");
    assert_eq!(by("c").max_length, None);
    assert_eq!(by("d").max_length, None);
    assert_eq!(by("e").max_length, Some(12), "whitespace is trimmed");
}

#[test]
fn meta_refresh_variants_never_panic_and_never_invent_a_target() {
    // The parser slices at byte 4 to test for `url=`; a multibyte character
    // straddling that index would panic on a naive implementation.
    for content in [
        "0; url=/next",
        "0;url=/next",
        "0; URL=/next",
        "0; UrL='/next'",
        "0; url=\"/next\"",
        "url=/next", // no delimiter
        ";",         // nothing after
        "0;",        // empty target
        "0; url=",   // empty value
        "€€€€=/x",   // multibyte at the slice point
        "0; €€=/x",
        "0; url=€",
        "\u{0}; url=/x",
        &format!("0; url={}", "a".repeat(100_000)),
    ] {
        let doc = format!("<meta http-equiv=\"refresh\" content=\"{content}\">");
        let e = extract_within_budget("meta refresh", &doc);
        for (href, _) in &e.links {
            assert!(!href.is_empty(), "empty redirect target from {content:?}");
        }
    }
}

#[test]
fn base_href_junk_cannot_redirect_extraction_off_host() {
    let page = Url::parse("https://e.com/dir/page").unwrap();
    let scope = Scope::new(&page, ScopePolicy::Host, &[]).unwrap();
    for base in [
        "::::",
        "javascript:alert(1)",
        "data:text/html,x",
        "//evil.test/",
        "https://evil.test/",
        "",
        "\u{0}",
        &"../".repeat(10_000),
    ] {
        let doc = format!("<base href=\"{base}\"><a href=\"x\">y</a>");
        let raw = extract_within_budget("base href", &doc);
        let r = surfmap::extract::resolve(raw, &page, &scope);
        for link in &r.links {
            // Whatever base does to resolution, the scope flag must agree with
            // the host that actually came out of it.
            let expected = link.url.host_str() == Some("e.com");
            assert_eq!(
                link.in_scope, expected,
                "base={base:?} produced {} flagged in_scope={}",
                link.url, link.in_scope
            );
        }
    }
}

#[test]
fn unusual_form_shapes_stay_inside_their_documented_domains() {
    for doc in [
        "<form><form><form><input name=a></form></form></form>",
        "<form method=PUT action=/x><input name=a></form>",
        "<form method=\"  post  \"><input name=a></form>",
        "<form method=€><input name=a></form>",
        "<form id=x></form><input name=outside form=x>",
        "<form id=x></form><input name=o1 form=x><input name=o2 form=x>",
        "<form id=x></form><input name=o form=y>", // owner that does not exist
        "<input name=orphan>",                     // no form at all
        "<form><select name=s></select><textarea name=t></textarea><button name=b></button></form>",
    ] {
        let e = extract_within_budget("form shape", doc);
        for form in &e.forms {
            assert!(
                matches!(form.method.as_str(), "GET" | "POST" | "DIALOG"),
                "method escaped its set: {:?} from {doc}",
                form.method
            );
            for input in &form.inputs {
                assert!(!input.input_type.is_empty(), "empty input type from {doc}");
                assert!(input.name.as_ref().is_none_or(|n| !n.is_empty()));
            }
        }
    }
}

/// Hidden field values, inline script bodies and `value=` attributes are the
/// things the schema promises never to keep.
#[test]
fn no_input_value_or_script_body_survives_extraction() {
    const CANARY: &str = "CANARY-SECRET-VALUE-8f3a";
    let doc = format!(
        "<html><head><title>{CANARY}-title</title></head><body>\
           <form><input type=hidden name=csrf value=\"{CANARY}\">\
           <textarea name=t>{CANARY}</textarea>\
           <select name=s><option selected>{CANARY}</option></select></form>\
           <script>var secret = \"{CANARY}\";</script></body></html>"
    );
    let e = extract_within_budget("canary", &doc);
    let rendered = format!("{:?}{:?}", e.forms, e.scripts);
    assert!(
        !rendered.contains(CANARY),
        "a value survived extraction: {rendered}"
    );
    // The hash is kept, and it is a hash.
    let inline = e.scripts.iter().find(|s| s.src.is_none()).unwrap();
    assert_eq!(inline.body_sha256.as_ref().unwrap().len(), 64);
}

// ---------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------

#[test]
fn hostile_urls_never_pass_a_scope_check_they_should_fail() {
    let seed = Url::parse("https://target.test/").unwrap();
    for policy in [ScopePolicy::Host, ScopePolicy::Subdomains] {
        let scope = Scope::new(&seed, policy, &[]).unwrap();
        for candidate in [
            "https://target.test.evil.test/",
            "https://eviltarget.test/",
            "https://target.test@evil.test/",
            "https://evil.test/?x=https://target.test/",
            "https://evil.test/#https://target.test/",
            "https://TARGET.TEST.evil.test/",
            "https://target.test%2eevil.test/",
            "https://[::1]/",
            "javascript:alert(1)//target.test",
            "https://target.test:8080@evil.test/",
        ] {
            let Ok(u) = Url::parse(candidate) else {
                continue;
            };
            assert!(
                !scope.contains(&u),
                "{policy:?} accepted {candidate} (host={:?})",
                u.host_str()
            );
            // And normalizing it must not change that answer.
            assert_eq!(
                scope.contains(&u),
                scope.contains(&normalize(&u)),
                "normalization flipped the scope decision for {candidate}"
            );
        }
    }
}

/// Credentials in a URL must never reach storage. The schema has no column for
/// a secret, and `pages.url` is not a loophole in that.
#[test]
fn credentials_are_stripped_before_a_url_can_be_stored() {
    for raw in [
        "https://admin:hunter2@target.test/x",
        "https://apikey@target.test/x",
        "https://user:@target.test/x",
        "https://:pass@target.test/x",
    ] {
        let n = normalize(&Url::parse(raw).unwrap());
        assert_eq!(n.username(), "", "username survived: {n}");
        assert_eq!(n.password(), None, "password survived: {n}");
        assert!(!n.as_str().contains("hunter2"), "password in URL: {n}");
        assert!(!n.as_str().contains("apikey"), "username in URL: {n}");
        assert_eq!(n.host_str(), Some("target.test"), "host changed: {n}");
    }
}

#[test]
fn normalization_is_idempotent_on_awkward_urls() {
    for raw in [
        "https://e.com",
        "https://e.com:443/",
        "http://e.com:80/",
        "https://E.CoM/PathCase",
        "https://e.com/?",
        "https://e.com/?&&&",
        "https://e.com/?b=2&a=1&a=0",
        "https://e.com/%ZZ",
        "https://e.com/%2e%2e/",
        "https://e.com/a/../b",
        "https://[::1]:443/",
        "https://e.com/?x=%00",
        "https://e.com/#",
        "https://user:p@e.com/",
    ] {
        let Ok(u) = Url::parse(raw) else { continue };
        let once = normalize(&u);
        let twice = normalize(&once);
        assert_eq!(once.as_str(), twice.as_str(), "not idempotent: {raw}");
        assert!(once.fragment().is_none(), "fragment survived: {raw}");
        assert!(!once.path().is_empty(), "empty path: {raw}");
        // A stable signature is what bounds crawler traps.
        assert_eq!(signature(&once), signature(&twice));
    }
}

#[test]
fn parameter_extraction_handles_hostile_query_strings() {
    for q in [
        "a=1&a=2&a=3",
        "=novalue",
        "novalue=",
        "&&&&",
        "a",
        "a=%00%01%02",
        "a=%",
        "a=%ZZ",
        &format!("a={}", "x".repeat(100_000)),
        &(0..5_000).map(|i| format!("k{i}=v&")).collect::<String>(),
        "a[]=1&a[]=2",
        "a=\u{202e}reversed",
    ] {
        let Ok(u) = Url::parse(&format!("https://e.com/?{q}")) else {
            continue;
        };
        let started = Instant::now();
        let ps = params::from_url(&u, ParamSource::SelfUrl);
        assert!(started.elapsed() < BUDGET, "slow query: {q:.60}");
        for p in &ps {
            assert!(!p.name.is_empty(), "empty parameter name from {q:.60}");
            assert!(!p.shape.is_empty());
            assert!(p.shape.chars().all(|c| c.is_ascii_lowercase()));
        }
    }
}

#[test]
fn shape_classification_never_echoes_a_value() {
    const SECRET: &str = "sk_live_51H8xQ2eZvKYlo2C";
    assert_ne!(params::classify(SECRET), SECRET);
    // Values that look like edge cases of the numeric rules.
    for (value, expected) in [
        ("-", "alnum"),
        ("--", "alnum"),
        ("-0", "numeric"),
        ("-42", "numeric"),
        ("+", "opaque"),
        ("", "empty"),
        ("   ", "empty"),
    ] {
        assert_eq!(
            params::classify(value),
            expected,
            "classify({value:?}) drifted"
        );
    }
}

// ---------------------------------------------------------------------------
// Cookies and headers
// ---------------------------------------------------------------------------

#[test]
fn malformed_set_cookie_headers_are_rejected_not_survived() {
    for header in [
        "", ";", ";;;;", "=", "=novalue", "   =x", "\u{0}=x", "name", "name;",
    ] {
        let got = cookies::parse_set_cookie(header);
        if let Some(c) = got {
            assert!(
                !c.name.trim().is_empty(),
                "empty cookie name from {header:?}"
            );
        }
    }
}

#[test]
fn enormous_and_exotic_cookies_do_not_retain_their_value() {
    const CANARY: &str = "CANARYCOOKIEVALUE";
    let cases = [
        format!("sid={CANARY}; HttpOnly; Secure; SameSite=Strict"),
        format!("sid={CANARY}{}; Path=/", "x".repeat(100_000)),
        format!("sid=a=b=c={CANARY}; Max-Age=1"),
        format!("sid={CANARY}; {}", "attr=v; ".repeat(5_000)),
        format!("\u{20AC}={CANARY}; Secure"),
        format!("sid={CANARY}; expires=not-a-date"),
        format!("sid={CANARY}; SameSite="),
    ];
    for header in &cases {
        let started = Instant::now();
        let parsed = cookies::parse_set_cookie(header);
        assert!(started.elapsed() < BUDGET, "slow cookie parse");
        if let Some(c) = parsed {
            let rendered = format!("{c:?}");
            assert!(
                !rendered.contains(CANARY),
                "cookie value survived: {rendered}"
            );
        }
    }
}

#[test]
fn credential_headers_are_redacted_whatever_their_value() {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    const CANARY: &str = "Bearer CANARY-TOKEN-VALUE";
    let mut h = HeaderMap::new();
    for name in [
        "set-cookie",
        "authorization",
        "proxy-authorization",
        "www-authenticate",
        "proxy-authenticate",
    ] {
        h.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(CANARY),
        );
    }
    // Mixed case must be redacted too -- header names are case-insensitive.
    h.insert("X-Safe", HeaderValue::from_static("keep-me"));
    let captured = headers::capture(&h);
    let rendered = format!("{captured:?}");
    assert!(
        !rendered.contains("CANARY-TOKEN-VALUE"),
        "a credential header leaked: {rendered}"
    );
    assert!(rendered.contains("keep-me"), "ordinary headers are kept");
}

// ---------------------------------------------------------------------------
// robots.txt
// ---------------------------------------------------------------------------

#[test]
fn pathological_robots_patterns_do_not_blow_up_matching() {
    let path = format!("/{}", "a".repeat(4_000));
    let patterns = [
        "*".repeat(1_000),
        "a*".repeat(500),
        format!("{}$", "a*".repeat(500)),
        format!("{}$", "*a".repeat(500)),
        format!("/{}*", "a".repeat(4_000)),
        "*/*/*/*/*/*/*/*/*/*/*/*/*/*/*/*$".to_string(),
    ];
    for pattern in &patterns {
        let text = format!("User-agent: *\nDisallow: {pattern}\n");
        let started = Instant::now();
        let rules = RobotsRules::parse(&text);
        let _ = rules.allows("surfmap/0.1.0", &path);
        assert!(
            started.elapsed() < BUDGET,
            "pattern took {:?}: {:.40}",
            started.elapsed(),
            pattern
        );
    }
}

#[test]
fn malformed_robots_files_never_loosen_a_denial() {
    let path = "/admin/secret";
    // Whatever noise surrounds it, a blanket disallow that applies to us wins.
    for noise in [
        "",
        "\u{feff}",
        "\r\n\r\n",
        "#comment\n",
        "Disallow: /x\n",                 // rule before any group
        "User-agent:\n",                  // empty agent
        "User-agent: *\nUser-agent: *\n", // repeated header
        "garbage without a colon\n",
        "Crawl-delay: not-a-number\n",
        "Crawl-delay: -5\n",
        "Crawl-delay: NaN\n",
        "Sitemap:\n",
        &"\n".repeat(10_000),
    ] {
        let text = format!("{noise}User-agent: *\nDisallow: /\n");
        assert!(
            !RobotsRules::parse(&text).allows("surfmap/0.1.0", path),
            "a blanket Disallow was bypassed with prefix {noise:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Byte-level junk
// ---------------------------------------------------------------------------

/// Nothing in the extractor may assume its input is valid, printable, or even
/// text-shaped. These are the inputs a fuzzer would reach first.
#[test]
fn arbitrary_byte_soup_is_survivable() {
    let page = Url::parse("https://e.com/").unwrap();
    let scope = Scope::new(&page, ScopePolicy::Host, &[]).unwrap();

    let mut docs: Vec<String> = vec![
        String::new(),
        "\u{0}".repeat(10_000),
        "\u{fffd}".repeat(10_000),
        "\u{feff}<html><a href=/x>y</a>".to_string(),
        "<<<<<>>>>>".repeat(5_000),
        "<a href='".repeat(10_000),
        "\"".repeat(50_000),
        "&".repeat(50_000),
        "&#x".repeat(20_000),
        "&#999999999;".repeat(5_000),
        "\r\n".repeat(50_000),
        "\u{202e}".repeat(10_000),
    ];
    // Every byte value, as lossy text -- what a binary response decodes to.
    docs.push(String::from_utf8_lossy(&(0u8..=255).collect::<Vec<u8>>()).into_owned());
    docs.push(
        String::from_utf8_lossy(&(0..20_000).map(|i| (i % 256) as u8).collect::<Vec<u8>>())
            .into_owned(),
    );

    for (i, doc) in docs.iter().enumerate() {
        let raw = extract_within_budget(&format!("byte soup #{i}"), doc);
        // Resolution must survive it too: that is where URLs get joined.
        let r = surfmap::extract::resolve(raw, &page, &scope);
        for link in &r.links {
            assert!(
                matches!(link.url.scheme(), "http" | "https"),
                "non-fetchable scheme reached the graph from doc #{i}: {}",
                link.url
            );
        }
    }
}
