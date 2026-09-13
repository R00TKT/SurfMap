//! Path discovery: probing a wordlist against a directory.
//!
//! This is the one part of surfmap that sends requests the target never
//! advertised, which makes it the one part that can be noisy and the one part
//! that needs its own authorization. Everything else about it is deliberately
//! conventional -- the same wordlist-times-extensions expansion that `dirb`,
//! `gobuster` and `feroxbuster` do.
//!
//! The piece that is not optional is **calibration**. A large share of real
//! sites answer every unknown path with `200 OK` and a friendly "not found"
//! page, and a prober that trusts status codes reports every word in the list
//! as a hit. Before probing a directory, surfmap asks it for a path that cannot
//! exist and remembers what the answer looked like; candidates that look the
//! same are misses, whatever their status code says.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use reqwest::Client;
use sha2::{Digest, Sha256};
use url::Url;

use crate::model::PageObservation;
use crate::politeness::Politeness;

/// Status codes reported as hits when nothing else is specified.
///
/// 404 is absent for the obvious reason; 403 and 401 are present because "you
/// may not look at this" is a discovery, often the most interesting one.
pub const DEFAULT_ACCEPT: &[u16] = &[200, 204, 301, 302, 307, 308, 401, 403, 405];

/// Which response codes count as a discovery.
#[derive(Debug, Clone)]
pub struct StatusFilter {
    codes: Vec<u16>,
    ranges: Vec<(u16, u16)>,
}

impl StatusFilter {
    pub fn new(codes: Vec<u16>) -> Self {
        StatusFilter {
            codes,
            ranges: Vec::new(),
        }
    }

    /// Parse `200,204,301-308`.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut codes = Vec::new();
        let mut ranges = Vec::new();
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            match part.split_once('-') {
                Some((lo, hi)) => {
                    let lo: u16 = parse_code(lo)?;
                    let hi: u16 = parse_code(hi)?;
                    if lo > hi {
                        return Err(format!("`{part}` is backwards; write {hi}-{lo}"));
                    }
                    ranges.push((lo, hi));
                }
                None => codes.push(parse_code(part)?),
            }
        }
        if codes.is_empty() && ranges.is_empty() {
            return Err("no status codes given".to_string());
        }
        Ok(StatusFilter { codes, ranges })
    }

    pub fn contains(&self, status: u16) -> bool {
        self.codes.contains(&status)
            || self
                .ranges
                .iter()
                .any(|&(lo, hi)| status >= lo && status <= hi)
    }
}

impl Default for StatusFilter {
    fn default() -> Self {
        StatusFilter::new(DEFAULT_ACCEPT.to_vec())
    }
}

fn parse_code(s: &str) -> Result<u16, String> {
    let code: u16 = s
        .trim()
        .parse()
        .map_err(|_| format!("`{s}` is not an HTTP status code"))?;
    if !(100..=599).contains(&code) {
        return Err(format!("`{code}` is not in the range 100-599"));
    }
    Ok(code)
}

/// What a directory answers for a path that does not exist.
#[derive(Debug, Clone, PartialEq)]
pub struct Baseline {
    pub status: u16,
    /// Miss pages are usually HTML even where the real file is not, so a
    /// differing content type is by itself enough to say "not a miss".
    pub content_type: Option<String>,
    /// Body length of a miss, with the requested path's length subtracted when
    /// `echoes_path` is set. Absent when there was no measurable body.
    pub len: Option<u64>,
    /// True when the miss body grows with the length of the requested path,
    /// which is what "Nothing at /x/y" pages do.
    pub echoes_path: bool,
    /// True when two nonsense paths produced answers that fit no pattern, so
    /// only the status filter can be trusted.
    pub unstable: bool,
}

impl Baseline {
    /// Only the status filter applies; nothing can be fingerprinted.
    fn unstable() -> Self {
        Baseline {
            status: 0,
            content_type: None,
            len: None,
            echoes_path: false,
            unstable: true,
        }
    }

    /// Learn the shape of a directory's miss from two samples whose paths are
    /// deliberately different lengths.
    ///
    /// If the two bodies differ by exactly the difference in path length, the
    /// page embeds the path and its length is only meaningful once that is
    /// subtracted. If the two bodies are the same length, the page is constant.
    /// Anything else is not a pattern worth trusting.
    fn learn(a: &Sample, b: &Sample) -> Self {
        if a.status != b.status || a.content_type != b.content_type {
            return Baseline::unstable();
        }
        let common = Baseline {
            status: a.status,
            content_type: a.content_type.clone(),
            len: None,
            echoes_path: false,
            unstable: false,
        };
        match (a.len, b.len) {
            (Some(la), Some(lb)) => {
                let norm_a = la as i64 - a.path_len as i64;
                let norm_b = lb as i64 - b.path_len as i64;
                if norm_a == norm_b && norm_a >= 0 {
                    Baseline {
                        len: Some(norm_a as u64),
                        echoes_path: true,
                        ..common
                    }
                } else if la == lb {
                    Baseline {
                        len: Some(la),
                        ..common
                    }
                } else {
                    Baseline::unstable()
                }
            }
            (None, None) => common,
            _ => Baseline::unstable(),
        }
    }

    /// Does this response look like the directory's "not found" answer?
    pub fn looks_like_miss(
        &self,
        status: u16,
        content_type: Option<&str>,
        len: Option<u64>,
        path_len: usize,
    ) -> bool {
        if self.unstable || self.status != status {
            return false;
        }
        // A different media type is a different kind of response, whatever its
        // length works out to: a .sql dump is not the HTML apology page.
        if self.content_type.as_deref().map(base_media_type) != content_type.map(base_media_type) {
            return false;
        }
        match (self.len, len) {
            (Some(expected), Some(actual)) => {
                let normalized = if self.echoes_path {
                    actual as i64 - path_len as i64
                } else {
                    actual as i64
                };
                // Tight, because the path-length variance has already been
                // removed. What is left is genuine content difference.
                let slack = (expected / 50).max(8) as i64;
                (normalized - expected as i64).abs() <= slack
            }
            (None, None) => true,
            _ => false,
        }
    }
}

/// One calibration request.
#[derive(Debug, Clone)]
struct Sample {
    status: u16,
    content_type: Option<String>,
    len: Option<u64>,
    /// Length of the URL path requested, which is what a miss page echoes.
    path_len: usize,
}

/// `text/html; charset=utf-8` -> `text/html`.
fn base_media_type(ct: &str) -> &str {
    ct.split(';').next().unwrap_or(ct).trim()
}

pub struct Discovery {
    words: Arc<Vec<String>>,
    /// Appended to every word: `admin` + `php` -> `admin.php`.
    extensions: Vec<String>,
    accept: StatusFilter,
    /// How many directory levels deep to keep probing. 0 probes only the seed.
    pub recurse_depth: u32,
    /// Per-directory miss fingerprints, learned once and reused.
    baselines: DashMap<String, Arc<Baseline>>,
    /// Serializes calibration so N workers reaching a new directory together
    /// issue one calibration request rather than N.
    calibrating: DashMap<String, Arc<tokio::sync::Mutex<()>>>,
    probes_sent: AtomicU64,
    hits: AtomicU64,
}

impl Discovery {
    pub fn new(
        words: Vec<String>,
        extensions: Vec<String>,
        accept: StatusFilter,
        recurse_depth: u32,
    ) -> Self {
        Discovery {
            words: Arc::new(words),
            extensions,
            accept,
            recurse_depth,
            baselines: DashMap::new(),
            calibrating: DashMap::new(),
            probes_sent: AtomicU64::new(0),
            hits: AtomicU64::new(0),
        }
    }

    pub fn word_count(&self) -> usize {
        self.words.len()
    }

    /// Requests one full pass over a directory will make.
    pub fn candidates_per_dir(&self) -> usize {
        self.words.len() * (1 + self.extensions.len())
    }

    pub fn probes_sent(&self) -> u64 {
        self.probes_sent.load(Ordering::Relaxed)
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Every URL to try inside `dir`, which must end in `/`.
    pub fn candidates(&self, dir: &Url) -> Vec<Url> {
        let mut out = Vec::with_capacity(self.candidates_per_dir());
        for word in self.words.iter() {
            if let Ok(u) = dir.join(word) {
                out.push(u);
            }
            // A word ending in `/` is already asking for a directory; adding
            // `.php` to it would be nonsense.
            if word.ends_with('/') {
                continue;
            }
            for ext in &self.extensions {
                if let Ok(u) = dir.join(&format!("{word}.{ext}")) {
                    out.push(u);
                }
            }
        }
        self.probes_sent
            .fetch_add(out.len() as u64, Ordering::Relaxed);
        out
    }

    /// Learn (once) what `dir` says about a path that cannot exist.
    ///
    /// Two nonsense paths are requested, not one: if a directory answers them
    /// differently its misses carry per-request content and cannot be
    /// fingerprinted by length, so the baseline is marked unstable and only the
    /// status filter applies.
    pub async fn baseline_for(
        &self,
        client: &Client,
        politeness: &Politeness,
        dir: &Url,
    ) -> Arc<Baseline> {
        let key = dir.as_str().to_string();
        if let Some(hit) = self.baselines.get(&key) {
            return hit.clone();
        }

        // Clone the lock out and drop the map guard before awaiting; holding a
        // DashMap reference across an await is the deadlock this avoids.
        let lock = self
            .calibrating
            .entry(key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = lock.lock().await;
        if let Some(hit) = self.baselines.get(&key) {
            return hit.clone();
        }

        // Two samples, with deliberately different path lengths: comparing
        // them is what reveals whether the miss page embeds the path.
        let first = self.probe_nonexistent(client, politeness, dir, 24).await;
        let second = self.probe_nonexistent(client, politeness, dir, 40).await;

        let baseline = Arc::new(match (first, second) {
            (Some(a), Some(b)) => Baseline::learn(&a, &b),
            // Calibration failed (connection error, robots, timeout). Fall back
            // to status filtering alone rather than inventing a fingerprint.
            _ => Baseline::unstable(),
        });

        tracing::debug!(
            dir = %dir,
            status = baseline.status,
            content_type = ?baseline.content_type,
            len = ?baseline.len,
            echoes_path = baseline.echoes_path,
            unstable = baseline.unstable,
            "calibrated"
        );
        self.baselines.insert(key, baseline.clone());
        baseline
    }

    async fn probe_nonexistent(
        &self,
        client: &Client,
        politeness: &Politeness,
        dir: &Url,
        segment_len: usize,
    ) -> Option<Sample> {
        let Ok(url) = dir.join(&nonexistent_segment(segment_len)) else {
            return None;
        };
        // Calibration is a real request to the target and is rate limited like
        // any other. robots.txt is checked too: if the directory is disallowed,
        // calibration fails and the probes will be skipped anyway.
        politeness.clear_to_fetch(&url).await.ok()?;
        let response = client.get(url.clone()).send().await.ok()?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_ascii_lowercase());
        let declared = response.content_length();
        // Prefer the actual body length; `Content-Length` is absent on chunked
        // responses and can be wrong.
        let len = match response.bytes().await {
            Ok(body) => Some(body.len() as u64),
            Err(_) => declared,
        };
        Some(Sample {
            status,
            content_type,
            len,
            path_len: url.path().len(),
        })
    }

    /// Is this probe response a discovery rather than a dressed-up miss?
    pub fn is_hit(&self, baseline: &Baseline, obs: &PageObservation) -> bool {
        let len = obs.body_bytes.or(obs.content_length);
        if baseline.looks_like_miss(
            obs.status,
            obs.content_type.as_deref(),
            len,
            obs.url.path().len(),
        ) {
            return false;
        }
        self.accept.contains(obs.status)
    }
}

/// A path segment of exactly `len` characters that will not exist, different on
/// every call.
///
/// The length is a parameter because calibration needs two probes whose paths
/// differ in length: comparing the two response sizes is what tells surfmap
/// whether the miss page echoes the path back.
fn nonexistent_segment(len: usize) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut out = String::with_capacity(len);
    let mut round = 0u64;
    while out.len() < len {
        let digest = Sha256::digest(format!("surfmap-calibration-{n}-{nanos}-{round}").as_bytes());
        for b in digest.iter() {
            if out.len() >= len {
                break;
            }
            out.push_str(&format!("{b:02x}"));
        }
        round += 1;
    }
    out.truncate(len);
    out
}

/// The directory a probe lives in, used to look up its baseline.
pub fn parent_dir(url: &Url) -> Option<Url> {
    let mut dir = url.clone();
    dir.set_query(None);
    dir.set_fragment(None);
    let path = dir.path().to_string();
    let cut = path.trim_end_matches('/').rfind('/')?;
    dir.set_path(&path[..=cut]);
    Some(dir)
}

/// Whether a discovered URL is itself a directory worth probing.
///
/// Two signals: the URL already ends in `/`, or the server redirected the
/// bare name to the same name with a trailing slash, which is how essentially
/// every server says "that is a directory".
pub fn directory_form(obs: &PageObservation) -> Option<Url> {
    if obs.url.path().ends_with('/') {
        return Some(obs.url.clone());
    }
    if (300..400).contains(&obs.status) {
        let target = obs
            .links
            .iter()
            .find(|l| l.link_type == crate::model::LinkType::Redirect)?;
        let expected = format!("{}/", obs.url.path());
        if target.url.path() == expected && target.url.host_str() == obs.url.host_str() {
            return Some(target.url.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn status_filter_parses_codes_and_ranges() {
        let f = StatusFilter::parse("200,301-308,403").unwrap();
        assert!(f.contains(200) && f.contains(301) && f.contains(308) && f.contains(403));
        assert!(!f.contains(404) && !f.contains(300) && !f.contains(309));
    }

    #[test]
    fn status_filter_rejects_nonsense() {
        assert!(StatusFilter::parse("").is_err());
        assert!(StatusFilter::parse("abc").is_err());
        assert!(StatusFilter::parse("99").is_err());
        assert!(StatusFilter::parse("600").is_err());
        assert!(StatusFilter::parse("308-301").is_err());
    }

    #[test]
    fn default_filter_accepts_interesting_codes_and_not_404() {
        let f = StatusFilter::default();
        for good in [200, 204, 301, 302, 307, 308, 401, 403, 405] {
            assert!(f.contains(good), "{good} should count as a discovery");
        }
        assert!(!f.contains(404), "404 is the whole point of filtering");
        assert!(!f.contains(500));
    }

    fn sample(status: u16, ct: &str, len: u64, path_len: usize) -> Sample {
        Sample {
            status,
            content_type: Some(ct.into()),
            len: Some(len),
            path_len,
        }
    }

    #[test]
    fn a_constant_soft_404_is_recognised_despite_its_200() {
        // Every unknown path returns the same friendly 200 page.
        let b = Baseline::learn(
            &sample(200, "text/html", 5000, 30),
            &sample(200, "text/html", 5000, 46),
        );
        assert!(!b.unstable && !b.echoes_path);
        assert!(b.looks_like_miss(200, Some("text/html"), Some(5000), 12));
        assert!(!b.looks_like_miss(200, Some("text/html"), Some(20000), 12));
        assert!(!b.looks_like_miss(403, Some("text/html"), Some(5000), 12));
    }

    #[test]
    fn a_path_echoing_soft_404_is_recognised() {
        // "Nothing at /portal/xyz" -- the body grows with the path, so raw
        // length comparison would call every miss a hit.
        let b = Baseline::learn(
            &sample(200, "text/html", 130, 30),
            &sample(200, "text/html", 146, 46),
        );
        assert!(b.echoes_path, "the body tracks path length");
        assert_eq!(b.len, Some(100), "constant part of the page");
        // A different path length, same page: still a miss.
        assert!(b.looks_like_miss(200, Some("text/html"), Some(118), 18));
        // A real page of the same length but a different type is not a miss.
        assert!(!b.looks_like_miss(200, Some("text/plain"), Some(118), 18));
        // A real page with genuinely different content is not a miss.
        assert!(!b.looks_like_miss(200, Some("text/html"), Some(900), 18));
    }

    #[test]
    fn a_real_file_is_not_swallowed_by_a_nearby_length() {
        // The regression this exists for: /portal/config.php returned 138 bytes
        // of text/plain where the echoing miss page would have been ~147, and a
        // loose byte tolerance called it a miss.
        let b = Baseline::learn(
            &sample(200, "text/html", 159, 32),
            &sample(200, "text/html", 175, 48),
        );
        assert!(b.echoes_path);
        assert!(
            !b.looks_like_miss(200, Some("text/plain"), Some(138), 18),
            "a different media type is never the HTML miss page"
        );
    }

    #[test]
    fn charset_differences_do_not_break_the_type_comparison() {
        let b = Baseline::learn(
            &sample(200, "text/html; charset=utf-8", 500, 30),
            &sample(200, "text/html; charset=utf-8", 500, 46),
        );
        assert!(b.looks_like_miss(200, Some("text/html"), Some(500), 12));
    }

    #[test]
    fn inconsistent_calibration_is_marked_unstable_and_swallows_nothing() {
        // Two nonsense paths answered with unrelated sizes: no pattern to trust.
        let b = Baseline::learn(
            &sample(200, "text/html", 500, 30),
            &sample(200, "text/html", 9000, 46),
        );
        assert!(b.unstable);
        assert!(!b.looks_like_miss(200, Some("text/html"), Some(500), 30));
    }

    #[test]
    fn differing_status_between_samples_is_unstable() {
        let b = Baseline::learn(
            &sample(200, "text/html", 500, 30),
            &sample(404, "text/html", 500, 46),
        );
        assert!(b.unstable);
    }

    #[test]
    fn candidates_expand_words_by_extensions() {
        let d = Discovery::new(
            vec!["admin".into(), "api/".into()],
            vec!["php".into(), "bak".into()],
            StatusFilter::default(),
            0,
        );
        let got: Vec<String> = d
            .candidates(&u("https://e.com/app/"))
            .iter()
            .map(|x| x.path().to_string())
            .collect();
        assert_eq!(
            got,
            vec![
                "/app/admin",
                "/app/admin.php",
                "/app/admin.bak",
                "/app/api/", // a directory word gets no extensions
            ]
        );
    }

    #[test]
    fn candidates_stay_inside_the_directory() {
        let d = Discovery::new(
            vec!["a".into(), "b/c".into()],
            vec![],
            StatusFilter::default(),
            0,
        );
        for c in d.candidates(&u("https://e.com/deep/dir/")) {
            assert!(c.path().starts_with("/deep/dir/"), "escaped: {c}");
            assert_eq!(c.host_str(), Some("e.com"));
        }
    }

    #[test]
    fn parent_dir_of_a_probe() {
        assert_eq!(
            parent_dir(&u("https://e.com/a/b/admin")).unwrap().as_str(),
            "https://e.com/a/b/"
        );
        assert_eq!(
            parent_dir(&u("https://e.com/admin")).unwrap().as_str(),
            "https://e.com/"
        );
        assert_eq!(
            parent_dir(&u("https://e.com/a/b/")).unwrap().as_str(),
            "https://e.com/a/"
        );
    }

    #[test]
    fn calibration_segments_are_unique_and_exactly_as_long_as_asked() {
        for len in [1, 8, 24, 40, 64, 100] {
            let a = nonexistent_segment(len);
            let b = nonexistent_segment(len);
            assert_ne!(a, b, "two calibration probes must differ");
            assert_eq!(a.len(), len, "length is what makes echo detection work");
            assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }
}
