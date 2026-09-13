pub mod frontier;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use anyhow::{Context, Result, bail};
use dashmap::DashSet;
use reqwest::Client;
use reqwest::header::{HeaderMap, LOCATION};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use url::Url;
use crate::brute::Discovery;
use crate::brute::discovery::{directory_form, parent_dir};
use crate::config::CrawlConfig;
use crate::error::CrawlError;
use crate::extract::{self, cookies, headers, html, params};
use crate::model::{
    CrawlEvent, CrawlStats, LinkRecord, LinkType, PageError, PageObservation, ParamSource,
};
use crate::politeness::Politeness;
use crate::robots::RobotsCache;
use crate::scope::{Scope, normalize};

pub use frontier::{Frontier, InFlightGuard, Offer, Task};


#[derive(Debug, Default, Clone, Copy)]
pub struct Outcome {
    pub stats: CrawlStats,
    pub interrupted: bool,
}

pub struct Engine {
    cfg: Arc<CrawlConfig>,
    scope: Arc<Scope>,
    client: Client,
    politeness: Arc<Politeness>,
    discovery: Option<Arc<Discovery>>,
    follow_links: bool,
}

impl Engine {
    pub fn new(cfg: CrawlConfig, scope: Scope) -> Result<Self> {
        let client = Client::builder()
            .user_agent(cfg.user_agent.clone())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(cfg.request_timeout)
            .connect_timeout(cfg.request_timeout)
            .pool_max_idle_per_host(cfg.concurrency.max(1))
            .build()
            .context("building the HTTP client")?;
        let robots = Arc::new(RobotsCache::new(
            client.clone(),
            cfg.user_agent.clone(),
            cfg.request_timeout,
        ));
        let politeness = Arc::new(Politeness::new(
            robots,
            cfg.rate_limit,
            cfg.respect_robots,
            cfg.user_agent.clone(),
        ));
        Ok(Engine {
            cfg: Arc::new(cfg),
            scope: Arc::new(scope),
            client,
            politeness,
            discovery: None,
            follow_links: true,
        })
    }
    pub fn with_discovery(mut self, discovery: Arc<Discovery>) -> Self {
        self.discovery = Some(discovery);
        self.follow_links = false;
        self
    }
    pub fn following_links(mut self, follow: bool) -> Self {
        self.follow_links = follow;
        self
    }
    pub async fn run(self, tx: mpsc::Sender<CrawlEvent>) -> Result<Outcome> {
        let seed = Url::parse(&self.cfg.seed)
            .with_context(|| format!("`{}` is not a valid URL", self.cfg.seed))?;
        if !matches!(seed.scheme(), "http" | "https") {
            bail!("seed must be http or https, got `{}`", seed.scheme());
        }
        let seed = normalize(&seed);

        let (frontier, mut rx) = Frontier::new(
            self.cfg.max_depth,
            self.cfg.max_pages,
            self.cfg.max_variants,
        );
        let offer = frontier.offer(seed.clone(), 0);
        if offer != Offer::Accepted {
            bail!(
                "seed `{seed}` was rejected by the frontier ({offer:?}); \
                 check --max-pages, --max-variants and --depth"
            );
        }
        let worker = Arc::new(Worker {
            cfg: self.cfg.clone(),
            scope: self.scope.clone(),
            client: self.client.clone(),
            politeness: self.politeness.clone(),
            discovery: self.discovery.clone(),
            follow_links: self.follow_links,
            frontier: frontier.clone(),
            probed_dirs: DashSet::new(),
            counters: Counters::default(),
            tx,
        });
        let permits = Arc::new(Semaphore::new(self.cfg.concurrency.max(1)));
        let finished = frontier.finished();
        let mut tasks = JoinSet::new();
        let mut interrupted = false;
        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);
        let mut watching_signal = true;

        loop {
            tokio::select! {
                biased;

                // Fires when the last in-flight task completes with an empty
                // queue -- the only correct definition of "done".
                _ = finished.cancelled() => break,

                signal = &mut ctrl_c, if watching_signal => {
                    watching_signal = false;
                    if signal.is_ok() {
                        tracing::warn!("interrupted; abandoning in-flight requests");
                        interrupted = true;
                        break;
                    }
                }

                next = rx.recv() => {
                    let Some(task) = next else { break };
                    let Ok(permit) = permits.clone().acquire_owned().await else {
                        break;
                    };
                    let worker = worker.clone();
                    let frontier = frontier.clone();
                    tasks.spawn(async move {
                        let _guard = InFlightGuard::new(frontier);
                        let _permit = permit;
                        worker.handle(task).await;
                    });
                }
            }
        }

        if interrupted {
            tasks.shutdown().await;
        } else {
            while tasks.join_next().await.is_some() {}
        }

        let stats = worker.counters.snapshot();
        tracing::info!(
            fetched = stats.fetched,
            skipped = stats.skipped,
            errors = stats.errors,
            rejected = frontier.rejected(),
            "crawl finished"
        );
        Ok(Outcome { stats, interrupted })
    }
}

struct Worker {
    cfg: Arc<CrawlConfig>,
    scope: Arc<Scope>,
    client: Client,
    politeness: Arc<Politeness>,
    discovery: Option<Arc<Discovery>>,
    follow_links: bool,
    frontier: Arc<Frontier>,
    probed_dirs: DashSet<String>,
    counters: Counters,
    tx: mpsc::Sender<CrawlEvent>,
}
#[derive(Default)]
struct Counters {
    fetched: AtomicUsize,
    skipped: AtomicUsize,
    errors: AtomicUsize,
}
impl Counters {
    fn snapshot(&self) -> CrawlStats {
        CrawlStats {
            fetched: self.fetched.load(Ordering::Relaxed),
            skipped: self.skipped.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}





struct Fetched {
    status: u16,
    headers: HeaderMap,
    declared_length: Option<u64>,
    body: Vec<u8>,
}

impl Worker {
    async fn handle(self: Arc<Self>, task: Task) {
        let Task { url, depth, probe } = task;
        if !self.scope.contains(&url) {
            tracing::debug!(%url, "out of scope");
            self.counters.skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // robots.txt and the rate limit
        if let Err(e) = self.politeness.clear_to_fetch(&url).await {
            tracing::debug!(%url, error = %e, "not fetched");
            self.counters.skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let started = Instant::now();
        let fetched = match self.fetch(&url).await {
            Ok(f) => f,
            Err(e) => {
                tracing::debug!(%url, error = %e, "fetch failed");
                self.counters.errors.fetch_add(1, Ordering::Relaxed);
                let _ = self
                    .tx
                    .send(CrawlEvent::Failed(PageError {
                        url,
                        depth,
                        message: e.to_string(),
                    }))
                    .await;
                return;
            }
        };
        let elapsed_ms = started.elapsed().as_millis() as u64;

        let obs = self.observe(url, depth, probe, fetched, elapsed_ms).await;
        if probe && let Some(d) = &self.discovery {
            let dir = parent_dir(&obs.url).unwrap_or_else(|| obs.url.clone());
            let baseline = d.baseline_for(&self.client, &self.politeness, &dir).await;
            if !d.is_hit(&baseline, &obs) {
                tracing::trace!(url = %obs.url, status = obs.status, "miss");
                self.counters.skipped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            d.record_hit();
            tracing::info!(url = %obs.url, status = obs.status, "found");
        }
        let next: Vec<Url> = if self.follow_links {
            obs.in_scope_links()
                .filter(|l| l.link_type.is_crawlable())
                .map(|l| l.url.clone())
                .collect()
        } else {
            Vec::new()
        };
        let directory = self.directory_to_probe(&obs, depth, probe);

        self.counters.fetched.fetch_add(1, Ordering::Relaxed);
        if self.tx.send(CrawlEvent::Page(Box::new(obs))).await.is_err() {
            // The writer is gone; there is nothing useful left to do.
            return;
        }

        for url in next {
            self.frontier.offer(url, depth + 1);
        }
        if let Some(dir) = directory {
            self.probe_directory(dir, depth).await;
        }
    }

    async fn fetch(&self, url: &Url) -> Result<Fetched, CrawlError> {
        let cap = self.cfg.max_body_bytes;
        let request = self.client.get(url.clone()).send();

        let read = async move {
            let mut response = request.await?;
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let declared_length = response.content_length();

            
            if declared_length.is_some_and(|n| n > cap as u64) {
                return Err(CrawlError::BodyTooLarge(cap));
            }
            let mut body: Vec<u8> = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                if body.len() + chunk.len() > cap {
                    return Err(CrawlError::BodyTooLarge(cap));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(Fetched {
                status,
                headers,
                declared_length,
                body,
            })
        };
        tokio::time::timeout(self.cfg.request_timeout, read)
            .await
            .unwrap_or(Err(CrawlError::Timeout))
    }



    async fn observe(
        &self,
        url: Url,
        depth: u32,
        probe: bool,
        fetched: Fetched,
        elapsed_ms: u64,
    ) -> PageObservation {
        let content_type = headers::content_type(&fetched.headers);
        let cookies = headers::set_cookie_values(&fetched.headers)
            .iter()
            .filter_map(|v| cookies::parse_set_cookie(v))
            .collect();

        let mut obs = PageObservation {
            status: fetched.status,
            content_type: content_type.clone(),
            content_length: fetched.declared_length,
            body_bytes: Some(fetched.body.len() as u64),
            title: None,
            elapsed_ms,
            headers: headers::capture(&fetched.headers),
            cookies,
            forms: Vec::new(),
            links: Vec::new(),
            scripts: Vec::new(),
            params: params::from_url(&url, ParamSource::SelfUrl),
            probed: probe,
            url,
            depth,
        };

        if is_markup(content_type.as_deref()) {
            let text = String::from_utf8_lossy(&fetched.body).into_owned();
            match tokio::task::spawn_blocking(move || html::extract(&text)).await {
                Ok(raw) => {
                    let resolved = extract::resolve(raw, &obs.url, &self.scope);
                    obs.title = resolved.title;
                    obs.links = resolved.links;
                    obs.forms = resolved.forms;
                    obs.scripts = resolved.scripts;
                    obs.params = resolved.params;
                }
                Err(e) => tracing::warn!(url = %obs.url, error = %e, "html parse task failed"),
            }
        }
        if (300..400).contains(&obs.status)
            && let Some(target) = redirect_target(&fetched.headers, &obs.url)
        {
            let in_scope = self.scope.contains(&target);
            obs.links.push(LinkRecord {
                url: target,
                link_type: LinkType::Redirect,
                in_scope,
            });
        }

        obs
    }

    fn directory_to_probe(&self, obs: &PageObservation, depth: u32, probe: bool) -> Option<Url> {
        self.discovery.as_ref()?;
        directory_form(obs).or_else(|| {
            (depth == 0 && !probe).then(|| parent_dir(&obs.url)).flatten()
        })
    }




    async fn probe_directory(&self, dir: Url, level: u32) {
        let Some(d) = self.discovery.clone() else {
            return;
        };
        if level > d.recurse_depth || !self.scope.contains(&dir) {
            return;
        }
        if !self.probed_dirs.insert(dir.as_str().to_string()) {
            return;
        }
        let baseline = d.baseline_for(&self.client, &self.politeness, &dir).await;
        tracing::debug!(%dir, unstable = baseline.unstable, level, "probing directory");
        self.frontier.offer_probe(dir.clone(), level);
        for candidate in d.candidates(&dir) {
            if self.frontier.offer_probe(candidate, level + 1) == Offer::PageBudgetExhausted {
                tracing::debug!(%dir, "request budget reached; stopping this pass");
                break;
            }
        }
    }
}





fn is_markup(content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else {
        return true;
    };
    let base = ct.split(';').next().unwrap_or(ct).trim();
    matches!(
        base,
        "text/html" | "application/xhtml+xml" | "application/xml" | "text/xml" | ""
    )
}
fn redirect_target(headers: &HeaderMap, base: &Url) -> Option<Url> {
    let raw = headers.get(LOCATION)?.to_str().ok()?.trim();
    if raw.is_empty() {
        return None;
    }
    let joined = base.join(raw).ok()?;
    if !matches!(joined.scheme(), "http" | "https") {
        return None;
    }
    Some(normalize(&joined))
}










#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;
    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }
    fn location(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(value) {
            h.insert(LOCATION, v);
        }
        h
    }
    #[test]
    fn a_relative_redirect_resolves_against_the_page() {
        let target = redirect_target(&location("/new"), &u("http://e.com/old")).unwrap();
        assert_eq!(target.as_str(), "http://e.com/new");
    }
    #[test]
    fn unfetchable_redirect_targets_are_dropped() {
        let base = u("http://e.com/");
        for bad in ["", "   ", "javascript:alert(1)", "mailto:a@e.com"] {
            assert!(
                redirect_target(&location(bad), &base).is_none(),
                "`{bad}` must not become a graph node"
            );
        }
        assert!(redirect_target(&HeaderMap::new(), &base).is_none());
    }
    #[test]
    fn only_markup_content_types_are_parsed() {
        assert!(is_markup(None));
        assert!(is_markup(Some("text/html")));
        assert!(is_markup(Some("text/html; charset=utf-8")));
        assert!(!is_markup(Some("application/json")));
        assert!(!is_markup(Some("text/plain")));
        assert!(!is_markup(Some("not/a/real/type")));
    }
}

