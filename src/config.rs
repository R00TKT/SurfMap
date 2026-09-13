use std::path::PathBuf;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::scope::ScopePolicy;



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlConfig {
    pub seed: String,
    pub scope_policy: ScopePolicy,
    pub extra_hosts: Vec<String>,
    pub max_depth: u32,
    pub max_pages: usize,
    pub max_variants: usize,
    pub concurrency: usize,
    pub rate_limit: f64,
    pub respect_robots: bool,
    pub user_agent: String,
    pub request_timeout: Duration,
    pub max_body_bytes: usize,
    pub db_path: PathBuf,
}
impl CrawlConfig {
    pub fn min_interval(&self) -> Duration {
        Duration::from_secs_f64(1.0 / self.rate_limit.max(0.001))
    }
}
/// Ceiling on `--depth`.
pub const MAX_DEPTH_LIMIT: u32 = 20;
/// Ceiling on `--concurrency`.
pub const MAX_CONCURRENCY_LIMIT: usize = 64;
pub const DEFAULT_USER_AGENT: &str = concat!(
    "surfmap/",
    env!("CARGO_PKG_VERSION"),
    " (+authorized-scan; https://github.com/example/surfmap)"
);
pub const REDACTED_HEADERS: &[&str] = &[
    "set-cookie",
    "authorization",
    "proxy-authorization",
    "www-authenticate",
    "proxy-authenticate",
];
pub const SECURITY_HEADERS: &[&str] = &[
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
];
