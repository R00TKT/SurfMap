use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use dashmap::DashMap;
use governor::{DefaultKeyedRateLimiter, Quota};
use tokio::time::Instant;
use url::Url;
use crate::error::CrawlError;
use crate::robots::RobotsCache;

pub struct Politeness {
    limiter: DefaultKeyedRateLimiter<String>,
    robots: Arc<RobotsCache>,
    respect_robots: bool,
    user_agent: String,
    next_allowed: DashMap<String, Instant>,
}






impl Politeness {
    pub fn new(
        robots: Arc<RobotsCache>,
        rate_limit: f64,
        respect_robots: bool,
        user_agent: String,
    ) -> Self {
        let period = Duration::from_secs_f64(1.0 / rate_limit.max(0.001));
        let quota = Quota::with_period(period)
            .expect("rate limit period is non-zero")
            .allow_burst(NonZeroU32::new(1).unwrap());

        Politeness {
            limiter: DefaultKeyedRateLimiter::keyed(quota),
            robots,
            respect_robots,
            user_agent,
            next_allowed: DashMap::new(),
        }
    }

    pub async fn clear_to_fetch(&self, url: &Url) -> Result<(), CrawlError> {
        let host = url.host_str().unwrap_or_default().to_string();

        if self.respect_robots {
            let rules = self.robots.rules_for(url).await;
            let path = match url.query() {
                Some(q) => format!("{}?{}", url.path(), q),
                None => url.path().to_string(),
            };
            if !rules.allows(&self.user_agent, &path) {
                return Err(CrawlError::RobotsDisallowed);
            }
            if let Some(delay) = rules.crawl_delay(&self.user_agent) {
                self.honour_crawl_delay(&host, delay).await;
            }
        }

        self.limiter.until_key_ready(&host).await;
        Ok(())
    }
    

    async fn honour_crawl_delay(&self, host: &str, delay: Duration) {
        let wait_until = {
            let now = Instant::now();
            let mut slot = self
                .next_allowed
                .entry(host.to_string())
                .or_insert_with(|| now);
            let reserved = (*slot).max(now);
            *slot = reserved + delay;
            reserved
        };


        tokio::time::sleep_until(wait_until).await;
    }
}
