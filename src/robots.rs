use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use dashmap::DashMap;
use reqwest::Client;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    allow: bool,
    pattern: String,
}
#[derive(Debug, Default, Clone)]
struct Group {
    agents: Vec<String>,
    rules: Vec<Rule>,
    crawl_delay: Option<f64>,
}
#[derive(Debug, Default, Clone)]
pub struct RobotsRules {
    groups: Vec<Group>,
    pub sitemaps: Vec<String>,
    denied_all: bool,
}




impl RobotsRules {
    /// No robots.txt published (404) -- everything is permitted.
    pub fn allow_all() -> Self {
        RobotsRules::default()
    }
    /// Policy unreadable (5xx, timeout, connection error) -- deny by default.
    pub fn deny_all() -> Self {
        RobotsRules {
            denied_all: true,
            ..Default::default()
        }
    }
    pub fn parse(text: &str) -> Self {
        let text = text.trim_start_matches('\u{feff}');
        let mut rules = RobotsRules::default();
        let mut current: Option<Group> = None;
        let mut in_header = false;


        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let Some((field, value)) = line.split_once(':') else {
                continue;
            };
            let field = field.trim().to_ascii_lowercase();
            let value = value.trim();

            match field.as_str() {
                "user-agent" => {
                    if !in_header && let Some(g) = current.take() {
                        rules.groups.push(g);
                    }
                    let group = current.get_or_insert_with(Group::default);
                    group.agents.push(value.to_ascii_lowercase());
                    in_header = true;
                }
                "allow" | "disallow" => {
                    in_header = false;
                    if value.is_empty() {
                        continue;
                    }
                    if let Some(g) = current.as_mut() {
                        g.rules.push(Rule {
                            allow: field == "allow",
                            pattern: value.to_string(),
                        });
                    }
                }
                "crawl-delay" => {
                    in_header = false;
                    if let (Some(g), Ok(d)) = (current.as_mut(), value.parse::<f64>())
                        && d.is_finite()
                        && d >= 0.0
                    {
                        g.crawl_delay = Some(d);
                    }
                }
                "sitemap" => rules.sitemaps.push(value.to_string()),
                _ => {}
            }
        }
        if let Some(g) = current.take() {
            rules.groups.push(g);
        }
        rules
    }


    fn applicable(&self, user_agent: &str) -> Vec<&Group> {
        let ua = user_agent.to_ascii_lowercase();
        let mut best: Option<&str> = None;
        for group in &self.groups {
            for agent in &group.agents {
                if agent == "*" {
                    continue;
                }
                if ua.contains(agent.as_str()) && best.is_none_or(|b: &str| agent.len() > b.len()) {
                    best = Some(agent.as_str());
                }
            }
        }
        let token = best.unwrap_or("*");
        self.groups
            .iter()
            .filter(|g| g.agents.iter().any(|a| a == token))
            .collect()
    }

    pub fn allows(&self, user_agent: &str, path_and_query: &str) -> bool {
        if self.denied_all {
            return false;
        }
        let groups = self.applicable(user_agent);
        let mut best: Option<&Rule> = None;
        for rule in groups.iter().flat_map(|g| g.rules.iter()) {
            if !path_matches(&rule.pattern, path_and_query) {
                continue;
            }
            best = Some(match best {
                None => rule,
                Some(b) if rule.pattern.len() > b.pattern.len() => rule,
                Some(b) if rule.pattern.len() == b.pattern.len() && rule.allow && !b.allow => rule,
                Some(b) => b,
            });
        }
        best.is_none_or(|r| r.allow)
    }
    pub fn crawl_delay(&self, user_agent: &str) -> Option<Duration> {
        self.applicable(user_agent)
            .iter()
            .find_map(|g| g.crawl_delay)
            .map(Duration::from_secs_f64)
    }
}



fn path_matches(pattern: &str, path: &str) -> bool {
    let anchored = pattern.ends_with('$');
    let pat = if anchored {
        &pattern[..pattern.len() - 1]
    } else {
        pattern
    }
    .as_bytes();
    let text = path.as_bytes();

    let (mut p, mut t) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (usize::MAX, 0usize);

    loop {
        if p == pat.len() {
            if !anchored || t == text.len() {
                return true;
            }
        } else if pat[p] == b'*' {
            star_p = p;
            star_t = t;
            p += 1;
            continue;
        } else if t < text.len() && pat[p] == text[t] {
            p += 1;
            t += 1;
            continue;
        }
        if star_p != usize::MAX && star_t < text.len() {
            star_t += 1;
            t = star_t;
            p = star_p + 1;
            continue;
        }
        return false;
    }
}

pub struct RobotsCache {
    client: Client,
    user_agent: String,
    timeout: Duration,
    cache: DashMap<String, Arc<RobotsRules>>,
    locks: DashMap<String, Arc<tokio::sync::Mutex<()>>>,
}

impl RobotsCache {
    pub fn new(client: Client, user_agent: String, timeout: Duration) -> Self {
        RobotsCache {
            client,
            user_agent,
            timeout,
            cache: DashMap::new(),
            locks: DashMap::new(),
        }
    }

    pub async fn rules_for(&self, url: &Url) -> Arc<RobotsRules> {
        let key = robots_key(url);
        if let Some(hit) = self.cache.get(&key) {
            return hit.clone();
        }

        

        let lock = self
            .locks
            .entry(key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = lock.lock().await;

        if let Some(hit) = self.cache.get(&key) {
            return hit.clone();
        }

        let rules = Arc::new(self.fetch(url).await);
        self.cache.insert(key, rules.clone());
        rules
    }

    async fn fetch(&self, url: &Url) -> RobotsRules {
        let Ok(robots_url) = url.join("/robots.txt") else {
            return RobotsRules::deny_all();
        };
        let request = self
            .client
            .get(robots_url.clone())
            .header(reqwest::header::USER_AGENT, &self.user_agent)
            .timeout(self.timeout)
            .send();

        match request.await {
            Ok(resp) if resp.status().is_success() => match resp.text().await {
                Ok(body) => {
                    tracing::debug!(url = %robots_url, bytes = body.len(), "fetched robots.txt");
                    RobotsRules::parse(&body)
                }
                Err(e) => {
                    tracing::warn!(url = %robots_url, error = %e, "robots.txt unreadable; denying host");
                    RobotsRules::deny_all()
                }
            },
            Ok(resp) if resp.status().is_client_error() => {
                tracing::debug!(url = %robots_url, status = %resp.status(), "no robots.txt; allowing");
                RobotsRules::allow_all()
            }
            Ok(resp) => {
                tracing::warn!(url = %robots_url, status = %resp.status(), "robots.txt server error; denying host");
                RobotsRules::deny_all()
            }
            Err(e) => {
                tracing::warn!(url = %robots_url, error = %e, "robots.txt fetch failed; denying host");
                RobotsRules::deny_all()
            }
        }
    }
    pub fn stats(&self) -> HashMap<String, bool> {
        self.cache
            .iter()
            .map(|e| (e.key().clone(), !e.value().denied_all))
            .collect()
    }
}

fn robots_key(url: &Url) -> String {
    format!(
        "{}://{}{}",
        url.scheme(),
        url.host_str().unwrap_or(""),
        url.port().map(|p| format!(":{p}")).unwrap_or_default()
    )
}



#[cfg(test)]
mod tests {
    use super::*;

    const UA: &str = "surfmap/0.1.0";

    #[test]
    fn prefix_and_wildcard_matching() {
        assert!(path_matches("/admin", "/admin/users"));
        assert!(path_matches("/admin", "/admin"));
        assert!(!path_matches("/admin", "/adm"));
        assert!(path_matches("/*.php", "/a/b/c.php?x=1"));
        assert!(path_matches("/*.php$", "/a/b/c.php"));
        assert!(!path_matches("/*.php$", "/a/b/c.php?x=1"));
        assert!(path_matches("/", "/anything"));
        assert!(path_matches("/fish*.html", "/fish/salmon.html"));
    }

    #[test]
    fn longest_pattern_wins_and_allow_breaks_ties() {
        let r = RobotsRules::parse("User-agent: *\nDisallow: /admin\nAllow: /admin/public\n");
        assert!(!r.allows(UA, "/admin/secret"));
        assert!(r.allows(UA, "/admin/public/x"));
        assert!(r.allows(UA, "/"));

        let tie = RobotsRules::parse("User-agent: *\nDisallow: /x\nAllow: /x\n");
        assert!(tie.allows(UA, "/x/y"), "equal-length tie goes to Allow");
    }

    #[test]
    fn specific_agent_group_overrides_wildcard() {
        let r = RobotsRules::parse(
            "User-agent: *\nDisallow: /\n\nUser-agent: surfmap\nDisallow: /private\n",
        );
        assert!(r.allows(UA, "/public"));
        assert!(!r.allows(UA, "/private/x"));
        assert!(!r.allows("SomeOtherBot/2", "/public"));
    }

    #[test]
    fn consecutive_agent_lines_share_one_group() {
        let r = RobotsRules::parse("User-agent: surfmap\nUser-agent: otherbot\nDisallow: /nope\n");
        assert!(!r.allows(UA, "/nope"));
        assert!(!r.allows("otherbot/1", "/nope"));
    }

    #[test]
    fn empty_disallow_means_allow_everything() {
        let r = RobotsRules::parse("User-agent: *\nDisallow:\n");
        assert!(r.allows(UA, "/anything"));
    }

    #[test]
    fn comments_crawl_delay_and_sitemaps() {
        let r = RobotsRules::parse(
            "# hello\nUser-agent: *   # trailing\nCrawl-delay: 2.5\nDisallow: /x\nSitemap: https://e.com/sitemap.xml\n",
        );
        assert_eq!(r.crawl_delay(UA), Some(Duration::from_secs_f64(2.5)));
        assert_eq!(r.sitemaps, vec!["https://e.com/sitemap.xml"]);
        assert!(!r.allows(UA, "/x"));
    }

    #[test]
    fn unreadable_policy_denies() {
        assert!(!RobotsRules::deny_all().allows(UA, "/"));
        assert!(RobotsRules::allow_all().allows(UA, "/"));
    }
}
