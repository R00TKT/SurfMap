use std::fmt;
use serde::{Deserialize, Serialize};
use url::{Host, Url};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum ScopePolicy {
    Host,
    Subdomains,
    List,
}

impl fmt::Display for ScopePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ScopePolicy::Host => "host",
            ScopePolicy::Subdomains => "subdomains",
            ScopePolicy::List => "list",
        })
    }
}

impl std::str::FromStr for ScopePolicy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "host" | "exact" => Ok(ScopePolicy::Host),
            "subdomains" | "sub" => Ok(ScopePolicy::Subdomains),
            "list" => Ok(ScopePolicy::List),
            other => Err(format!(
                "unknown scope policy `{other}` (expected host, subdomains, or list)"
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Scope {
    policy: ScopePolicy,
    hosts: Vec<String>,
}

impl Scope {
    pub fn new(seed: &Url, policy: ScopePolicy, extra_hosts: &[String]) -> Result<Self, String> {
        let mut hosts: Vec<String> = Vec::new();
        if policy != ScopePolicy::List {
            let host = seed
                .host_str()
                .ok_or_else(|| format!("seed url `{seed}` has no host"))?;
            hosts.push(host.to_ascii_lowercase());
        }
        for h in extra_hosts {
            let h = h.trim().to_ascii_lowercase();
            if !h.is_empty() && !hosts.contains(&h) {
                hosts.push(h);
            }
        }
        if hosts.is_empty() {
            return Err("scope policy `list` requires at least one --host".into());
        }
        Ok(Scope { policy, hosts })
    }

    pub fn policy(&self) -> ScopePolicy {
        self.policy
    }

    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// auth statement shown to the operator before a crawl starts
    pub fn describe(&self) -> String {
        match self.policy {
            ScopePolicy::Host | ScopePolicy::List => self.hosts.join(", "),
            ScopePolicy::Subdomains => self
                .hosts
                .iter()
                .map(|h| format!("{h} (+ subdomains)"))
                .collect::<Vec<_>>()
                .join(", "),
        }
    }

    pub fn contains(&self, url: &Url) -> bool {
        if !matches!(url.scheme(), "http" | "https") {
            return false;
        }
        let host = match url.host() {
            Some(Host::Domain(d)) => d.to_ascii_lowercase(),
            Some(Host::Ipv4(a)) => a.to_string(),
            Some(Host::Ipv6(a)) => a.to_string(),
            None => return false,
        };
        let literal_host = !matches!(url.host(), Some(Host::Domain(_)));

        self.hosts.iter().any(|allowed| {
            if host == *allowed {
                return true;
            }
            if literal_host {
                return false;
            }
            match self.policy {
                ScopePolicy::Subdomains => host.ends_with(&format!(".{allowed}")),
                ScopePolicy::Host | ScopePolicy::List => false,
            }
        })
    }
}



pub fn normalize(url: &Url) -> Url {
    let mut u = url.clone();

    u.set_fragment(None);
    if !u.username().is_empty() || u.password().is_some() {
        let _ = u.set_username("");
        let _ = u.set_password(None);
    }
    if let Some(host) = u.host_str() {
        let lower = host.to_ascii_lowercase();
        if lower != host {
            let _ = u.set_host(Some(&lower));
        }
    }
    if matches!(
        (u.scheme(), u.port()),
        ("http", Some(80)) | ("https", Some(443))
    ) {
        let _ = u.set_port(None);
    }

    if u.path().is_empty() {
        u.set_path("/");
    }

    match u.query() {
        Some("") | None => u.set_query(None),
        Some(_) => {
            let mut pairs: Vec<(String, String)> = u
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            pairs.sort();
            let mut serializer = form_urlencoded::Serializer::new(String::new());
            for (k, v) in &pairs {
                serializer.append_pair(k, v);
            }
            let rebuilt = serializer.finish();
            if rebuilt.is_empty() {
                u.set_query(None);
            } else {
                u.set_query(Some(&rebuilt));
            }
        }
    }

    u
}

pub fn signature(url: &Url) -> String {
    let mut names: Vec<String> = url.query_pairs().map(|(k, _)| k.into_owned()).collect();
    names.sort();
    names.dedup();
    format!(
        "{}://{}{}?{}",
        url.scheme(),
        url.host_str().unwrap_or(""),
        url.path(),
        names.join("&")
    )
}







#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn normalize_strips_fragment_and_default_port() {
        assert_eq!(
            normalize(&u("https://Example.COM:443/a#frag")).as_str(),
            "https://example.com/a"
        );
        assert_eq!(
            normalize(&u("http://example.com:80/")).as_str(),
            "http://example.com/"
        );
    }
    #[test]
    fn normalize_sorts_query_and_drops_empty() {
        assert_eq!(
            normalize(&u("https://e.com/s?b=2&a=1")).as_str(),
            "https://e.com/s?a=1&b=2"
        );
        assert_eq!(
            normalize(&u("https://e.com/s?")).as_str(),
            "https://e.com/s"
        );
    }
    #[test]
    fn normalize_preserves_path_case_and_repeated_params() {
        assert_eq!(
            normalize(&u("https://e.com/CaseSensitive")).as_str(),
            "https://e.com/CaseSensitive"
        );
        assert_eq!(
            normalize(&u("https://e.com/s?id=2&id=1")).as_str(),
            "https://e.com/s?id=1&id=2"
        );
    }
    #[test]
    fn host_policy_rejects_subdomains() {
        let s = Scope::new(&u("https://example.com/"), ScopePolicy::Host, &[]).unwrap();
        assert!(s.contains(&u("https://example.com/x")));
        assert!(!s.contains(&u("https://app.example.com/x")));
        assert!(!s.contains(&u("https://evil.com/x")));
    }

    #[test]
    fn subdomain_policy_is_not_suffix_confusable() {
        let s = Scope::new(&u("https://example.com/"), ScopePolicy::Subdomains, &[]).unwrap();
        assert!(s.contains(&u("https://app.example.com/x")));
        assert!(!s.contains(&u("https://notexample.com/x")));
        assert!(!s.contains(&u("https://example.com.evil.net/x")));
    }
    #[test]
    fn non_http_schemes_are_never_in_scope() {
        let s = Scope::new(&u("https://example.com/"), ScopePolicy::Subdomains, &[]).unwrap();
        assert!(!s.contains(&u("javascript:alert(1)")));
        assert!(!s.contains(&u("mailto:a@example.com")));
        assert!(!s.contains(&u("data:text/html,<b>")));
        assert!(!s.contains(&u("ftp://example.com/f")));
    }
    #[test]
    fn signature_collapses_values_not_names() {
        assert_eq!(
            signature(&u("https://e.com/cal?month=1&year=2024")),
            signature(&u("https://e.com/cal?month=9&year=2031"))
        );
        assert_ne!(
            signature(&u("https://e.com/cal?month=1")),
            signature(&u("https://e.com/cal?week=1"))
        );
    }
}
