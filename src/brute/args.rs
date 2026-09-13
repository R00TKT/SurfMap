//! The `surfmap brute` command line.
//!
//! Kept beside the code it drives rather than in `cli`, so the whole feature --
//! flags, wordlist, prober -- reads as one unit. The shared value parsers still
//! live in `cli`, because `crawl` enforces the same bounds on the same flags
//! and two copies of a limit is one copy too many.

use std::path::PathBuf;

use clap::Args;

use crate::cli::{parse_concurrency, parse_depth, parse_rate_limit};
use crate::scope::ScopePolicy;

/// Path discovery. Shares the crawl's scope, politeness and storage; what
/// differs is where candidate URLs come from.
#[derive(Debug, Args)]
#[command(allow_negative_numbers = true)]
pub struct BruteArgs {
    /// Base URL to probe. A path without a trailing slash is treated as one.
    pub url: String,
    /// Wordlist file, one path per line. Uses the built-in list when omitted.
    #[arg(short, long, value_name = "FILE")]
    pub wordlist: Option<PathBuf>,
    /// Also try each word with these extensions, e.g. `-x php,bak,old`.
    #[arg(short = 'x', long, value_name = "EXT", value_delimiter = ',')]
    pub extensions: Vec<String>,
    /// Directory levels to recurse into. 0 probes only the base URL. Capped at 20.
    #[arg(short, long, visible_alias = "max-depth", default_value_t = 0,
          value_parser = parse_depth)]
    pub depth: u32,
    /// Status codes counted as a find, e.g. `200,301-308,403`.
    #[arg(
        long,
        value_name = "CODES",
        default_value = "200,204,301,302,307,308,401,403,405"
    )]
    pub status: String,
    /// Which hosts count as in scope.
    #[arg(long, value_enum, default_value_t = ScopePolicy::Host)]
    pub scope: ScopePolicy,
    /// Additional in-scope host (repeatable). Required with `--scope list`.
    #[arg(long = "host", value_name = "HOST")]
    pub hosts: Vec<String>,
    /// Maximum simultaneous in-flight requests. Capped at 64.
    #[arg(short, long, visible_alias = "threads", default_value_t = 4,
          value_parser = parse_concurrency)]
    pub concurrency: usize,
    /// Requests per second, per host. Must be positive.
    #[arg(long, value_name = "RPS", default_value_t = 2.0,
          value_parser = parse_rate_limit)]
    pub rate_limit: f64,
    /// Hard cap on requests sent, across the whole run.
    #[arg(long, default_value_t = 20_000)]
    pub max_requests: usize,
    /// Follow links found on discovered pages, turning the run into a crawl
    /// seeded by what the wordlist found.
    #[arg(long)]
    pub crawl_hits: bool,
    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 15)]
    pub timeout: u64,
    /// Override the User-Agent string.
    #[arg(long)]
    pub user_agent: Option<String>,
    /// Do not honour robots.txt. Only valid with explicit written authorization.
    #[arg(long)]
    pub ignore_robots: bool,
    /// Skip the interactive authorization prompts (for scripted runs).
    #[arg(short = 'y', long = "yes")]
    pub assume_authorized: bool,
}
