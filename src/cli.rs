use std::path::PathBuf;
use clap::{Args, Parser, Subcommand, ValueEnum};
use crate::brute::BruteArgs;
use crate::config::{MAX_CONCURRENCY_LIMIT, MAX_DEPTH_LIMIT};
use crate::scope::ScopePolicy;

const _: () = assert!(
    MAX_DEPTH_LIMIT == 20,
    "MAX_DEPTH_LIMIT changed -- update the --depth doc comment to match"
);
const _: () = assert!(
    MAX_CONCURRENCY_LIMIT == 64,
    "MAX_CONCURRENCY_LIMIT changed -- update the --concurrency doc comment to match"
);


pub(crate) fn parse_depth(s: &str) -> Result<u32, String> {
    let depth: u32 = s
        .parse()
        .map_err(|_| format!("`{s}` is not a whole number"))?;
    if depth > MAX_DEPTH_LIMIT {
        return Err(format!(
            "depth {depth} exceeds the maximum of {MAX_DEPTH_LIMIT}; \
             link depth is exponential, so bound the run with --max-pages instead"
        ));
    }
    Ok(depth)
}
pub(crate) fn parse_concurrency(s: &str) -> Result<usize, String> {
    let n: usize = s
        .parse()
        .map_err(|_| format!("`{s}` is not a whole number"))?;
    if n == 0 {
        return Err("concurrency must be at least 1".to_string());
    }
    if n > MAX_CONCURRENCY_LIMIT {
        return Err(format!(
            "concurrency {n} exceeds the maximum of {MAX_CONCURRENCY_LIMIT}; \
             that many simultaneous requests is a load test, not an assessment"
        ));
    }
    Ok(n)
}
pub(crate) fn parse_rate_limit(s: &str) -> Result<f64, String> {
    let rps: f64 = s.parse().map_err(|_| format!("`{s}` is not a number"))?;
    if !rps.is_finite() || rps <= 0.0 {
        return Err(format!(
            "rate limit must be a positive number of requests per second, got `{s}`"
        ));
    }
    Ok(rps)
}

#[derive(Debug, Parser)]
#[command(
    name = "surfmap",
    version,
    about = "Web crawler and attack-surface mapper for authorized assessments",
    long_about = "surfmap crawls a web application inside an explicitly authorized scope and \
records its attack surface -- input vectors, parameters, security headers, cookie flags and \
script references -- into a queryable SQLite database.\n\n\
Only point this at systems you have written permission to test."
)]
pub struct Cli {
    /// SQLite database to read from / write to.
    #[arg(long, global = true, default_value = "surfmap.db", value_name = "PATH")]
    pub db: PathBuf,
    /// Increase log detail (-v debug, -vv trace).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Emit machine-readable JSON instead of tables.
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Crawl a target and record its attack surface.
    Crawl(CrawlArgs),

    /// Probe a wordlist for unlinked directories and files.
    Brute(BruteArgs),

    /// Print a findings report from stored crawl data.
    Report(ReportArgs),

    /// List recorded crawl runs.
    Crawls,

    /// Compare the attack surface of two crawl runs.
    Diff {
        /// Baseline crawl id.
        base: i64,
        /// Newer crawl id.
        target: i64,
    },

    /// Run read-only SQL against the crawl database.
    Query {
        /// The SQL to run. The connection is opened read-only.
        sql: String,
        #[arg(long, default_value_t = 100)]
        limit: i64,
    },

    /// Print the database schema.
    Schema,
}

#[derive(Debug, Args)]
// Without this, clap reads `--depth -1` as a missing value followed by an
// unknown `-1` flag and reports "unexpected argument", which sends an operator
// looking for a typo in the wrong place. Letting the value through means the
// parsers above get to reject it on its merits.
#[command(allow_negative_numbers = true)]
pub struct CrawlArgs {
    /// Seed URL to start from.
    pub url: String,
    /// Maximum link depth from the seed. Capped at 20.
    #[arg(short, long, visible_alias = "max-depth", default_value_t = 3,
          value_parser = parse_depth)]
    pub depth: u32,
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
    /// Stop after this many pages.
    #[arg(long, default_value_t = 500)]
    pub max_pages: usize,
    /// Query-value variants to follow per URL shape (bounds calendar-style traps).
    #[arg(long, default_value_t = 5)]
    pub max_variants: usize,
    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 15)]
    pub timeout: u64,
    /// Refuse response bodies larger than this many megabytes.
    #[arg(long, default_value_t = 4)]
    pub max_body_mb: usize,
    /// Override the User-Agent string.
    #[arg(long)]
    pub user_agent: Option<String>,
    /// Do not honour robots.txt. Only valid with explicit written authorization.
    #[arg(long)]
    pub ignore_robots: bool,
    /// Skip the interactive authorization prompt (for scripted runs).
    #[arg(short = 'y', long = "yes")]
    pub assume_authorized: bool,
}

#[derive(Debug, Args)]
pub struct ReportArgs {
    /// Which report to print.
    #[arg(value_enum, default_value_t = ReportKind::Summary)]
    pub kind: ReportKind,
    /// Crawl id to report on. Defaults to the most recent crawl.
    #[arg(long)]
    pub crawl: Option<i64>,
    /// Maximum rows.
    #[arg(long, default_value_t = 50)]
    pub limit: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportKind {
    /// Counts and settings for the run.
    Summary,
    /// Every page that was fetched.
    Pages,
    /// Security headers that were not set.
    Headers,
    /// Forms, their actions and their fields.
    Forms,
    /// Parameter names and value shapes.
    Params,
    /// Cookies missing HttpOnly / Secure / SameSite.
    Cookies,
    /// Script references, grouped by host.
    Scripts,
    /// URLs that could not be fetched.
    Errors,
    /// Paths found by wordlist probing rather than by following links.
    Discovered,
    /// The link graph as a table.
    Graph,
    /// The link graph as Graphviz DOT.
    Dot,
}





#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Parse a `crawl` invocation, returning its args or the error text.
    fn crawl(flags: &[&str]) -> Result<CrawlArgs, String> {
        let mut argv = vec!["surfmap", "crawl", "https://e.com/"];
        argv.extend_from_slice(flags);
        match Cli::try_parse_from(argv) {
            Ok(Cli {
                command: Command::Crawl(args),
                ..
            }) => Ok(args),
            Ok(_) => unreachable!("asked for the crawl subcommand"),
            Err(e) => Err(e.to_string()),
        }
    }

    #[test]
    fn short_forms_and_aliases_reach_the_same_fields() {
        let short = crawl(&["-d", "5", "-c", "8"]).unwrap();
        let long = crawl(&["--depth", "5", "--concurrency", "8"]).unwrap();
        let alias = crawl(&["--max-depth", "5", "--threads", "8"]).unwrap();
        for a in [&short, &long, &alias] {
            assert_eq!((a.depth, a.concurrency), (5, 8));
        }
    }

    #[test]
    fn the_limits_themselves_are_accepted() {
        // An off-by-one in the bound check would make the documented maximum
        // itself unusable, which is the failure nobody notices until a user
        // types exactly it.
        let a = crawl(&[
            "--depth",
            &MAX_DEPTH_LIMIT.to_string(),
            "--concurrency",
            &MAX_CONCURRENCY_LIMIT.to_string(),
        ])
        .unwrap();
        assert_eq!(a.depth, MAX_DEPTH_LIMIT);
        assert_eq!(a.concurrency, MAX_CONCURRENCY_LIMIT);
    }

    #[test]
    fn depth_above_the_ceiling_is_refused() {
        let err = crawl(&["--depth", &(MAX_DEPTH_LIMIT + 1).to_string()]).unwrap_err();
        assert!(err.contains("exceeds the maximum"), "{err}");
        // Depth 0 is meaningful: fetch the seed and follow nothing.
        assert_eq!(crawl(&["--depth", "0"]).unwrap().depth, 0);
    }

    #[test]
    fn concurrency_is_bounded_at_both_ends() {
        let high = crawl(&["--concurrency", &(MAX_CONCURRENCY_LIMIT + 1).to_string()]).unwrap_err();
        assert!(high.contains("exceeds the maximum"), "{high}");
        // Zero would be silently clamped to 1 by the engine's semaphore; say so
        // at the flag instead of quietly doing something else.
        assert!(
            crawl(&["--concurrency", "0"])
                .unwrap_err()
                .contains("at least 1")
        );
    }

    #[test]
    fn rate_limit_must_be_a_positive_finite_number() {
        for bad in ["0", "-3", "nan", "inf"] {
            assert!(
                crawl(&["--rate-limit", bad]).is_err(),
                "`--rate-limit {bad}` should be refused"
            );
        }
        assert_eq!(crawl(&["--rate-limit", "0.25"]).unwrap().rate_limit, 0.25);
    }

    #[test]
    fn robots_is_respected_unless_explicitly_turned_off() {
        assert!(!crawl(&[]).unwrap().ignore_robots, "the default is to obey");
        assert!(crawl(&["--ignore-robots"]).unwrap().ignore_robots);
    }
}
