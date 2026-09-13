use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;
use anyhow::{Context, Result, bail};
use clap::Parser;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;
use url::Url;
use surfmap::brute::wordlist;
use surfmap::brute::{BruteArgs, Discovery, StatusFilter};
use surfmap::cli::{Cli, Command, CrawlArgs, ReportArgs, ReportKind};
use surfmap::config::{CrawlConfig, DEFAULT_USER_AGENT};
use surfmap::engine::Engine;
use surfmap::report;
use surfmap::scope::Scope;
use surfmap::storage::{self, Store};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match &cli.command {
        Command::Crawl(args) => run_crawl(&cli, args).await,
        Command::Brute(args) => run_brute(&cli, args).await,
        Command::Report(args) => run_report(&cli, args),
        Command::Crawls => {
            let conn = report::open_readonly(&cli.db)?;
            emit(&cli, report::crawls(&conn)?);
            Ok(())
        }
        Command::Diff { base, target } => {
            let conn = report::open_readonly(&cli.db)?;
            print!("{}", report::diff(&conn, *base, *target)?);
            Ok(())
        }
        Command::Query { sql, limit } => {
            let conn = report::open_readonly(&cli.db)?;
            let table = report::query(&conn, &format!("SELECT * FROM ({sql}) LIMIT {limit}"), &[])?;
            emit(&cli, table);
            Ok(())
        }
        Command::Schema => {
            println!("{}", Store::schema_sql());
            Ok(())
        }
    }
}

fn init_tracing(verbose: u8) {
    // Default to surfmap's own events only: at debug level, hyper and rustls
    let default = match verbose {
        0 => "surfmap=info",
        1 => "surfmap=debug",
        _ => "surfmap=trace,reqwest=debug",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default)),
        )
        .with_target(false)
        .compact()
        .init();
}
async fn run_crawl(cli: &Cli, args: &CrawlArgs) -> Result<()> {
    let seed = Url::parse(&args.url).with_context(|| {
        format!(
            "`{}` is not a valid URL (did you include http:// ?)",
            args.url
        )
    })?;
    if !matches!(seed.scheme(), "http" | "https") {
        bail!("seed must be http or https, got `{}`", seed.scheme());
    }

    let scope = Scope::new(&seed, args.scope, &args.hosts).map_err(|e| anyhow::anyhow!(e))?;
    let cfg = CrawlConfig {
        seed: seed.to_string(),
        scope_policy: args.scope,
        extra_hosts: args.hosts.clone(),
        max_depth: args.depth,
        max_pages: args.max_pages,
        max_variants: args.max_variants,
        concurrency: args.concurrency,
        rate_limit: args.rate_limit,
        respect_robots: !args.ignore_robots,
        user_agent: args
            .user_agent
            .clone()
            .unwrap_or_else(|| DEFAULT_USER_AGENT.to_string()),
        request_timeout: Duration::from_secs(args.timeout),
        max_body_bytes: args.max_body_mb * 1024 * 1024,
        db_path: cli.db.clone(),
    };

    confirm_authorization(&cfg, &scope, args.assume_authorized)?;

    let store = Store::open(&cli.db)?;
    let crawl_id = store.begin_crawl(&cfg, &scope)?;
    drop(store);

    let (tx, rx) = mpsc::channel(256);
    let writer = storage::spawn_writer(cli.db.clone(), crawl_id, rx);

    let engine = Engine::new(cfg, scope)?;
    let started = std::time::Instant::now();
    let outcome = engine.run(tx.clone()).await;


    drop(tx);
    let write_result = writer.await.context("storage writer task panicked")?;

    let store = Store::open(&cli.db)?;
    let outcome = match outcome {
        Ok(o) => o,
        Err(e) => {
            store.finish_crawl(crawl_id, Default::default(), "failed")?;
            return Err(e);
        }
    };
    write_result?;

    let status = if outcome.interrupted {
        "interrupted"
    } else {
        "complete"
    };
    store.finish_crawl(crawl_id, outcome.stats, status)?;

    let elapsed = started.elapsed();
    println!();
    println!(
        "Crawl #{crawl_id} {status} in {:.1}s -- {} fetched, {} skipped, {} errors",
        elapsed.as_secs_f64(),
        outcome.stats.fetched,
        outcome.stats.skipped,
        outcome.stats.errors
    );
    if outcome.stats.fetched > 0 {
        println!(
            "  {:.1} pages/sec",
            outcome.stats.fetched as f64 / elapsed.as_secs_f64().max(0.001)
        );
    }
    println!();
    print!("{}", report::summary(store.conn(), crawl_id)?);
    Ok(())
}

async fn run_brute(cli: &Cli, args: &BruteArgs) -> Result<()> {
    let seed =
        Url::parse(&args.url).with_context(|| format!("`{}` is not a valid URL", args.url))?;
    if !matches!(seed.scheme(), "http" | "https") {
        bail!("target must be http or https, got `{}`", seed.scheme());
    }
    let base = ensure_directory(&seed);

    let scope = Scope::new(&base, args.scope, &args.hosts).map_err(|e| anyhow::anyhow!(e))?;
    let accept = StatusFilter::parse(&args.status).map_err(|e| anyhow::anyhow!("--status: {e}"))?;
    let words = wordlist::load(args.wordlist.as_deref())?;
    let extensions: Vec<String> = args
        .extensions
        .iter()
        .map(|e| e.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|e| !e.is_empty())
        .collect();
    let discovery = Arc::new(Discovery::new(
        words,
        extensions.clone(),
        accept,
        args.depth,
    ));
    let cfg = CrawlConfig {
        seed: base.to_string(),
        scope_policy: args.scope,
        extra_hosts: args.hosts.clone(),
        max_depth: args.depth + 1,
        max_pages: args.max_requests,
        max_variants: 16,
        concurrency: args.concurrency,
        rate_limit: args.rate_limit,
        respect_robots: !args.ignore_robots,
        user_agent: args
            .user_agent
            .clone()
            .unwrap_or_else(|| DEFAULT_USER_AGENT.to_string()),
        request_timeout: Duration::from_secs(args.timeout),
        max_body_bytes: 4 * 1024 * 1024,
        db_path: cli.db.clone(),
    };

    confirm_probe_authorization(&cfg, &scope, &discovery, &extensions, args)?;

    let store = Store::open(&cli.db)?;
    let crawl_id = store.begin_crawl(&cfg, &scope)?;
    drop(store);

    let (tx, rx) = mpsc::channel(256);
    let writer = storage::spawn_writer(cli.db.clone(), crawl_id, rx);
    let engine = Engine::new(cfg, scope)?
        .with_discovery(discovery.clone())
        .following_links(args.crawl_hits);
    let started = std::time::Instant::now();
    let outcome = engine.run(tx.clone()).await;

    drop(tx);
    let write_result = writer.await.context("storage writer task panicked")?;

    let store = Store::open(&cli.db)?;
    let outcome = match outcome {
        Ok(o) => o,
        Err(e) => {
            store.finish_crawl(crawl_id, Default::default(), "failed")?;
            return Err(e);
        }
    };
    write_result?;

    let status = if outcome.interrupted {
        "interrupted"
    } else {
        "complete"
    };
    store.finish_crawl(crawl_id, outcome.stats, status)?;

    let elapsed = started.elapsed();
    println!();
    println!(
        "Discovery #{crawl_id} {status} in {:.1}s -- {} found, {} misses, {} errors",
        elapsed.as_secs_f64(),
        discovery.hits(),
        outcome.stats.skipped,
        outcome.stats.errors
    );
    println!();
    print!(
        "{}",
        report::discovered(store.conn(), crawl_id, 200)?.render()
    );
    println!("\nFull surface for these pages: surfmap report forms | headers | params");
    Ok(())
}


fn ensure_directory(url: &Url) -> Url {
    let mut out = url.clone();
    out.set_fragment(None);
    out.set_query(None);
    if !out.path().ends_with('/') {
        let path = format!("{}/", out.path());
        out.set_path(&path);
    }
    out
}






fn confirm_probe_authorization(
    cfg: &CrawlConfig,
    scope: &Scope,
    discovery: &Discovery,
    extensions: &[String],
    args: &BruteArgs,
) -> Result<()> {
    const PHRASE: &str = "probe";
    let host = Url::parse(&cfg.seed)?
        .host_str()
        .unwrap_or_default()
        .to_string();

    let per_dir = discovery.candidates_per_dir();
    let seconds = per_dir as f64 / cfg.rate_limit.max(0.001);

    println!("  PATH DISCOVERY -- AUTHORIZATION CHECK");
    println!("  ---------------------------------------------------------------");
    println!("  base          {}", cfg.seed);
    println!("  scope         {} ({})", scope.describe(), scope.policy());
    println!(
        "  wordlist      {} words{}",
        discovery.word_count(),
        if extensions.is_empty() {
            String::new()
        } else {
            format!(
                " x {} extensions ({})",
                extensions.len() + 1,
                extensions.join(", ")
            )
        }
    );
    println!(
        "  requests      {per_dir} per directory | {} recursion levels | {} hard cap",
        args.depth, args.max_requests
    );
    println!(
        "  politeness    {:.2} req/s per host | {} concurrent | ~{} for one directory",
        cfg.rate_limit,
        cfg.concurrency,
        human_duration(seconds)
    );
    println!(
        "  robots.txt    {}",
        if cfg.respect_robots {
            "respected (disallowed paths are not probed)"
        } else {
            "IGNORED  <-- requires explicit written authorization"
        }
    );
    println!("  database      {}", cfg.db_path.display());
    println!("  ---------------------------------------------------------------");
    println!("  This sends requests for paths `{host}` never advertised. It is");
    println!("  active testing: it will appear in the target's logs as scanning,");
    println!("  and may trip rate limits, WAF rules or alerting.");
    println!("  ---------------------------------------------------------------");

    if args.assume_authorized {
        println!("  Authorization asserted with --yes for `{host}`.");
        if !cfg.respect_robots {
            println!("  robots.txt is DISABLED for this run under that assertion.");
        }
        println!();
        return Ok(());
    }
    print!("  Type `{PHRASE}` to confirm you are authorized to scan `{host}`: ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("reading confirmation")?;
    if answer.trim() != PHRASE {
        bail!("path discovery not confirmed (expected `{PHRASE}`); aborting");
    }
    println!();

    if !cfg.respect_robots {
        confirm_robots_override(&host)?;
    }
    Ok(())
}

fn human_duration(seconds: f64) -> String {
    if seconds < 90.0 {
        format!("{seconds:.0}s")
    } else if seconds < 5400.0 {
        format!("{:.0}m", seconds / 60.0)
    } else {
        format!("{:.1}h", seconds / 3600.0)
    }
}

/// The scope gate.

fn confirm_authorization(cfg: &CrawlConfig, scope: &Scope, assume: bool) -> Result<()> {
    let seed = Url::parse(&cfg.seed)?;
    let host = seed.host_str().unwrap_or_default().to_string();

    println!("  AUTHORIZATION CHECK");
    println!("  ---------------------------------------------------------------");
    println!("  seed          {}", cfg.seed);
    println!("  scope         {} ({})", scope.describe(), scope.policy());
    println!(
        "  limits        depth {} | max {} pages | {} variants per URL shape",
        cfg.max_depth, cfg.max_pages, cfg.max_variants
    );
    println!(
        "  politeness    {:.2} req/s per host | {} concurrent | {:.1}s min spacing",
        cfg.rate_limit,
        cfg.concurrency,
        cfg.min_interval().as_secs_f64()
    );
    println!(
        "  robots.txt    {}",
        if cfg.respect_robots {
            "respected"
        } else {
            "IGNORED  <-- requires explicit written authorization"
        }
    );
    println!("  database      {}", cfg.db_path.display());
    println!("  not stored    cookie values, response bodies, form field values");
    println!("  ---------------------------------------------------------------");

    if assume {
        println!("  Authorization asserted with --yes for `{host}`.");
        if !cfg.respect_robots {
            println!(
                "  robots.txt is DISABLED for this run under that assertion.\n\
                 \x20 Written authorization to ignore it is assumed to exist."
            );
        }
        println!();
        return Ok(());
    }

    println!("  Crawling a system without authorization may be unlawful.");
    print!("  Type the target host to confirm you are authorized to test it: ");
    io::stdout().flush()?;

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("reading confirmation")?;
    if answer.trim() != host {
        bail!("authorization not confirmed (expected `{host}`); aborting");
    }
    println!();

    if !cfg.respect_robots {
        confirm_robots_override(&host)?;
    }
    Ok(())
}


/// The second gate, for `--ignore-robots` only.
fn confirm_robots_override(host: &str) -> Result<()> {
    const PHRASE: &str = "ignore robots";

    println!("  ROBOTS.TXT OVERRIDE");
    println!("  ---------------------------------------------------------------");
    println!("  --ignore-robots is set, so surfmap will request paths that");
    println!("  `{host}` has asked crawlers not to visit -- including any");
    println!("  Disallow rule naming an admin, backup or internal path.");
    println!();
    println!("  Only proceed if your written authorization for this engagement");
    println!("  covers those paths. Scope confirmation above does not cover it.");
    println!("  ---------------------------------------------------------------");
    print!("  Type `{PHRASE}` to confirm you are authorized to do this: ");
    io::stdout().flush()?;

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("reading robots.txt override confirmation")?;
    if answer.trim() != PHRASE {
        bail!(
            "robots.txt override not confirmed (expected `{PHRASE}`); aborting.\n\
             Re-run without --ignore-robots to crawl with robots.txt respected."
        );
    }
    println!();
    Ok(())
}

fn run_report(cli: &Cli, args: &ReportArgs) -> Result<()> {
    let conn = report::open_readonly(&cli.db)?;
    let crawl_id = storage::resolve_crawl_id(&conn, args.crawl)?;
    let limit = args.limit;

    let table = match args.kind {
        ReportKind::Summary => {
            print!("{}", report::summary(&conn, crawl_id)?);
            return Ok(());
        }
        ReportKind::Dot => {
            print!("{}", report::graph_dot(&conn, crawl_id, limit)?);
            return Ok(());
        }
        ReportKind::Pages => report::pages(&conn, crawl_id, limit)?,
        ReportKind::Headers => report::missing_headers(&conn, crawl_id, limit)?,
        ReportKind::Forms => report::forms(&conn, crawl_id, limit)?,
        ReportKind::Params => report::params(&conn, crawl_id, limit)?,
        ReportKind::Cookies => report::cookies(&conn, crawl_id, limit)?,
        ReportKind::Scripts => report::scripts(&conn, crawl_id, limit)?,
        ReportKind::Errors => report::errors(&conn, crawl_id, limit)?,
        ReportKind::Discovered => report::discovered(&conn, crawl_id, limit)?,
        ReportKind::Graph => report::graph(&conn, crawl_id, limit)?,
    };
    if !cli.json {
        println!("crawl #{crawl_id} -- {:?} report", args.kind);
    }
    emit(cli, table);
    Ok(())
}

fn emit(cli: &Cli, table: report::Table) {
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&table.to_json()).unwrap_or_default()
        );
    } else {
        print!("{}", table.render());
    }
}
