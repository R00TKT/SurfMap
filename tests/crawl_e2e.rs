//! End-to-end: crawl a local site, then assert on what landed in SQLite.

mod support;

use std::path::PathBuf;
use std::time::Duration;

use rusqlite::Connection;
use tokio::sync::mpsc;

use surfmap::config::CrawlConfig;
use surfmap::engine::Engine;
use surfmap::scope::{Scope, ScopePolicy};
use surfmap::storage::{self, Store};

struct TempDb(PathBuf);

impl TempDb {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        TempDb(std::env::temp_dir().join(format!("surfmap-{tag}-{nanos}.db")))
    }
    fn path(&self) -> &PathBuf {
        &self.0
    }
    /// Main file plus WAL sidecars, for byte-level assertions.
    fn all_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for suffix in ["", "-wal", "-shm"] {
            let p = PathBuf::from(format!("{}{suffix}", self.0.display()));
            if let Ok(b) = std::fs::read(&p) {
                bytes.extend_from_slice(&b);
            }
        }
        bytes
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
    }
}

fn config(seed: String, db: PathBuf) -> CrawlConfig {
    CrawlConfig {
        seed,
        scope_policy: ScopePolicy::Host,
        extra_hosts: vec![],
        max_depth: 3,
        max_pages: 200,
        max_variants: 3,
        concurrency: 4,
        // Fast, because the target is a loopback fixture we control.
        rate_limit: 200.0,
        respect_robots: true,
        user_agent: "surfmap-test/0.1".to_string(),
        request_timeout: Duration::from_secs(5),
        max_body_bytes: 1024 * 1024,
        db_path: db,
    }
}

async fn crawl(cfg: CrawlConfig) -> (i64, surfmap::model::CrawlStats) {
    let seed_url = url::Url::parse(&cfg.seed).unwrap();
    let scope = Scope::new(&seed_url, cfg.scope_policy, &cfg.extra_hosts).unwrap();

    let store = Store::open(&cfg.db_path).unwrap();
    let crawl_id = store.begin_crawl(&cfg, &scope).unwrap();
    drop(store);

    let (tx, rx) = mpsc::channel(256);
    let writer = storage::spawn_writer(cfg.db_path.clone(), crawl_id, rx);

    let db_path = cfg.db_path.clone();
    let engine = Engine::new(cfg, scope).unwrap();
    let outcome = engine.run(tx.clone()).await.unwrap();
    drop(tx);
    writer.await.unwrap().unwrap();

    let store = Store::open(&db_path).unwrap();
    store
        .finish_crawl(crawl_id, outcome.stats, "complete")
        .unwrap();
    (crawl_id, outcome.stats)
}

fn count(conn: &Connection, sql: &str, id: i64) -> i64 {
    conn.query_row(sql, rusqlite::params![id], |r| r.get(0))
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crawls_a_site_and_records_its_attack_surface() {
    let (addr, requests) = support::spawn_site().await;
    let db = TempDb::new("e2e");
    let (crawl_id, stats) = crawl(config(format!("http://{addr}/"), db.path().clone())).await;

    assert!(stats.fetched >= 8, "expected a real crawl, got {stats:?}");

    let conn = Connection::open(db.path()).unwrap();
    let urls: Vec<String> = conn
        .prepare(
            "SELECT p.url FROM page_visits v JOIN pages p ON p.id=v.page_id
              WHERE v.crawl_id=?1 AND v.error IS NULL",
        )
        .unwrap()
        .query_map([crawl_id], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let has = |suffix: &str| urls.iter().any(|u| u.ends_with(suffix));

    // --- reach ---------------------------------------------------------
    assert!(has("/about"), "in-scope links are followed: {urls:?}");
    assert!(has("/login"));
    assert!(has("/upload"));
    assert!(has("/new"), "the 301 target is crawled as its own page");
    assert!(
        has("/recovered"),
        "links recovered from malformed markup are followed"
    );

    // --- scope and robots ----------------------------------------------
    assert!(
        !requests.hit("/admin/secret"),
        "robots.txt Disallow must be honoured before the request, not after: {:?}",
        requests.all()
    );
    assert!(
        !urls.iter().any(|u| u.contains("external.test")),
        "out-of-scope hosts are never fetched"
    );
    assert!(
        !urls.iter().any(|u| u.starts_with("javascript:")),
        "non-http schemes never enter the frontier"
    );

    // --- crawler trap ---------------------------------------------------
    let calendar_requests = requests.count_prefix("/calendar");
    assert_eq!(
        calendar_requests, 3,
        "12 calendar URLs share one signature; --max-variants caps them at 3"
    );

    // --- extraction ------------------------------------------------------
    let login_form: i64 = count(
        &conn,
        "SELECT COUNT(*) FROM attack_surface_forms
          WHERE crawl_id=?1 AND method='POST' AND has_password=1 AND action_url LIKE '%/session'",
        crawl_id,
    );
    assert_eq!(
        login_form, 1,
        "the login form is recorded as a POST input vector"
    );

    let upload_form: i64 = count(
        &conn,
        "SELECT COUNT(*) FROM attack_surface_forms WHERE crawl_id=?1 AND has_file_upload=1",
        crawl_id,
    );
    assert_eq!(upload_form, 1);

    let field_types: Vec<String> = conn
        .prepare(
            "SELECT fi.input_type FROM form_inputs fi
               JOIN forms f ON f.id=fi.form_id
               JOIN page_visits v ON v.id=f.visit_id
              WHERE v.crawl_id=?1",
        )
        .unwrap()
        .query_map([crawl_id], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(field_types.iter().any(|t| t == "password"));
    assert!(field_types.iter().any(|t| t == "hidden"));
    assert!(field_types.iter().any(|t| t == "file"));

    // --- findings ---------------------------------------------------------
    let insecure: i64 = count(
        &conn,
        "SELECT COUNT(*) FROM insecure_cookies WHERE crawl_id=?1 AND cookie_name='sid'",
        crawl_id,
    );
    assert_eq!(
        insecure, 1,
        "a cookie with no HttpOnly/Secure/SameSite is a finding"
    );

    let home_gaps: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM missing_security_headers
              WHERE crawl_id=?1 AND url LIKE '%/login'",
            [crawl_id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        home_gaps >= 5,
        "a page with no security headers reports gaps"
    );

    let about_csp: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM missing_security_headers
              WHERE crawl_id=?1 AND url LIKE '%/about' AND missing_header='content-security-policy'",
            [crawl_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        about_csp, 0,
        "a header that IS set must not be reported missing"
    );

    // --- parameters, scripts, graph ----------------------------------------
    let param_shapes: Vec<(String, String)> = conn
        .prepare(
            "SELECT DISTINCT up.name, up.value_shape FROM url_params up
               JOIN page_visits v ON v.id=up.visit_id WHERE v.crawl_id=?1",
        )
        .unwrap()
        .query_map([crawl_id], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(param_shapes.iter().any(|(n, _)| n == "q"));
    assert!(
        param_shapes
            .iter()
            .any(|(n, s)| n == "page" && s == "numeric")
    );
    assert!(param_shapes.iter().any(|(n, _)| n == "month"));

    let third_party: i64 = count(
        &conn,
        "SELECT COUNT(*) FROM scripts s JOIN page_visits v ON v.id=s.visit_id
          WHERE v.crawl_id=?1 AND s.third_party=1 AND s.host='cdn.third-party.test'",
        crawl_id,
    );
    assert_eq!(third_party, 1, "third-party script hosts are recorded");

    let inline_hashed: i64 = count(
        &conn,
        "SELECT COUNT(*) FROM scripts s JOIN page_visits v ON v.id=s.visit_id
          WHERE v.crawl_id=?1 AND s.is_inline=1 AND LENGTH(s.body_sha256)=64",
        crawl_id,
    );
    assert_eq!(inline_hashed, 1, "inline scripts are hashed, not stored");

    let redirect_edges: i64 = count(
        &conn,
        "SELECT COUNT(*) FROM edges WHERE crawl_id=?1 AND link_type='redirect'",
        crawl_id,
    );
    assert_eq!(
        redirect_edges, 1,
        "the 301 is an explicit edge in the graph"
    );

    let external_edges: i64 = count(
        &conn,
        "SELECT COUNT(*) FROM edges e JOIN pages p ON p.id=e.dst_page_id
          WHERE e.crawl_id=?1 AND e.in_scope=0 AND p.host='external.test'",
        crawl_id,
    );
    assert_eq!(
        external_edges, 1,
        "out-of-scope links are mapped but not fetched"
    );

    // --- the data-handling promise -----------------------------------------
    drop(conn);
    let bytes = db.all_bytes();
    for (label, canary) in [
        ("cookie value", support::CANARY_COOKIE),
        ("hidden form field value", support::CANARY_CSRF),
        ("response body text", support::CANARY_BODY),
    ] {
        assert!(
            !bytes.windows(canary.len()).any(|w| w == canary.as_bytes()),
            "{label} reached the database; it must never be persisted"
        );
    }
    // Query *values* are the one exception operators should know about: they
    // arrive inside URLs, which are recorded. Shapes are stored separately.
    assert!(
        param_shapes.iter().any(|(n, s)| n == "q" && s == "alnum"),
        "parameter shapes are catalogued without a value column"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crawl_terminates_and_respects_limits() {
    let (addr, _requests) = support::spawn_site().await;
    let db = TempDb::new("limits");

    let mut cfg = config(format!("http://{addr}/"), db.path().clone());
    cfg.max_pages = 5;
    cfg.max_depth = 1;

    // The real assertion is that this returns at all: a crawler whose
    // termination logic is wrong hangs here forever.
    let fetched = tokio::time::timeout(Duration::from_secs(30), crawl(cfg))
        .await
        .expect("crawl must terminate on its own")
        .1
        .fetched;

    assert!(fetched <= 5, "--max-pages is a hard cap, got {fetched}");
    assert!(fetched > 0);
}

/// A limit of zero rejects the seed itself. The frontier then never has a task
/// in flight, so the token that ends the crawl never fires and the dispatcher
/// waits on a queue nothing can fill -- previously an unkillable hang. Refusing
/// to start is the correct answer, and it has to arrive promptly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn degenerate_limits_refuse_to_start_instead_of_hanging() {
    let (addr, _requests) = support::spawn_site().await;
    let seed = format!("http://{addr}/");
    let seed_url = url::Url::parse(&seed).unwrap();

    for (label, max_pages, max_variants) in [("max_pages", 0, 3), ("max_variants", 200, 0)] {
        let db = TempDb::new(&format!("degenerate-{label}"));
        let mut cfg = config(seed.clone(), db.path().clone());
        cfg.max_pages = max_pages;
        cfg.max_variants = max_variants;

        let scope = Scope::new(&seed_url, cfg.scope_policy, &cfg.extra_hosts).unwrap();
        let engine = Engine::new(cfg, scope).unwrap();
        let (tx, mut rx) = mpsc::channel(16);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });

        let result = tokio::time::timeout(Duration::from_secs(10), engine.run(tx))
            .await
            .unwrap_or_else(|_| panic!("{label}=0 hung instead of returning"));
        let err = result.expect_err("a rejected seed is a setup error, not a silent empty crawl");
        assert!(
            err.to_string().contains("rejected by the frontier"),
            "error should name the cause, got: {err}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeat_crawls_accumulate_history_for_diffing() {
    let (addr, _requests) = support::spawn_site().await;
    let db = TempDb::new("diff");
    let seed = format!("http://{addr}/");

    let (first, _) = crawl(config(seed.clone(), db.path().clone())).await;
    let (second, _) = crawl(config(seed, db.path().clone())).await;
    assert_ne!(first, second);

    let conn = Connection::open(db.path()).unwrap();
    // `pages` is canonical across runs; `page_visits` is one row per run. The
    // same URL must therefore be one page row and two visit rows.
    let page_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pages WHERE url LIKE '%/about'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let visit_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM page_visits v JOIN pages p ON p.id=v.page_id
              WHERE p.url LIKE '%/about'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(page_rows, 1, "one canonical row per URL, across all crawls");
    assert_eq!(visit_rows, 2, "one observation row per crawl");

    let first_count = count(
        &conn,
        "SELECT COUNT(*) FROM page_visits WHERE crawl_id=?1",
        first,
    );
    let second_count = count(
        &conn,
        "SELECT COUNT(*) FROM page_visits WHERE crawl_id=?1",
        second,
    );
    assert_eq!(
        first_count, second_count,
        "a stable site yields a stable surface"
    );

    let report = surfmap::report::diff(&conn, first, second).unwrap();
    assert!(
        report.contains("New parameters: 0"),
        "no drift expected:\n{report}"
    );

    // A third, deliberately shallow run: everything the deeper runs reached is
    // now unreachable, and must be reported as a removal. Signing those `+`
    // tells an assessor the surface grew when it shrank.
    let mut shallow = config(format!("http://{addr}/"), db.path().clone());
    shallow.max_depth = 0;
    let (third, _) = crawl(shallow).await;

    let report = surfmap::report::diff(&conn, second, third).unwrap();
    let gone: Vec<&str> = report
        .lines()
        .skip_while(|l| !l.starts_with("Pages no longer reachable"))
        .skip(1)
        .take_while(|l| l.starts_with("    "))
        .collect();
    assert!(
        !gone.is_empty(),
        "a depth-0 run should drop pages:\n{report}"
    );
    assert!(
        gone.iter().all(|l| l.trim_start().starts_with('-')),
        "removals must be signed `-`, got:\n{}",
        gone.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ad_hoc_queries_cannot_write() {
    let (addr, _requests) = support::spawn_site().await;
    let db = TempDb::new("readonly");
    let (crawl_id, _) = crawl(config(format!("http://{addr}/"), db.path().clone())).await;

    let conn = surfmap::report::open_readonly(db.path()).unwrap();

    // Reads work.
    let pages: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM page_visits WHERE crawl_id=?1",
            [crawl_id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(pages > 0);

    // Writes are refused by the engine, not by inspecting the query text.
    for sql in [
        "DELETE FROM pages",
        "UPDATE crawls SET status='tampered'",
        "DROP TABLE forms",
        "INSERT INTO pages (url, scheme, host, path, first_seen) VALUES ('x','http','x','/','now')",
    ] {
        let err = conn.execute(sql, []).expect_err("write must be refused");
        assert!(
            err.to_string().contains("readonly") || err.to_string().contains("read-only"),
            "unexpected error for `{sql}`: {err}"
        );
    }

    // And the data is intact afterwards.
    let after: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM page_visits WHERE crawl_id=?1",
            [crawl_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pages, after);
}
