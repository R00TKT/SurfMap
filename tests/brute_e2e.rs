//! End-to-end: probe a wordlist against the fixture site, then assert on what
//! landed in SQLite.
//!
//! The assertions that matter are the two failure modes real path-discovery
//! tools have: reporting a soft 404 as a find, and refusing to look at a
//! directory the server announced with a redirect.

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rusqlite::Connection;
use tokio::sync::mpsc;

use surfmap::brute::{Discovery, StatusFilter};
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
        TempDb(std::env::temp_dir().join(format!("surfmap-brute-{tag}-{nanos}.db")))
    }
    fn path(&self) -> &PathBuf {
        &self.0
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
    }
}

fn config(base: &str, db: PathBuf, depth: u32) -> CrawlConfig {
    CrawlConfig {
        seed: base.to_string(),
        scope_policy: ScopePolicy::Host,
        extra_hosts: vec![],
        max_depth: depth + 1,
        max_pages: 5_000,
        max_variants: 16,
        concurrency: 4,
        rate_limit: 500.0,
        // The fixture disallows /admin; probing must honour that by default.
        respect_robots: true,
        user_agent: "surfmap-test/0.1".to_string(),
        request_timeout: Duration::from_secs(5),
        max_body_bytes: 1024 * 1024,
        db_path: db,
    }
}

/// Run a discovery pass and return (crawl id, hits, connection).
async fn brute(
    base: &str,
    db: &TempDb,
    words: &[&str],
    extensions: &[&str],
    depth: u32,
) -> (i64, u64) {
    let cfg = config(base, db.path().clone(), depth);
    let scope = Scope::new(&url::Url::parse(base).unwrap(), cfg.scope_policy, &[]).unwrap();

    let discovery = Arc::new(Discovery::new(
        words.iter().map(|w| w.to_string()).collect(),
        extensions.iter().map(|e| e.to_string()).collect(),
        StatusFilter::default(),
        depth,
    ));

    let store = Store::open(&cfg.db_path).unwrap();
    let crawl_id = store.begin_crawl(&cfg, &scope).unwrap();
    drop(store);

    let (tx, rx) = mpsc::channel(256);
    let writer = storage::spawn_writer(db.path().clone(), crawl_id, rx);

    let engine = Engine::new(cfg, scope)
        .unwrap()
        .with_discovery(discovery.clone());
    let outcome = tokio::time::timeout(Duration::from_secs(60), engine.run(tx.clone()))
        .await
        .expect("discovery must terminate on its own")
        .unwrap();
    drop(tx);
    writer.await.unwrap().unwrap();

    let store = Store::open(db.path()).unwrap();
    store
        .finish_crawl(crawl_id, outcome.stats, "complete")
        .unwrap();
    (crawl_id, discovery.hits())
}

fn probed_urls(conn: &Connection, crawl_id: i64) -> Vec<String> {
    conn.prepare(
        "SELECT p.url FROM page_visits v JOIN pages p ON p.id = v.page_id
          WHERE v.crawl_id = ?1 AND v.error IS NULL AND v.discovered_by = 'probe'
          ORDER BY p.url",
    )
    .unwrap()
    .query_map([crawl_id], |r| r.get(0))
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn finds_unlinked_files_a_crawl_cannot_reach() {
    let (addr, _requests) = support::spawn_site().await;
    let db = TempDb::new("unlinked");
    let base = format!("http://{addr}/");

    let (id, hits) = brute(
        &base,
        &db,
        &[
            "hidden-backup",
            "secret-config",
            "tools",
            "absent",
            "nothing",
        ],
        &["sql"],
        0,
    )
    .await;

    let found = probed_urls(&Connection::open(db.path()).unwrap(), id);
    let has = |s: &str| found.iter().any(|u| u.ends_with(s));

    assert!(
        has("/hidden-backup.sql"),
        "the extension expansion must reach it: {found:?}"
    );
    assert!(has("/secret-config"), "403 is a discovery: {found:?}");
    assert!(
        has("/tools"),
        "a 301 to a directory is a discovery: {found:?}"
    );
    assert!(
        !found
            .iter()
            .any(|u| u.ends_with("/absent") || u.ends_with("/nothing")),
        "paths that do not exist must not be reported: {found:?}"
    );
    assert_eq!(
        hits as usize,
        found.len(),
        "hit counter matches what was stored"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_soft_404_subtree_yields_only_the_file_that_exists() {
    // Every unknown path under /soft/ answers 200 with a page echoing the path.
    // Without calibration every word below would be reported as a find.
    let (addr, _requests) = support::spawn_site().await;
    let db = TempDb::new("soft404");
    let base = format!("http://{addr}/soft/");

    let words = ["real", "ghost", "phantom", "absent", "missing", "nowhere"];
    let (id, _) = brute(&base, &db, &words, &["txt"], 0).await;

    let found = probed_urls(&Connection::open(db.path()).unwrap(), id);
    assert_eq!(
        found.len(),
        1,
        "only /soft/real.txt exists; the rest are dressed-up 404s: {found:?}"
    );
    assert!(found[0].ends_with("/soft/real.txt"), "{found:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recursion_descends_into_a_directory_announced_by_redirect() {
    let (addr, _requests) = support::spawn_site().await;
    let db = TempDb::new("recurse");
    let base = format!("http://{addr}/");

    // `tools` is a 301 to `/tools/`; `debug` only exists inside it, so finding
    // it proves the redirect was read as "this is a directory".
    let (id, _) = brute(&base, &db, &["tools", "debug"], &[], 1).await;

    let conn = Connection::open(db.path()).unwrap();
    let found = probed_urls(&conn, id);
    assert!(
        found.iter().any(|u| u.ends_with("/tools/debug")),
        "recursion should reach inside /tools/: {found:?}"
    );

    // The directory body itself is fetched too, so its surface is recorded
    // rather than only the bare redirect.
    let dir_visits: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM page_visits v JOIN pages p ON p.id = v.page_id
              WHERE v.crawl_id = ?1 AND p.url LIKE '%/tools/' AND v.error IS NULL",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(dir_visits, 1, "the directory itself must be fetched");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn robots_disallowed_paths_are_not_probed() {
    // The fixture's robots.txt disallows /admin. Probing is active testing, so
    // it must respect that by default rather than treating a wordlist as
    // permission to ignore it.
    let (addr, requests) = support::spawn_site().await;
    let db = TempDb::new("robots");
    let base = format!("http://{addr}/");

    let (id, _) = brute(&base, &db, &["admin", "tools"], &[], 0).await;

    assert!(
        !requests.hit("/admin"),
        "a disallowed path must not be requested: {:?}",
        requests.all()
    );
    let found = probed_urls(&Connection::open(db.path()).unwrap(), id);
    assert!(
        !found.iter().any(|u| u.ends_with("/admin")),
        "and must not be reported: {found:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probing_records_the_full_surface_of_what_it_finds() {
    // A discovered page is not just a URL and a status: it goes through the
    // same extraction a crawled page does, so its headers are recorded too.
    let (addr, _requests) = support::spawn_site().await;
    let db = TempDb::new("surface");
    let base = format!("http://{addr}/");

    let (id, _) = brute(&base, &db, &["login", "upload"], &[], 0).await;

    let conn = Connection::open(db.path()).unwrap();
    let headers: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM response_headers h
               JOIN page_visits v ON v.id = h.visit_id
              WHERE v.crawl_id = ?1 AND v.discovered_by = 'probe'",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(headers > 0, "probe hits are extracted like any other page");

    // The login form lives on a page nothing linked to in this run.
    let forms: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM forms f
               JOIN page_visits v ON v.id = f.visit_id
              WHERE v.crawl_id = ?1 AND v.discovered_by = 'probe'",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        forms > 0,
        "a form found by probing is still an input vector"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovery_is_bounded_by_the_request_budget() {
    let (addr, _requests) = support::spawn_site().await;
    let db = TempDb::new("budget");
    let base = format!("http://{addr}/");

    let mut cfg = config(&base, db.path().clone(), 1);
    cfg.max_pages = 12;
    let scope = Scope::new(&url::Url::parse(&base).unwrap(), cfg.scope_policy, &[]).unwrap();

    let words: Vec<String> = (0..500).map(|i| format!("w{i}")).collect();
    let discovery = Arc::new(Discovery::new(words, vec![], StatusFilter::default(), 1));

    let store = Store::open(&cfg.db_path).unwrap();
    let crawl_id = store.begin_crawl(&cfg, &scope).unwrap();
    drop(store);
    let (tx, rx) = mpsc::channel(256);
    let writer = storage::spawn_writer(db.path().clone(), crawl_id, rx);

    let engine = Engine::new(cfg, scope).unwrap().with_discovery(discovery);
    let outcome = tokio::time::timeout(Duration::from_secs(30), engine.run(tx.clone()))
        .await
        .expect("a capped run must still terminate")
        .unwrap();
    drop(tx);
    writer.await.unwrap().unwrap();

    let sent = outcome.stats.fetched + outcome.stats.skipped + outcome.stats.errors;
    assert!(
        sent <= 12,
        "--max-requests is a hard cap on what the target sees, got {sent}"
    );
}
