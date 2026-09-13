//! Stress tests for the engine against a server that behaves badly.
//!
//! The fixture here speaks raw TCP rather than HTTP, because the interesting
//! cases are the ones a well-behaved server cannot produce: a `Content-Length`
//! that lies, a body that never ends, a connection dropped mid-response, a
//! redirect that points at itself.
//!
//! Every test asserts the same two things in some form. The crawl **terminates**
//! -- a hostile page must not be able to hang the run -- and it terminates
//! *without* the bad page taking the rest of the crawl down with it.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rusqlite::Connection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use surfmap::config::CrawlConfig;
use surfmap::engine::Engine;
use surfmap::scope::{Scope, ScopePolicy};
use surfmap::storage::{self, Store};

/// No crawl in this file should take anywhere near this. Exceeding it means a
/// hostile response hung the engine, which is the failure these tests exist for.
const HARD_TIMEOUT: Duration = Duration::from_secs(45);

struct TempDb(PathBuf);

impl TempDb {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        TempDb(std::env::temp_dir().join(format!("surfmap-hostile-{tag}-{nanos}.db")))
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

/// A server that answers every request according to `mode`.
async fn spawn_hostile(mode: &'static str) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let counter = counter.clone();
            tokio::spawn(async move {
                let _ = serve(stream, mode, addr, counter).await;
            });
        }
    });
    (addr, hits)
}

async fn read_request(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

async fn serve(
    mut stream: TcpStream,
    mode: &str,
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    let head = read_request(&mut stream).await?;
    let target = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
    hits.fetch_add(1, Ordering::Relaxed);

    // Always answer robots.txt honestly, so these tests exercise the engine
    // rather than the robots fetch.
    if target == "/robots.txt" {
        let body = "User-agent: *\nDisallow:\n";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    match mode {
        // Declares 10 bytes, sends megabytes. Trusting the header would mean
        // reading far more than the operator allowed.
        "lying_content_length" => {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 10\r\nConnection: close\r\n\r\n")
                .await?;
            let chunk = "<div>padding</div>".repeat(4096); // ~72 KB
            for _ in 0..200 {
                if stream.write_all(chunk.as_bytes()).await.is_err() {
                    break;
                }
            }
        }

        // A body with no end, sent as fast as it is accepted.
        "endless_body" => {
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n",
                )
                .await?;
            let chunk = "a".repeat(65536);
            loop {
                if stream.write_all(chunk.as_bytes()).await.is_err() {
                    break;
                }
            }
        }

        // Headers promise a body, then the connection drops.
        "truncated_body" => {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n<html><title>cut")
                .await?;
            // Dropping the stream here closes it mid-body.
        }

        // Two pages that redirect to each other forever.
        "redirect_loop" => {
            let next = if target.contains("/a") { "/b" } else { "/a" };
            let resp = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{addr}{next}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(resp.as_bytes()).await?;
        }

        // Points at itself.
        "self_redirect" => {
            let resp = format!(
                "HTTP/1.1 301 Moved Permanently\r\nLocation: http://{addr}{target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(resp.as_bytes()).await?;
        }

        // 3xx responses whose Location is missing, empty, or unusable.
        "broken_redirects" => {
            let location = match target.as_str() {
                "/" => Some("javascript:alert(1)".to_string()),
                "/none" => None,
                "/empty" => Some(String::new()),
                "/space" => Some("   ".to_string()),
                "/control" => Some("/ok\u{1}\u{2}".to_string()),
                _ => Some("/ok".to_string()),
            };
            let mut resp = String::from("HTTP/1.1 302 Found\r\n");
            if let Some(l) = location {
                resp.push_str(&format!("Location: {l}\r\n"));
            }
            resp.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
            stream.write_all(resp.as_bytes()).await?;
        }

        // A body that is not UTF-8 at all, declared as HTML.
        "binary_body" => {
            let mut body: Vec<u8> = (0..=255u8).cycle().take(40_000).collect();
            body.extend_from_slice(b"<a href=/x>link</a>");
            let mut resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            resp.extend_from_slice(&body);
            stream.write_all(&resp).await?;
        }

        // Status codes and content types outside anything sensible.
        "weird_status" => {
            let (code, ctype) = match target.as_str() {
                "/" => (200, "text/html"),
                "/s204" => (204, "text/html"),
                "/s418" => (418, "text/html"),
                "/s599" => (599, "text/html"),
                "/ctype" => (200, "not/a/real/type; charset=\u{0}bogus"),
                "/noctype" => (200, ""),
                _ => (200, "text/html"),
            };
            let body = "<html><title>x</title><a href=/s204>a</a><a href=/s418>b</a>\
                        <a href=/s599>c</a><a href=/ctype>d</a><a href=/noctype>e</a></html>";
            let mut resp = format!("HTTP/1.1 {code} X\r\n");
            if !ctype.is_empty() {
                resp.push_str(&format!("Content-Type: {ctype}\r\n"));
            }
            resp.push_str(&format!(
                "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ));
            stream.write_all(resp.as_bytes()).await?;
        }

        // Answers, then nothing at all.
        "empty_response" => {}

        // Not HTTP.
        "garbage_protocol" => {
            stream.write_all(&[0xff; 4096]).await?;
        }

        // Thousands of response headers.
        "header_flood" => {
            let mut resp = String::from("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n");
            for i in 0..2_000 {
                resp.push_str(&format!("X-Pad-{i}: {}\r\n", "v".repeat(64)));
            }
            resp.push_str("Content-Length: 4\r\nConnection: close\r\n\r\nhiya");
            stream.write_all(resp.as_bytes()).await?;
        }

        // Sends a byte every few hundred ms and never finishes.
        "slowloris_body" => {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1000000\r\nConnection: close\r\n\r\n")
                .await?;
            loop {
                if stream.write_all(b"a").await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }

        _ => unreachable!("unknown mode {mode}"),
    }
    Ok(())
}

fn config(seed: String, db: PathBuf) -> CrawlConfig {
    CrawlConfig {
        seed,
        scope_policy: ScopePolicy::Host,
        extra_hosts: vec![],
        max_depth: 3,
        max_pages: 50,
        max_variants: 5,
        concurrency: 4,
        rate_limit: 500.0,
        respect_robots: true,
        user_agent: "surfmap-hostile-test/0.1".to_string(),
        request_timeout: Duration::from_secs(3),
        max_body_bytes: 256 * 1024,
        db_path: db,
    }
}

/// Run a crawl that must terminate, and hand back its stats plus a connection.
async fn crawl(cfg: CrawlConfig) -> (i64, surfmap::model::CrawlStats) {
    let seed_url = url::Url::parse(&cfg.seed).unwrap();
    let scope = Scope::new(&seed_url, cfg.scope_policy, &[]).unwrap();

    let store = Store::open(&cfg.db_path).unwrap();
    let crawl_id = store.begin_crawl(&cfg, &scope).unwrap();
    drop(store);

    let (tx, rx) = mpsc::channel(256);
    let writer = storage::spawn_writer(cfg.db_path.clone(), crawl_id, rx);
    let db_path = cfg.db_path.clone();

    let engine = Engine::new(cfg, scope).unwrap();
    let outcome = tokio::time::timeout(HARD_TIMEOUT, engine.run(tx.clone()))
        .await
        .expect("a hostile response must not be able to hang the crawl")
        .expect("the crawl itself must not fail");
    drop(tx);
    writer
        .await
        .expect("storage writer must not panic")
        .expect("storage must not error");

    let store = Store::open(&db_path).unwrap();
    store
        .finish_crawl(crawl_id, outcome.stats, "complete")
        .unwrap();
    (crawl_id, outcome.stats)
}

async fn run_against(mode: &'static str, tag: &str) -> (TempDb, i64, surfmap::model::CrawlStats) {
    let (addr, _hits) = spawn_hostile(mode).await;
    let db = TempDb::new(tag);
    let (id, stats) = crawl(config(format!("http://{addr}/"), db.path().clone())).await;
    (db, id, stats)
}

fn errors_for(db: &TempDb, id: i64) -> Vec<String> {
    let conn = Connection::open(db.path()).unwrap();
    conn.prepare("SELECT error FROM page_visits WHERE crawl_id=?1 AND error IS NOT NULL")
        .unwrap()
        .query_map([id], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

// ---------------------------------------------------------------------------

/// A server that *understates* `Content-Length` and then floods the socket
/// cannot make the engine read more than it agreed to.
///
/// The read stops at the declared length, so this truncates rather than
/// overruns -- which is the safe direction. The unbounded case, where no length
/// is declared at all, is covered by the next test and is the one the streaming
/// cap exists for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_understated_content_length_truncates_rather_than_overruns() {
    let started = std::time::Instant::now();
    let (db, id, _) = run_against("lying_content_length", "lying-cl").await;
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "reading stopped at the declared length rather than draining the flood"
    );
    let conn = Connection::open(db.path()).unwrap();
    let lengths: Vec<i64> = conn
        .prepare("SELECT content_length FROM page_visits WHERE crawl_id=?1 AND content_length IS NOT NULL")
        .unwrap()
        .query_map([id], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for len in &lengths {
        assert!(
            *len <= 256 * 1024,
            "accepted {len} bytes, past the configured cap"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_endless_body_is_cut_off_rather_than_read_forever() {
    let (db, id, _) = run_against("endless_body", "endless").await;
    let errors = errors_for(&db, id);
    assert!(
        errors.iter().any(|e| e.contains("exceeded")),
        "an unbounded body must hit the cap: {errors:?}"
    );
}

/// A body that stops early is a transport error, recorded and moved past.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_truncated_body_is_recorded_as_an_error_not_a_page() {
    let (db, id, stats) = run_against("truncated_body", "truncated").await;
    assert_eq!(stats.fetched, 0, "a half-received page is not a page");
    assert!(
        !errors_for(&db, id).is_empty(),
        "the failure must be recorded"
    );
}

/// Two pages pointing at each other is the classic way to make a crawler spin.
/// The visited set is what stops it, and the test is simply that we get here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_redirect_loop_terminates() {
    let (addr, hits) = spawn_hostile("redirect_loop").await;
    let db = TempDb::new("redirect-loop");
    let (_, stats) = crawl(config(format!("http://{addr}/a"), db.path().clone())).await;
    let requests = hits.load(Ordering::Relaxed);
    assert!(
        requests <= 10,
        "a two-page redirect loop should be closed by the visited set, got {requests} requests"
    );
    assert!(stats.fetched >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_self_redirect_terminates() {
    let (addr, hits) = spawn_hostile("self_redirect").await;
    let db = TempDb::new("self-redirect");
    let _ = crawl(config(format!("http://{addr}/loop"), db.path().clone())).await;
    assert!(
        hits.load(Ordering::Relaxed) <= 6,
        "a self-redirect must be seen as already visited"
    );
}

/// A 3xx whose `Location` is missing, empty, or not fetchable must not become a
/// graph node and must not crash the worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn broken_redirect_targets_never_enter_the_graph() {
    let (db, id, _) = run_against("broken_redirects", "broken-redir").await;
    let conn = Connection::open(db.path()).unwrap();
    let urls: Vec<String> = conn
        .prepare("SELECT url FROM pages")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for u in &urls {
        assert!(
            u.starts_with("http://") || u.starts_with("https://"),
            "a non-fetchable redirect target became a node: {u}"
        );
    }
    let _ = id;
}

/// A response declared as HTML that is actually binary must degrade to a lossy
/// parse, not abort the crawl.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_binary_body_declared_as_html_is_parsed_lossily() {
    let (db, id, stats) = run_against("binary_body", "binary").await;
    assert!(stats.fetched >= 1, "the page should still be recorded");
    let conn = Connection::open(db.path()).unwrap();
    let visits: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM page_visits WHERE crawl_id=?1 AND error IS NULL",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(visits >= 1);
    // Nothing about a binary body should produce invalid rows.
    let bad: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pages WHERE url IS NULL OR url = ''",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(bad, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unusual_statuses_and_content_types_are_recorded_faithfully() {
    let (db, id, _) = run_against("weird_status", "weird").await;
    let conn = Connection::open(db.path()).unwrap();
    let statuses: Vec<i64> = conn
        .prepare(
            "SELECT status_code FROM page_visits
              WHERE crawl_id=?1 AND status_code IS NOT NULL",
        )
        .unwrap()
        .query_map([id], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        statuses.iter().any(|s| *s == 418 || *s == 599 || *s == 204),
        "unusual statuses must be recorded as they were, got {statuses:?}"
    );
    for s in &statuses {
        assert!((100..=599).contains(s), "impossible status stored: {s}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_or_non_http_response_is_an_error_not_a_crash() {
    for (mode, tag) in [("empty_response", "empty"), ("garbage_protocol", "garbage")] {
        let (db, id, stats) = run_against(mode, tag).await;
        assert_eq!(stats.fetched, 0, "{mode} should yield no pages");
        assert!(
            !errors_for(&db, id).is_empty(),
            "{mode} should be recorded as an error"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_header_flood_does_not_take_the_worker_down() {
    let (db, id, _) = run_against("header_flood", "headers").await;
    let conn = Connection::open(db.path()).unwrap();
    // Either the client rejects the response or we store it; both are fine, and
    // neither may panic or hang. What must not happen is a half-written page.
    let orphans: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM response_headers h
              LEFT JOIN page_visits v ON v.id = h.visit_id WHERE v.id IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(orphans, 0, "header rows outlived their visit");
    let _ = id;
}

/// A server that dribbles bytes forever is the case a per-request timeout
/// exists for. Without one the worker holds its permit indefinitely.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_body_hits_the_request_timeout() {
    let started = std::time::Instant::now();
    let (db, id, stats) = run_against("slowloris_body", "slow").await;
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the timeout should have fired long before this"
    );
    assert_eq!(stats.fetched, 0);
    assert!(
        !errors_for(&db, id).is_empty(),
        "a timed-out fetch must be recorded"
    );
}

/// The end-to-end property: whatever the server does, the database is left
/// consistent and the run ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_hostile_mode_leaves_a_consistent_database() {
    for (mode, tag) in [
        ("lying_content_length", "c1"),
        ("truncated_body", "c2"),
        ("redirect_loop", "c3"),
        ("broken_redirects", "c4"),
        ("binary_body", "c5"),
        ("weird_status", "c6"),
        ("empty_response", "c7"),
        ("garbage_protocol", "c8"),
        ("header_flood", "c9"),
    ] {
        let (db, id, _) = run_against(mode, tag).await;
        let conn = Connection::open(db.path()).unwrap();

        // Foreign keys hold: no child row without its parent.
        for (child, parent_key) in [
            ("response_headers", "visit_id"),
            ("cookies", "visit_id"),
            ("url_params", "visit_id"),
            ("scripts", "visit_id"),
            ("forms", "visit_id"),
        ] {
            let orphans: i64 = conn
                .query_row(
                    &format!(
                        "SELECT COUNT(*) FROM {child} c
                          LEFT JOIN page_visits v ON v.id = c.{parent_key}
                         WHERE v.id IS NULL"
                    ),
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(orphans, 0, "{mode}: orphaned rows in {child}");
        }

        // Every visit belongs to this crawl and names a real page.
        let dangling: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM page_visits v
                  LEFT JOIN pages p ON p.id = v.page_id
                 WHERE v.crawl_id = ?1 AND p.id IS NULL",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(dangling, 0, "{mode}: visits pointing at no page");

        // A visit is either a success or a failure, never silently neither.
        let incoherent: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM page_visits
                  WHERE crawl_id = ?1 AND error IS NULL AND status_code IS NULL",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            incoherent, 0,
            "{mode}: a visit with neither a status nor an error"
        );
    }
}
