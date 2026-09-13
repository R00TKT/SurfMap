use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use tokio::sync::mpsc;
use url::Url;
use crate::config::CrawlConfig;
use crate::model::{CrawlEvent, CrawlStats, PageError, PageObservation};
use crate::scope::Scope;

const SCHEMA: &str = include_str!("schema.sql");
const BATCH_SIZE: usize = 32;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening database at {}", path.display()))?;


        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;

        conn.execute_batch(SCHEMA).context("applying schema")?;
        migrate(&conn).context("migrating schema")?;
        Ok(Store { conn })
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn schema_sql() -> &'static str {
        SCHEMA
    }

    pub fn begin_crawl(&self, cfg: &CrawlConfig, scope: &Scope) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO crawls (seed_url, scope_policy, scope_hosts, max_depth, max_pages,
                                 concurrency, rate_limit_per_sec, respect_robots, user_agent,
                                 started_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'running')",
            params![
                cfg.seed,
                scope.policy().to_string(),
                serde_json::to_string(scope.hosts())?,
                cfg.max_depth,
                cfg.max_pages as i64,
                cfg.concurrency as i64,
                cfg.rate_limit,
                cfg.respect_robots as i64,
                cfg.user_agent,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn finish_crawl(&self, crawl_id: i64, stats: CrawlStats, status: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE crawls
                SET finished_at = ?1, status = ?2,
                    pages_fetched = ?3, pages_skipped = ?4, errors = ?5
              WHERE id = ?6",
            params![
                Utc::now().to_rfc3339(),
                status,
                stats.fetched as i64,
                stats.skipped as i64,
                stats.errors as i64,
                crawl_id,
            ],
        )?;
        Ok(())
    }

    fn write_batch(&mut self, crawl_id: i64, batch: Vec<CrawlEvent>) -> Result<()> {
        let tx = self.conn.transaction()?;
        for event in batch {
            match event {
                CrawlEvent::Page(obs) => write_page(&tx, crawl_id, &obs)?,
                CrawlEvent::Failed(err) => write_failure(&tx, crawl_id, &err)?,
            }
        }
        tx.commit()?;
        Ok(())
    }
}


fn migrate(conn: &Connection) -> Result<()> {
    if !has_column(conn, "page_visits", "discovered_by")? {
        conn.execute(
            "ALTER TABLE page_visits
                 ADD COLUMN discovered_by TEXT NOT NULL DEFAULT 'crawl'",
            [],
        )?;
        tracing::info!("migrated: page_visits.discovered_by added");
    }
    Ok(())
}

fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn upsert_page(tx: &rusqlite::Transaction<'_>, url: &Url) -> Result<i64> {
   
    let mut stmt = tx.prepare_cached(
        "INSERT INTO pages (url, scheme, host, path, first_seen)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(url) DO UPDATE SET url = excluded.url
         RETURNING id",
    )?;
    let id = stmt.query_row(
        params![
            url.as_str(),
            url.scheme(),
            url.host_str().unwrap_or(""),
            url.path(),
            Utc::now().to_rfc3339(),
        ],
        |row| row.get(0),
    )?;
    Ok(id)
}

fn write_page(tx: &rusqlite::Transaction<'_>, crawl_id: i64, obs: &PageObservation) -> Result<()> {
    let page_id = upsert_page(tx, &obs.url)?;

    let visit_id: i64 = tx
        .prepare_cached(
            "INSERT INTO page_visits (crawl_id, page_id, depth, status_code, content_type,
                                      content_length, title, elapsed_ms, error, fetched_at,
                                      discovered_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?10)
             ON CONFLICT(crawl_id, page_id) DO UPDATE SET
                 status_code = excluded.status_code,
                 content_type = excluded.content_type,
                 title = excluded.title,
                 error = NULL
             RETURNING id",
        )?
        .query_row(
            params![
                crawl_id,
                page_id,
                obs.depth,
                obs.status,
                obs.content_type,
                obs.content_length.map(|v| v as i64),
                obs.title,
                obs.elapsed_ms as i64,
                Utc::now().to_rfc3339(),
                if obs.probed { "probe" } else { "crawl" },
            ],
            |row| row.get(0),
        )?;
    for table in [
        "response_headers",
        "cookies",
        "url_params",
        "scripts",
        "forms",
    ] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE visit_id = ?1"),
            params![visit_id],
        )?;
    }

    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO response_headers (visit_id, name, value) VALUES (?1, ?2, ?3)",
        )?;
        for h in &obs.headers {
            stmt.execute(params![visit_id, h.name, h.value])?;
        }
    }

    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO cookies (visit_id, name, domain, path, http_only, secure, same_site, has_expiry)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for c in &obs.cookies {
            stmt.execute(params![
                visit_id,
                c.name,
                c.domain,
                c.path,
                c.http_only as i64,
                c.secure as i64,
                c.same_site,
                c.has_expiry as i64,
            ])?;
        }
    }

    {
        let mut stmt = tx.prepare_cached(
            "INSERT OR IGNORE INTO url_params (visit_id, name, value_shape, source)
             VALUES (?1, ?2, ?3, ?4)",
        )?;
        for p in &obs.params {
            stmt.execute(params![visit_id, p.name, p.shape, p.source.as_str()])?;
        }
    }

    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO scripts (visit_id, src, is_inline, host, third_party, integrity,
                                  crossorigin, body_sha256, body_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )?;
        for s in &obs.scripts {
            stmt.execute(params![
                visit_id,
                s.src,
                s.is_inline() as i64,
                s.host,
                s.third_party as i64,
                s.integrity,
                s.crossorigin,
                s.body_sha256,
                s.body_bytes,
            ])?;
        }
    }

    for f in &obs.forms {
        let form_id: i64 = tx
            .prepare_cached(
                "INSERT INTO forms (visit_id, action_url, method, enctype, form_name, form_id,
                                    input_count, has_file_upload, has_password, cross_origin)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 RETURNING id",
            )?
            .query_row(
                params![
                    visit_id,
                    f.action,
                    f.method,
                    f.enctype,
                    f.name,
                    f.dom_id,
                    f.inputs.len() as i64,
                    f.has_file_upload() as i64,
                    f.has_password() as i64,
                    f.cross_origin as i64,
                ],
                |row| row.get(0),
            )?;

        let mut stmt = tx.prepare_cached(
            "INSERT INTO form_inputs (form_id, name, input_type, required, has_default_value, max_length)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for i in &f.inputs {
            stmt.execute(params![
                form_id,
                i.name,
                i.input_type,
                i.required as i64,
                i.has_default_value as i64,
                i.max_length,
            ])?;
        }
    }

    {
        let mut stmt = tx.prepare_cached(
            "INSERT OR IGNORE INTO edges (crawl_id, src_page_id, dst_page_id, link_type, in_scope)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for l in &obs.links {
            let dst = upsert_page(tx, &l.url)?;
            stmt.execute(params![
                crawl_id,
                page_id,
                dst,
                l.link_type.as_str(),
                l.in_scope as i64,
            ])?;
        }
    }

    Ok(())
}

fn write_failure(tx: &rusqlite::Transaction<'_>, crawl_id: i64, err: &PageError) -> Result<()> {
    let page_id = upsert_page(tx, &err.url)?;
    tx.prepare_cached(
        "INSERT INTO page_visits (crawl_id, page_id, depth, error, fetched_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(crawl_id, page_id) DO UPDATE SET error = excluded.error",
    )?
    .execute(params![
        crawl_id,
        page_id,
        err.depth,
        err.message,
        Utc::now().to_rfc3339(),
    ])?;
    Ok(())
}
pub fn spawn_writer(
    db_path: PathBuf,
    crawl_id: i64,
    mut rx: mpsc::Receiver<CrawlEvent>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::task::spawn_blocking(move || {
        let mut store = Store::open(&db_path)?;
        while let Some(first) = rx.blocking_recv() {
            let mut batch = Vec::with_capacity(BATCH_SIZE);
            batch.push(first);
            while batch.len() < BATCH_SIZE {
                match rx.try_recv() {
                    Ok(event) => batch.push(event),
                    Err(_) => break,
                }
            }
            let count = batch.len();
            store.write_batch(crawl_id, batch)?;
            tracing::debug!(count, "committed batch");
        }
        Ok(())
    })
}



pub fn resolve_crawl_id(conn: &Connection, requested: Option<i64>) -> Result<i64> {
    match requested {
        Some(id) => {
            let exists: Option<i64> = conn
                .query_row("SELECT id FROM crawls WHERE id = ?1", params![id], |r| {
                    r.get(0)
                })
                .optional()?;
            exists.ok_or_else(|| anyhow::anyhow!("no crawl with id {id}"))
        }
        None => conn
            .query_row("SELECT id FROM crawls ORDER BY id DESC LIMIT 1", [], |r| {
                r.get(0)
            })
            .optional()?
            .ok_or_else(|| {
                anyhow::anyhow!("no crawls recorded yet -- run `surfmap crawl <url>` first")
            }),
    }
}
