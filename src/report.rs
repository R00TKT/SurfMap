//! Findings reports.
//!
//! Every report here is a SQL query and nothing else. That is the payoff of a
//! normalized schema: "which POST forms take a file upload" is a `WHERE` clause,
//! not a parsing pass, and an operator can write their own query the tool's
//! author never thought of.

use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, Row, params};

const MAX_CELL: usize = 78;
/// Rows listed per `diff` section before the rest are summarized as a count.
const DIFF_ROWS: usize = 25;

#[derive(Debug, Default)]
pub struct Table {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

impl Table {
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.rows
                .iter()
                .map(|row| {
                    serde_json::Value::Object(
                        self.columns
                            .iter()
                            .cloned()
                            .zip(row.iter().map(|c| serde_json::Value::String(c.clone())))
                            .collect(),
                    )
                })
                .collect(),
        )
    }

    pub fn render(&self) -> String {
        if self.rows.is_empty() {
            return "  (no rows)\n".to_string();
        }
        let mut widths: Vec<usize> = self.columns.iter().map(|c| c.chars().count()).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if i < widths.len() {
                    widths[i] = widths[i].max(cell.chars().count().min(MAX_CELL));
                }
            }
        }

        let mut out = String::new();
        let header: Vec<String> = self
            .columns
            .iter()
            .enumerate()
            .map(|(i, c)| pad(c, widths[i]))
            .collect();
        out.push_str(&format!("  {}\n", header.join("  ").trim_end()));
        out.push_str(&format!(
            "  {}\n",
            widths
                .iter()
                .map(|w| "-".repeat(*w))
                .collect::<Vec<_>>()
                .join("  ")
        ));
        for row in &self.rows {
            let cells: Vec<String> = row
                .iter()
                .enumerate()
                .map(|(i, c)| pad(&truncate(c), widths.get(i).copied().unwrap_or(0)))
                .collect();
            out.push_str(&format!("  {}\n", cells.join("  ").trim_end()));
        }
        out
    }
}

fn pad(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - len))
    }
}

fn truncate(s: &str) -> String {
    if s.chars().count() <= MAX_CELL {
        return s.to_string();
    }
    let head: String = s.chars().take(MAX_CELL - 1).collect();
    format!("{head}\u{2026}")
}

fn cell(row: &Row<'_>, idx: usize) -> String {
    match row.get_ref(idx) {
        Ok(ValueRef::Null) => String::new(),
        Ok(ValueRef::Integer(i)) => i.to_string(),
        Ok(ValueRef::Real(f)) => format!("{f}"),
        Ok(ValueRef::Text(t)) => String::from_utf8_lossy(t).into_owned(),
        Ok(ValueRef::Blob(b)) => format!("<{} bytes>", b.len()),
        Err(_) => String::new(),
    }
}

pub fn query(conn: &Connection, sql: &str, args: &[&dyn rusqlite::ToSql]) -> Result<Table> {
    let mut stmt = conn.prepare(sql).context("preparing query")?;
    let columns: Vec<String> = stmt.column_names().into_iter().map(String::from).collect();
    let width = columns.len();
    let rows = stmt
        .query_map(args, |row| {
            Ok((0..width).map(|i| cell(row, i)).collect::<Vec<String>>())
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Table { columns, rows })
}

/// A second connection opened with SQLITE_OPEN_READ_ONLY, so ad-hoc operator SQL
/// is prevented from writing by the database engine rather than by inspecting
/// the query text -- which is a filter, and filters get bypassed.
pub fn open_readonly(path: &Path) -> Result<Connection> {
    // Checked here rather than at each call site: a read-only open of a missing
    // file fails with SQLite error 14, which tells an operator who mistyped
    // `--db` nothing useful. Every reader goes through this function.
    if !path.exists() {
        anyhow::bail!(
            "no database at {} -- run `surfmap crawl <url>` first",
            path.display()
        );
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .with_context(|| format!("opening {} read-only", path.display()))?;
    Ok(conn)
}

pub fn crawls(conn: &Connection) -> Result<Table> {
    query(
        conn,
        "SELECT id, seed_url, scope_policy, status, started_at,
                pages_fetched AS fetched, pages_skipped AS skipped, errors
           FROM crawls ORDER BY id DESC",
        &[],
    )
}

pub fn pages(conn: &Connection, crawl_id: i64, limit: i64) -> Result<Table> {
    query(
        conn,
        "SELECT v.status_code AS status, v.depth, p.url, v.content_type, v.title
           FROM page_visits v JOIN pages p ON p.id = v.page_id
          WHERE v.crawl_id = ?1 AND v.error IS NULL
          ORDER BY v.depth, p.url LIMIT ?2",
        &[&crawl_id, &limit],
    )
}

pub fn missing_headers(conn: &Connection, crawl_id: i64, limit: i64) -> Result<Table> {
    query(
        conn,
        "SELECT missing_header, COUNT(*) AS pages_affected,
                MIN(url) AS example_page
           FROM missing_security_headers
          WHERE crawl_id = ?1
          GROUP BY missing_header
          ORDER BY pages_affected DESC LIMIT ?2",
        &[&crawl_id, &limit],
    )
}

pub fn forms(conn: &Connection, crawl_id: i64, limit: i64) -> Result<Table> {
    query(
        conn,
        "SELECT method, action_url, page_url, input_count AS inputs,
                CASE WHEN has_password THEN 'yes' ELSE '' END AS password,
                CASE WHEN has_file_upload THEN 'yes' ELSE '' END AS upload,
                CASE WHEN cross_origin THEN 'yes' ELSE '' END AS cross_origin,
                inputs AS fields
           FROM attack_surface_forms
          WHERE crawl_id = ?1
          ORDER BY has_file_upload DESC, has_password DESC, method DESC LIMIT ?2",
        &[&crawl_id, &limit],
    )
}

pub fn params(conn: &Connection, crawl_id: i64, limit: i64) -> Result<Table> {
    query(
        conn,
        "SELECT up.name,
                GROUP_CONCAT(DISTINCT up.value_shape) AS shapes,
                COUNT(DISTINCT v.page_id) AS pages,
                MIN(p.url) AS example_page
           FROM url_params up
           JOIN page_visits v ON v.id = up.visit_id
           JOIN pages p       ON p.id = v.page_id
          WHERE v.crawl_id = ?1
          GROUP BY up.name
          ORDER BY pages DESC, up.name LIMIT ?2",
        &[&crawl_id, &limit],
    )
}

pub fn cookies(conn: &Connection, crawl_id: i64, limit: i64) -> Result<Table> {
    query(
        conn,
        "SELECT cookie_name,
                CASE WHEN http_only THEN '' ELSE 'missing' END AS httponly,
                CASE WHEN secure    THEN '' ELSE 'missing' END AS secure,
                same_site,
                COUNT(*) AS seen_on_pages,
                MIN(url) AS example_page
           FROM insecure_cookies
          WHERE crawl_id = ?1
          GROUP BY cookie_name, httponly, secure, same_site
          ORDER BY seen_on_pages DESC LIMIT ?2",
        &[&crawl_id, &limit],
    )
}

pub fn scripts(conn: &Connection, crawl_id: i64, limit: i64) -> Result<Table> {
    query(
        conn,
        "SELECT COALESCE(s.host, '(inline)') AS host,
                COUNT(*) AS refs,
                SUM(CASE WHEN s.integrity IS NULL AND s.third_party THEN 1 ELSE 0 END) AS third_party_no_sri,
                MIN(COALESCE(s.src, 'inline script')) AS example
           FROM scripts s
           JOIN page_visits v ON v.id = s.visit_id
          WHERE v.crawl_id = ?1
          GROUP BY host
          ORDER BY refs DESC LIMIT ?2",
        &[&crawl_id, &limit],
    )
}

pub fn errors(conn: &Connection, crawl_id: i64, limit: i64) -> Result<Table> {
    query(
        conn,
        "SELECT p.url, v.depth, v.error
           FROM page_visits v JOIN pages p ON p.id = v.page_id
          WHERE v.crawl_id = ?1 AND v.error IS NOT NULL
          ORDER BY p.url LIMIT ?2",
        &[&crawl_id, &limit],
    )
}

/// What wordlist probing turned up, as opposed to what a crawl followed.
///
/// Ordered by status so the 200s lead and the 401/403s -- "this exists and you
/// may not have it" -- sit together below them.
pub fn discovered(conn: &Connection, crawl_id: i64, limit: i64) -> Result<Table> {
    query(
        conn,
        "SELECT v.status_code AS status, p.url, v.content_type,
                v.content_length AS bytes, v.title
           FROM page_visits v JOIN pages p ON p.id = v.page_id
          WHERE v.crawl_id = ?1 AND v.error IS NULL AND v.discovered_by = 'probe'
          ORDER BY v.status_code, p.url LIMIT ?2",
        &[&crawl_id, &limit],
    )
}

pub fn graph(conn: &Connection, crawl_id: i64, limit: i64) -> Result<Table> {
    query(
        conn,
        "SELECT src.url AS source, e.link_type, dst.url AS target,
                CASE WHEN e.in_scope THEN '' ELSE 'external' END AS scope
           FROM edges e
           JOIN pages src ON src.id = e.src_page_id
           JOIN pages dst ON dst.id = e.dst_page_id
          WHERE e.crawl_id = ?1
          ORDER BY source, target LIMIT ?2",
        &[&crawl_id, &limit],
    )
}

/// Graphviz output: `surfmap report dot | dot -Tsvg` renders the link graph.
pub fn graph_dot(conn: &Connection, crawl_id: i64, limit: i64) -> Result<String> {
    let table = graph(conn, crawl_id, limit)?;
    let mut out =
        String::from("digraph surfmap {\n  rankdir=LR;\n  node [shape=box, fontsize=9];\n");
    for row in &table.rows {
        let (src, kind, dst, scope) = (&row[0], &row[1], &row[2], &row[3]);
        let style = if scope == "external" {
            ", style=dashed, color=gray"
        } else {
            ""
        };
        out.push_str(&format!(
            "  {} -> {} [label=\"{}\"{}];\n",
            quote(src),
            quote(dst),
            kind,
            style
        ));
    }
    out.push_str("}\n");
    Ok(out)
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// One-number-per-line overview of a crawl.
pub fn summary(conn: &Connection, crawl_id: i64) -> Result<String> {
    let meta = query(
        conn,
        "SELECT seed_url, scope_policy, scope_hosts, max_depth, concurrency,
                rate_limit_per_sec, respect_robots, status, started_at, finished_at,
                pages_fetched, pages_skipped, errors
           FROM crawls WHERE id = ?1",
        &[&crawl_id],
    )?;
    let Some(row) = meta.rows.first() else {
        anyhow::bail!("no crawl with id {crawl_id}");
    };

    let count =
        |sql: &str| -> Result<i64> { Ok(conn.query_row(sql, params![crawl_id], |r| r.get(0))?) };

    let pages = count("SELECT COUNT(*) FROM page_visits WHERE crawl_id=?1 AND error IS NULL")?;
    let probed = count(
        "SELECT COUNT(*) FROM page_visits
          WHERE crawl_id=?1 AND error IS NULL AND discovered_by='probe'",
    )?;
    let failed = count("SELECT COUNT(*) FROM page_visits WHERE crawl_id=?1 AND error IS NOT NULL")?;
    let edges = count("SELECT COUNT(*) FROM edges WHERE crawl_id=?1")?;
    let external = count("SELECT COUNT(*) FROM edges WHERE crawl_id=?1 AND in_scope=0")?;
    let forms = count(
        "SELECT COUNT(*) FROM forms f JOIN page_visits v ON v.id=f.visit_id WHERE v.crawl_id=?1",
    )?;
    let post_forms = count(
        "SELECT COUNT(*) FROM forms f JOIN page_visits v ON v.id=f.visit_id
          WHERE v.crawl_id=?1 AND UPPER(f.method)='POST'",
    )?;
    let upload_forms = count(
        "SELECT COUNT(*) FROM forms f JOIN page_visits v ON v.id=f.visit_id
          WHERE v.crawl_id=?1 AND f.has_file_upload=1",
    )?;
    let param_names = count(
        "SELECT COUNT(DISTINCT up.name) FROM url_params up
           JOIN page_visits v ON v.id=up.visit_id WHERE v.crawl_id=?1",
    )?;
    let cookie_issues = count("SELECT COUNT(*) FROM insecure_cookies WHERE crawl_id=?1")?;
    let header_gaps = count("SELECT COUNT(*) FROM missing_security_headers WHERE crawl_id=?1")?;
    let third_party = count(
        "SELECT COUNT(DISTINCT s.host) FROM scripts s
           JOIN page_visits v ON v.id=s.visit_id
          WHERE v.crawl_id=?1 AND s.third_party=1",
    )?;

    let f = |i: usize| row.get(i).cloned().unwrap_or_default();
    let mut out = String::new();
    out.push_str(&format!("Crawl #{crawl_id}\n"));
    out.push_str(&format!("  seed            {}\n", f(0)));
    out.push_str(&format!("  scope           {} {}\n", f(1), f(2)));
    out.push_str(&format!(
        "  settings        depth={} concurrency={} rate={}/s robots={}\n",
        f(3),
        f(4),
        f(5),
        if f(6) == "1" { "respected" } else { "IGNORED" }
    ));
    out.push_str(&format!("  status          {} (started {})\n", f(7), f(8)));
    if !f(9).is_empty() {
        out.push_str(&format!("  finished        {}\n", f(9)));
    }
    out.push_str("\nAttack surface\n");
    out.push_str(&format!("  pages crawled   {pages}\n"));
    if probed > 0 {
        out.push_str(&format!("  found by probe  {probed}\n"));
    }
    out.push_str(&format!("  failed/skipped  {failed}\n"));
    out.push_str(&format!(
        "  links (edges)   {edges}  ({external} leaving scope)\n"
    ));
    out.push_str(&format!(
        "  forms           {forms}  ({post_forms} POST, {upload_forms} with file upload)\n"
    ));
    out.push_str(&format!("  unique params   {param_names}\n"));
    out.push_str(&format!("  3rd-party JS    {third_party} distinct hosts\n"));
    out.push_str("\nFindings\n");
    out.push_str(&format!(
        "  header gaps     {header_gaps}  (page x missing-header pairs)\n"
    ));
    out.push_str(&format!("  cookie issues   {cookie_issues}\n"));
    out.push_str("\nNext: surfmap report forms | headers | params | cookies | scripts\n");
    Ok(out)
}

/// What changed in the attack surface between two runs.
pub fn diff(conn: &Connection, base: i64, target: i64) -> Result<String> {
    let mut out = String::new();
    out.push_str(&format!(
        "Attack surface diff: crawl #{base} -> crawl #{target}\n\n"
    ));

    // The sign is per-section, not a decoration: three of these sections list
    // surface that appeared and one lists surface that went away. Marking a
    // disappearance with `+` inverts the finding for whoever reads the report.
    let sections: [(&str, char, &str); 4] = [
        (
            "Pages appearing in the newer crawl",
            '+',
            "SELECT p.url FROM page_visits v JOIN pages p ON p.id=v.page_id
              WHERE v.crawl_id=?2 AND v.error IS NULL
             EXCEPT
             SELECT p.url FROM page_visits v JOIN pages p ON p.id=v.page_id
              WHERE v.crawl_id=?1 AND v.error IS NULL",
        ),
        (
            "Pages no longer reachable",
            '-',
            "SELECT p.url FROM page_visits v JOIN pages p ON p.id=v.page_id
              WHERE v.crawl_id=?1 AND v.error IS NULL
             EXCEPT
             SELECT p.url FROM page_visits v JOIN pages p ON p.id=v.page_id
              WHERE v.crawl_id=?2 AND v.error IS NULL",
        ),
        (
            "New input vectors (form action + method)",
            '+',
            "SELECT COALESCE(action_url,'(self)') || '  [' || method || ']'
               FROM attack_surface_forms WHERE crawl_id=?2
             EXCEPT
             SELECT COALESCE(action_url,'(self)') || '  [' || method || ']'
               FROM attack_surface_forms WHERE crawl_id=?1",
        ),
        (
            "New parameters",
            '+',
            "SELECT DISTINCT up.name || ' (' || up.value_shape || ')'
               FROM url_params up JOIN page_visits v ON v.id=up.visit_id WHERE v.crawl_id=?2
             EXCEPT
             SELECT DISTINCT up.name || ' (' || up.value_shape || ')'
               FROM url_params up JOIN page_visits v ON v.id=up.visit_id WHERE v.crawl_id=?1",
        ),
    ];

    for (heading, sign, sql) in sections {
        let table = query(conn, sql, &[&base, &target])?;
        out.push_str(&format!("{heading}: {}\n", table.rows.len()));
        for row in table.rows.iter().take(DIFF_ROWS) {
            out.push_str(&format!("    {sign} {}\n", row[0]));
        }
        if table.rows.len() > DIFF_ROWS {
            out.push_str(&format!(
                "    ... and {} more\n",
                table.rows.len() - DIFF_ROWS
            ));
        }
        out.push('\n');
    }
    Ok(out)
}
