/*
Crawler attack-surface schema
Nothing in the schema stores secrets e.g. cookies, auth header, etc.
*/



PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS crawls (
    id                 INTEGER PRIMARY KEY,
    seed_url           TEXT    NOT NULL,
    scope_policy       TEXT    NOT NULL,
    scope_hosts        TEXT    NOT NULL,
    max_depth          INTEGER NOT NULL,
    max_pages          INTEGER,
    concurrency        INTEGER NOT NULL,
    rate_limit_per_sec REAL    NOT NULL,
    respect_robots     INTEGER NOT NULL,
    user_agent         TEXT    NOT NULL,
    started_at         TEXT    NOT NULL,
    finished_at        TEXT,
    status             TEXT    NOT NULL DEFAULT 'running', -- 'running' | 'complete' | 'interrupted' | 'failed'
    pages_fetched      INTEGER NOT NULL DEFAULT 0,
    pages_skipped      INTEGER NOT NULL DEFAULT 0,
    errors             INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS pages (
    id         INTEGER PRIMARY KEY,
    url        TEXT NOT NULL UNIQUE,
    scheme     TEXT NOT NULL,
    host       TEXT NOT NULL,
    path       TEXT NOT NULL,
    first_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pages_host ON pages(host);

CREATE TABLE IF NOT EXISTS page_visits (
    id             INTEGER PRIMARY KEY,
    crawl_id       INTEGER NOT NULL REFERENCES crawls(id) ON DELETE CASCADE,
    page_id        INTEGER NOT NULL REFERENCES pages(id)  ON DELETE CASCADE,
    depth          INTEGER NOT NULL,
    status_code    INTEGER,
    content_type   TEXT,
    content_length INTEGER,
    title          TEXT,
    elapsed_ms     INTEGER,
    error          TEXT,
    fetched_at     TEXT NOT NULL,
    discovered_by  TEXT NOT NULL DEFAULT 'crawl', -- 'crawl' | 'probe'
    UNIQUE(crawl_id, page_id)
);
CREATE INDEX IF NOT EXISTS idx_visits_crawl ON page_visits(crawl_id);
CREATE INDEX IF NOT EXISTS idx_visits_found ON page_visits(crawl_id, discovered_by);

CREATE TABLE IF NOT EXISTS edges (
    id          INTEGER PRIMARY KEY,
    crawl_id    INTEGER NOT NULL REFERENCES crawls(id) ON DELETE CASCADE,
    src_page_id INTEGER NOT NULL REFERENCES pages(id)  ON DELETE CASCADE,
    dst_page_id INTEGER NOT NULL REFERENCES pages(id)  ON DELETE CASCADE,
    link_type   TEXT    NOT NULL, -- 'anchor' | 'form-action' | 'script-src' | 'iframe' | 'redirect'
    in_scope    INTEGER NOT NULL,
    UNIQUE(crawl_id, src_page_id, dst_page_id, link_type)
);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(crawl_id, src_page_id);

CREATE TABLE IF NOT EXISTS forms (
    id              INTEGER PRIMARY KEY,
    visit_id        INTEGER NOT NULL REFERENCES page_visits(id) ON DELETE CASCADE,
    action_url      TEXT,
    method          TEXT    NOT NULL,
    enctype         TEXT,
    form_name       TEXT,
    form_id         TEXT,
    input_count     INTEGER NOT NULL DEFAULT 0,
    has_file_upload INTEGER NOT NULL DEFAULT 0,
    has_password    INTEGER NOT NULL DEFAULT 0,
    cross_origin    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_forms_visit ON forms(visit_id);

CREATE TABLE IF NOT EXISTS form_inputs (
    id                INTEGER PRIMARY KEY,
    form_id           INTEGER NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
    name              TEXT,
    input_type        TEXT    NOT NULL,
    required          INTEGER NOT NULL DEFAULT 0,
    has_default_value INTEGER NOT NULL DEFAULT 0,
    max_length        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_inputs_form ON form_inputs(form_id);

CREATE TABLE IF NOT EXISTS url_params (
    id          INTEGER PRIMARY KEY,
    visit_id    INTEGER NOT NULL REFERENCES page_visits(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,
    value_shape TEXT    NOT NULL,
    source      TEXT    NOT NULL, -- 'self' | 'link' | 'form'
    UNIQUE(visit_id, name, value_shape, source)
);
CREATE INDEX IF NOT EXISTS idx_params_name ON url_params(name);

CREATE TABLE IF NOT EXISTS response_headers (
    id       INTEGER PRIMARY KEY,
    visit_id INTEGER NOT NULL REFERENCES page_visits(id) ON DELETE CASCADE,
    name     TEXT    NOT NULL,
    value    TEXT
);
CREATE INDEX IF NOT EXISTS idx_headers_visit_name ON response_headers(visit_id, name);

CREATE TABLE IF NOT EXISTS cookies (
    id         INTEGER PRIMARY KEY,
    visit_id   INTEGER NOT NULL REFERENCES page_visits(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    domain     TEXT,
    path       TEXT,
    http_only  INTEGER NOT NULL DEFAULT 0,
    secure     INTEGER NOT NULL DEFAULT 0,
    same_site  TEXT,
    has_expiry INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scripts (
    id          INTEGER PRIMARY KEY,
    visit_id    INTEGER NOT NULL REFERENCES page_visits(id) ON DELETE CASCADE,
    src         TEXT,
    is_inline   INTEGER NOT NULL,
    host        TEXT,
    third_party INTEGER NOT NULL DEFAULT 0,
    integrity   TEXT,
    crossorigin TEXT,
    body_sha256 TEXT,
    body_bytes  INTEGER
);

DROP VIEW IF EXISTS missing_security_headers;
CREATE VIEW missing_security_headers AS
WITH expected(header) AS (
    VALUES ('content-security-policy'),
           ('strict-transport-security'),
           ('x-frame-options'),
           ('x-content-type-options'),
           ('referrer-policy'),
           ('permissions-policy')
)
SELECT v.crawl_id      AS crawl_id,
       p.url           AS url,
       e.header        AS missing_header,
       v.status_code   AS status_code
FROM page_visits v
JOIN pages p ON p.id = v.page_id
CROSS JOIN expected e
LEFT JOIN response_headers h ON h.visit_id = v.id AND h.name = e.header
WHERE h.id IS NULL
  AND v.error IS NULL
  AND COALESCE(v.content_type, '') LIKE 'text/html%';

DROP VIEW IF EXISTS attack_surface_forms;
CREATE VIEW attack_surface_forms AS
SELECT v.crawl_id        AS crawl_id,
       p.url             AS page_url,
       f.id              AS form_id,
       UPPER(f.method)   AS method,
       f.action_url      AS action_url,
       f.enctype         AS enctype,
       f.input_count     AS input_count,
       f.has_file_upload AS has_file_upload,
       f.has_password    AS has_password,
       f.cross_origin    AS cross_origin,
       (SELECT GROUP_CONCAT(COALESCE(fi.name, '(unnamed)') || ':' || fi.input_type, ', ')
          FROM form_inputs fi WHERE fi.form_id = f.id) AS inputs
FROM forms f
JOIN page_visits v ON v.id = f.visit_id
JOIN pages p       ON p.id = v.page_id;

DROP VIEW IF EXISTS insecure_cookies;
CREATE VIEW insecure_cookies AS
SELECT v.crawl_id AS crawl_id,
       p.url      AS url,
       c.name     AS cookie_name,
       c.http_only, c.secure, COALESCE(c.same_site, '(unset)') AS same_site
FROM cookies c
JOIN page_visits v ON v.id = c.visit_id
JOIN pages p       ON p.id = v.page_id
WHERE c.http_only = 0 OR c.secure = 0 OR c.same_site IS NULL;


