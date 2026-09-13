//! A deliberately awkward test site: malformed markup, a redirect, a
//! robots-disallowed path, a third-party link, a crawler trap, and canary
//! strings that must never reach the database.
//!
//! It also serves the material path discovery is tested against: files and a
//! directory that nothing links to, and a `/soft/` subtree that answers unknown
//! paths with `200 OK` and a page echoing the path back.

// Included by more than one integration test, and each uses a different part
// of it; unused-in-this-crate is expected rather than a finding.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Values the crawler sees but must not persist.
pub const CANARY_COOKIE: &str = "CANARYCOOKIEVALUE";
pub const CANARY_CSRF: &str = "CANARYCSRFTOKEN";
pub const CANARY_BODY: &str = "CANARYBODYTEXT";
pub const CANARY_PARAM: &str = "CANARYQUERYVALUE";

#[derive(Clone, Default)]
pub struct Requests(Arc<Mutex<Vec<String>>>);

impl Requests {
    pub fn all(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
    pub fn hit(&self, path: &str) -> bool {
        self.0.lock().unwrap().iter().any(|p| p == path)
    }
    pub fn count_prefix(&self, prefix: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.starts_with(prefix))
            .count()
    }
}

pub async fn spawn_site() -> (SocketAddr, Requests) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let log = Requests::default();

    let accept_log = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let log = accept_log.clone();
            tokio::spawn(async move {
                let _ = serve(stream, log, addr).await;
            });
        }
    });

    (addr, log)
}

async fn serve(mut stream: TcpStream, log: Requests, addr: SocketAddr) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let head = String::from_utf8_lossy(&buf);
    let target = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
    log.0.lock().unwrap().push(target.clone());

    let response = route(&target, addr);
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

fn ok(body: &str, extra: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
        body.len()
    )
}

fn route(target: &str, addr: SocketAddr) -> String {
    let base = format!("http://{addr}");
    let path = target.split('?').next().unwrap_or("/");

    match path {
        "/robots.txt" => {
            let body =
                "User-agent: *\nDisallow: /admin\nAllow: /admin/public\nSitemap: /sitemap.xml\n";
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        }

        "/" => {
            let mut links = String::new();
            for month in 1..=12 {
                links.push_str(&format!(
                    r#"<a href="/calendar?month={month}&view=grid">m{month}</a>"#
                ));
            }
            let body = format!(
                r##"<html><head><title>Test Home</title>
                   <script src="https://cdn.third-party.test/lib.js"></script>
                   <script>var x=1;</script></head>
                   <body><p>{CANARY_BODY}</p>
                   <a href="/about">About</a>
                   <a href="/login">Login</a>
                   <a href="/upload">Upload</a>
                   <a href="/old">Old</a>
                   <a href="/broken">Broken</a>
                   <a href="/api/data">Api</a>
                   <a href="/admin/secret">Admin</a>
                   <a href="/search?q={CANARY_PARAM}&page=2">Search</a>
                   <a href="https://external.test/elsewhere">External</a>
                   <a href="#anchor">Anchor</a>
                   <a href="javascript:void(0)">JS</a>
                   {links}
                   </body></html>"##
            );
            ok(&body, "")
        }

        "/about" => ok(
            "<html><head><title>About</title></head><body><a href=\"/\">home</a></body></html>",
            "Content-Security-Policy: default-src 'self'\r\nX-Frame-Options: DENY\r\n",
        ),

        "/login" => {
            let body = format!(
                r#"<html><head><title>Login</title></head><body>
                   <form action="/session" method="post">
                     <input name="username" type="text" required maxlength="64">
                     <input name="password" type="password" required>
                     <input name="csrf" type="hidden" value="{CANARY_CSRF}">
                     <button name="go" type="submit">Sign in</button>
                   </form></body></html>"#
            );
            ok(
                &body,
                &format!("Set-Cookie: sid={CANARY_COOKIE}; Path=/\r\n"),
            )
        }

        "/upload" => ok(
            r#"<html><head><title>Upload</title></head><body>
               <form action="/files" method="POST" enctype="multipart/form-data">
                 <input name="doc" type="file" required>
               </form></body></html>"#,
            "",
        ),

        "/session" | "/files" => ok("<html><title>Posted</title></html>", ""),

        "/old" => format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {base}/new\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),

        "/new" => ok(
            "<html><head><title>New</title></head><body>moved</body></html>",
            "",
        ),

        // Unquoted attributes, unclosed tags, a stray nested form: html5ever's
        // error recovery is expected to produce a usable tree anyway.
        "/broken" => ok(
            "<html><head><title>Broken</title><body><a href=/recovered>link<form><input name=q><p><b>bold",
            "",
        ),

        "/recovered" => ok("<html><title>Recovered</title></html>", ""),

        // --- Unlinked: reachable only by guessing the path. ---------------
        "/hidden-backup.sql" => {
            let body = "-- dump\nCREATE TABLE t (id int);\n".repeat(6);
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        }
        "/secret-config" => {
            let body = "<html><title>Forbidden</title></html>";
            format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        }
        // A directory, announced the way servers announce one.
        "/tools" => format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {base}/tools/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
        "/tools/" => ok("<html><title>Tools</title></html>", ""),
        "/tools/debug" => ok("<html><title>Debug</title></html>", ""),

        // --- The soft-404 subtree. ----------------------------------------
        "/soft/" => ok("<html><title>Soft root</title></html>", ""),
        "/soft/real.txt" => {
            let body = "genuine file contents\n".repeat(4);
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        }
        p if p.starts_with("/soft/") => {
            // 200 OK for anything, with the path echoed so successive misses
            // differ in length. A prober that trusts status codes reports every
            // word in its list as a hit here.
            let body = format!(
                "<html><head><title>Not found</title></head><body>Nothing at {p} here.</body></html>"
            );
            ok(&body, "")
        }

        "/api/data" => {
            let body = r#"{"ok":true}"#;
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        }

        "/search" => ok(
            "<html><head><title>Search</title></head><body>results</body></html>",
            "",
        ),

        "/calendar" => ok(
            "<html><head><title>Calendar</title></head><body>cal</body></html>",
            "",
        ),

        p if p.starts_with("/admin") => ok("<html><title>ADMIN</title></html>", ""),

        _ => {
            let body = "<html><title>Not Found</title></html>";
            format!(
                "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        }
    }
}
