#[derive(Debug, thiserror::Error)]
pub enum CrawlError {
    #[error("request failed: {0}")]
    Http(String),
    #[error("request timed out")]
    Timeout,
    #[error("disallowed by robots.txt")]
    RobotsDisallowed,
    #[error("out of scope")]
    OutOfScope,
    #[error("skipped content type `{0}`")]
    UnsupportedContentType(String),
    #[error("response body exceeded {0} bytes")]
    BodyTooLarge(usize),
    #[error("invalid url: {0}")]
    InvalidUrl(#[from] url::ParseError),
}
impl From<reqwest::Error> for CrawlError {
    fn from(e: reqwest::Error) -> Self {
        if e.is_timeout() {
            CrawlError::Timeout
        } else if e.is_connect() {
            CrawlError::Http(format!("connection failed: {e}"))
        } else {
            CrawlError::Http(e.to_string())
        }
    }
}
