use url::Url;

#[derive(Debug, Clone)]
pub struct PageObservation {
    pub url: Url,
    pub depth: u32,
    pub status: u16,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub body_bytes: Option<u64>,
    pub title: Option<String>,
    pub elapsed_ms: u64,
    pub headers: Vec<HeaderRecord>,
    pub cookies: Vec<CookieRecord>,
    pub forms: Vec<FormRecord>,
    pub links: Vec<LinkRecord>,
    pub scripts: Vec<ScriptRecord>,
    pub params: Vec<ParamRecord>,
    pub probed: bool,
}

impl PageObservation {
    pub fn in_scope_links(&self) -> impl Iterator<Item = &LinkRecord> {
        self.links.iter().filter(|l| l.in_scope)
    }
}
#[derive(Debug, Clone)]
pub struct HeaderRecord {
    pub name: String,
    pub value: Option<String>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CookieRecord {
    pub name: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: Option<String>,
    pub has_expiry: bool,
}
#[derive(Debug, Clone)]
pub struct FormRecord {
    pub action: Option<String>,
    pub method: String,
    pub enctype: Option<String>,
    pub name: Option<String>,
    pub dom_id: Option<String>,
    pub cross_origin: bool,
    pub inputs: Vec<FormInput>,
}

impl FormRecord {
    pub fn has_file_upload(&self) -> bool {
        self.inputs.iter().any(|i| i.input_type == "file")
    }
    pub fn has_password(&self) -> bool {
        self.inputs.iter().any(|i| i.input_type == "password")
    }
}

#[derive(Debug, Clone)]
pub struct FormInput {
    pub name: Option<String>,
    pub input_type: String,
    pub required: bool,
    pub has_default_value: bool,
    pub max_length: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct LinkRecord {
    pub url: Url,
    pub link_type: LinkType,
    pub in_scope: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkType {
    Anchor,
    FormAction,
    ScriptSrc,
    Iframe,
    Redirect,
}

impl LinkType {
    pub fn as_str(self) -> &'static str {
        match self {
            LinkType::Anchor => "anchor",
            LinkType::FormAction => "form-action",
            LinkType::ScriptSrc => "script-src",
            LinkType::Iframe => "iframe",
            LinkType::Redirect => "redirect",
        }
    }

    pub fn is_crawlable(self) -> bool {
        matches!(
            self,
            LinkType::Anchor | LinkType::Iframe | LinkType::Redirect
        )
    }
}

#[derive(Debug, Clone)]
pub struct ScriptRecord {
    pub src: Option<String>,
    pub host: Option<String>,
    pub third_party: bool,
    pub integrity: Option<String>,
    pub crossorigin: Option<String>,
    pub body_sha256: Option<String>,
    pub body_bytes: Option<i64>,
}

impl ScriptRecord {
    pub fn is_inline(&self) -> bool {
        self.src.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ParamRecord {
    pub name: String,
    pub shape: String,
    pub source: ParamSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParamSource {
    SelfUrl,
    Link,
    Form,
}

impl ParamSource {
    pub fn as_str(self) -> &'static str {
        match self {
            ParamSource::SelfUrl => "self",
            ParamSource::Link => "link",
            ParamSource::Form => "form",
        }
    }
}



#[derive(Debug, Clone)]
pub struct PageError {
    pub url: Url,
    pub depth: u32,
    pub message: String,
}
#[derive(Debug)]
pub enum CrawlEvent {
    Page(Box<PageObservation>),
    Failed(PageError),
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CrawlStats {
    pub fetched: usize,
    pub skipped: usize,
    pub errors: usize,
}
