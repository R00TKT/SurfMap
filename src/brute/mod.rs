//! Path discovery: finding what nothing links to.
//!
//! A crawl can only reach pages the target advertises. This module is the other
//! half of the question -- it takes a wordlist and asks, path by path, whether
//! something is there. That makes it the one part of surfmap that sends
//! requests the target never offered, which is why it is a separate subcommand
//! behind its own confirmation rather than a flag on `crawl`.
//!
//! | file             | responsibility                                       |
//! |------------------|------------------------------------------------------|
//! | [`args`]         | the `surfmap brute` flags                            |
//! | [`wordlist`]     | loading and sanitising candidate paths                |
//! | [`discovery`]    | candidate generation, soft-404 calibration, matching  |
//!
//! The engine itself is not duplicated: [`crate::engine::Engine::with_discovery`]
//! switches the existing crawl loop into probing mode, so scope, robots.txt,
//! rate limiting, storage and extraction all apply unchanged. A wordlist is a
//! different source of URLs, not a different crawler.
//!
//! `wordlists/common.txt` is compiled in, so the feature works with no external
//! file; `--wordlist` replaces it.

pub mod args;
pub mod discovery;
pub mod wordlist;

pub use args::BruteArgs;
pub use discovery::{Baseline, DEFAULT_ACCEPT, Discovery, StatusFilter};
