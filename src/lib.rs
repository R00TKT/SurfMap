//! surfmap -- a web crawler and attack-surface mapper for authorized assessments.
//!
//! The crate is split along the four boundaries the design calls for:
//!
//! | module                  | responsibility                                        |
//! |-------------------------|-------------------------------------------------------|
//! | [`engine`]              | frontier, bounded-concurrency fetch loop, termination  |
//! | [`extract`]             | untrusted HTML/HTTP -> owned, structured surface data  |
//! | [`storage`]             | normalized SQLite persistence, per-run history         |
//! | [`report`]              | findings queries over that schema                      |
//! | [`brute`]               | wordlist path probing, with soft-404 calibration       |
//!
//! [`scope`], [`robots`] and [`politeness`] sit across all of them: they are the
//! safety controls, and they are enforced in one place each rather than sprinkled
//! through call sites.

pub mod brute;
pub mod cli;
pub mod config;
pub mod engine;
pub mod error;
pub mod extract;
pub mod model;
pub mod politeness;
pub mod report;
pub mod robots;
pub mod scope;
pub mod storage;
