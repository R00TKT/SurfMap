use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use dashmap::{DashMap, DashSet};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use url::Url;
use crate::scope::signature;

#[derive(Debug, Clone)]
pub struct Task {
    pub url: Url,
    pub depth: u32,
    pub probe: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    Accepted,
    Duplicate,
    TooDeep,
    PageBudgetExhausted,
    VariantCapped,
}
pub struct Frontier {
    tx: mpsc::UnboundedSender<Task>,
    visited: DashSet<String>,
    variants: DashMap<String, usize>,
    in_flight: AtomicUsize,
    accepted: AtomicUsize,
    rejected: AtomicUsize,
    finished: CancellationToken,
    max_depth: u32,
    max_pages: usize,
    max_variants: usize,
}
impl Frontier {
    pub fn new(
        max_depth: u32,
        max_pages: usize,
        max_variants: usize,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<Task>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let frontier = Arc::new(Frontier {
            tx,
            visited: DashSet::new(),
            variants: DashMap::new(),
            in_flight: AtomicUsize::new(0),
            accepted: AtomicUsize::new(0),
            rejected: AtomicUsize::new(0),
            finished: CancellationToken::new(),
            max_depth,
            max_pages,
            max_variants,
        });
        (frontier, rx)
    }
    /// following a link
    pub fn offer(&self, url: Url, depth: u32) -> Offer {
        self.offer_task(url, depth, false)
    }
    /// wordlist.
    pub fn offer_probe(&self, url: Url, depth: u32) -> Offer {
        self.offer_task(url, depth, true)
    }
    fn offer_task(&self, url: Url, depth: u32, probe: bool) -> Offer {
        if depth > self.max_depth {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return Offer::TooDeep;
        }
        if !self.visited.insert(url.as_str().to_string()) {
            return Offer::Duplicate;
        }

        {
            let mut slot = self.variants.entry(signature(&url)).or_insert(0);
            if *slot >= self.max_variants {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                return Offer::VariantCapped;
            }
            *slot += 1;
        }
        if self
            .accepted
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < self.max_pages).then_some(n + 1)
            })
            .is_err()
        {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return Offer::PageBudgetExhausted;
        }
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        if self.tx.send(Task { url, depth, probe }).is_err() {
            self.complete();
            return Offer::PageBudgetExhausted;
        }
        Offer::Accepted
    }
    pub fn complete(&self) {
        if self.in_flight.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.finished.cancel();
        }
    }
    pub fn finished(&self) -> CancellationToken {
        self.finished.clone()
    }
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::Relaxed)
    }
    pub fn rejected(&self) -> usize {
        self.rejected.load(Ordering::Relaxed)
    }
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }
}
pub struct InFlightGuard(Arc<Frontier>);

impl InFlightGuard {
    pub fn new(frontier: Arc<Frontier>) -> Self {
        InFlightGuard(frontier)
    }
}
impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.complete();
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }
    #[tokio::test]
    async fn duplicates_are_claimed_exactly_once() {
        let (f, _rx) = Frontier::new(5, 100, 10);
        assert_eq!(f.offer(u("https://e.com/a"), 0), Offer::Accepted);
        assert_eq!(f.offer(u("https://e.com/a"), 1), Offer::Duplicate);
        assert_eq!(f.accepted(), 1);
    }
    #[tokio::test]
    async fn depth_and_page_budget_are_enforced() {
        let (f, _rx) = Frontier::new(1, 2, 10);
        assert_eq!(f.offer(u("https://e.com/a"), 2), Offer::TooDeep);
        assert_eq!(f.offer(u("https://e.com/b"), 1), Offer::Accepted);
        assert_eq!(f.offer(u("https://e.com/c"), 0), Offer::Accepted);
        assert_eq!(f.offer(u("https://e.com/d"), 0), Offer::PageBudgetExhausted);
    }
    #[tokio::test]
    async fn crawl_finishes_only_when_the_last_worker_completes() {
        let (f, _rx) = Frontier::new(5, 100, 10);
        let done = f.finished();
        f.offer(u("https://e.com/a"), 0);
        f.offer(u("https://e.com/b"), 0);
        assert!(!done.is_cancelled());
        f.complete();
        assert!(!done.is_cancelled(), "one worker still in flight");
        f.offer(u("https://e.com/c"), 1);
        f.complete();
        assert!(!done.is_cancelled());
        f.complete();
        assert!(done.is_cancelled(), "queue drained and nothing in flight");
    }
}