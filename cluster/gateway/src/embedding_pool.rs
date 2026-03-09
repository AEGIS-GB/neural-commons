use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

pub struct EmbeddingNode {
    pub node_id:     String,
    pub address:     String,   // "http://10.0.0.1:8081"
    pub active_reqs: AtomicU32,
    pub healthy:     std::sync::atomic::AtomicBool,
}

pub struct EmbeddingPool {
    pub nodes: Vec<Arc<EmbeddingNode>>,
}

impl EmbeddingPool {
    /// Least-connections selection among healthy nodes.
    pub fn pick(&self) -> Option<Arc<EmbeddingNode>> {
        self.nodes.iter()
            .filter(|n| n.healthy.load(Ordering::Relaxed))
            .min_by_key(|n| n.active_reqs.load(Ordering::Relaxed))
            .cloned()
    }
}
