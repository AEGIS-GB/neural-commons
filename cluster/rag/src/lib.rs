//! aegis-rag: Remote RAG service
//!
//! Privacy model (two data classes):
//! - Private RAG: adapter computes embeddings locally, encrypts chunks client-side,
//!   sends {plaintext_vector, encrypted_chunk}. Cluster searches vectors, returns
//!   encrypted chunks. Cluster never sees RAG content.
//! - Botawiki claims: intentionally public, cluster-side embedding.

pub mod search;
pub mod storage;
