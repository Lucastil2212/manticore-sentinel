use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use crate::store::{DocumentRow, Store};

pub const EMBED_DIM: usize = 64;
const RRF_K: f32 = 60.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchMode {
    Hybrid,
    Fts,
    Vector,
}

impl SearchMode {
    pub fn from_env(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "fts" | "lexical" => Self::Fts,
            "vector" | "semantic" => Self::Vector,
            _ => Self::Hybrid,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hybrid => "hybrid",
            Self::Fts => "fts",
            Self::Vector => "vector",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub id: i64,
    pub kind: String,
    pub ts: u64,
    pub title: String,
    pub body: String,
    pub source: String,
    pub fts_rank: Option<f32>,
    pub vector_score: Option<f32>,
    pub fused_score: f32,
}

#[derive(Debug, Clone)]
pub struct DiscoveryReport {
    pub trending: Vec<(String, u64)>,
    pub recent: Vec<SearchHit>,
    pub related: Vec<SearchHit>,
}

pub fn embed_text(text: &str) -> [f32; EMBED_DIM] {
    let mut vec = [0.0f32; EMBED_DIM];
    let lowered = text.to_ascii_lowercase();
    let chars: Vec<char> = lowered.chars().filter(|c| c.is_ascii() && !c.is_control()).collect();
    for n in 1..=3 {
        if chars.len() < n {
            continue;
        }
        for window in chars.windows(n) {
            let gram: String = window.iter().collect();
            accumulate(&mut vec, &gram);
        }
    }
    for token in tokenize(&lowered) {
        accumulate(&mut vec, token);
    }
    l2_normalize(&mut vec);
    vec
}

pub fn pack_embedding(vec: &[f32; EMBED_DIM]) -> Vec<u8> {
    let mut out = Vec::with_capacity(EMBED_DIM * 4);
    for v in vec {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let n = a.len().min(b.len());
    let mut dot = 0.0f32;
    let mut na = 0.0f32;
    let mut nb = 0.0f32;
    for i in 0..n {
        dot += a[i] * b[i];
        na += a[i] * a[i];
        nb += b[i] * b[i];
    }
    let denom = (na.sqrt() * nb.sqrt()).max(1e-8);
    (dot / denom).clamp(-1.0, 1.0)
}

pub fn fts_match_query(raw: &str) -> String {
    let terms: Vec<String> = tokenize(raw)
        .into_iter()
        .filter(|t| t.len() >= 2)
        .map(|t| {
            let safe: String = t.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
            if safe.is_empty() {
                String::new()
            } else {
                format!("{safe}*")
            }
        })
        .filter(|t| !t.is_empty())
        .collect();
    terms.join(" OR ")
}

pub fn hybrid_search(
    store: &Store,
    query: &str,
    mode: SearchMode,
    limit: usize,
) -> anyhow::Result<Vec<SearchHit>> {
    let query = query.trim();
    if query.is_empty() {
        return Ok(recent_as_hits(store, limit)?);
    }
    let limit = limit.clamp(1, 100);
    let fts_hits = if matches!(mode, SearchMode::Hybrid | SearchMode::Fts) {
        let q = fts_match_query(query);
        if q.is_empty() {
            Vec::new()
        } else {
            store.fts_search(&q, limit.saturating_mul(3))?
        }
    } else {
        Vec::new()
    };
    let vector_hits = if matches!(mode, SearchMode::Hybrid | SearchMode::Vector) {
        vector_search(store, query, limit.saturating_mul(3))?
    } else {
        Vec::new()
    };

    if mode == SearchMode::Fts {
        return Ok(fts_hits
            .into_iter()
            .enumerate()
            .map(|(rank, (doc, bm25))| {
                hit_from_doc(doc, Some(bm25), None, rrf_score(rank))
            })
            .take(limit)
            .collect());
    }
    if mode == SearchMode::Vector {
        return Ok(vector_hits
            .into_iter()
            .enumerate()
            .map(|(rank, (doc, score))| {
                hit_from_doc(doc, None, Some(score), rrf_score(rank))
            })
            .take(limit)
            .collect());
    }

    Ok(fuse_rrf(fts_hits, vector_hits, limit))
}

pub fn discover(store: &Store, query: &str, limit: usize) -> anyhow::Result<DiscoveryReport> {
    let trending = store.kind_counts()?;
    let recent = recent_as_hits(store, limit)?;
    let related = if query.trim().is_empty() {
        recent.iter().cloned().take(limit.min(6)).collect()
    } else {
        hybrid_search(store, query, SearchMode::Hybrid, limit)?
    };
    Ok(DiscoveryReport {
        trending,
        recent,
        related,
    })
}

fn vector_search(
    store: &Store,
    query: &str,
    limit: usize,
) -> anyhow::Result<Vec<(DocumentRow, f32)>> {
    let q = embed_text(query);
    let mut scored: Vec<(DocumentRow, f32)> = store
        .load_embeddings(2_000)?
        .into_iter()
        .map(|(doc, vec)| (doc, cosine(&q, &vec)))
        .filter(|(_, score)| *score > 0.05)
        .collect();
    scored.sort_by(|a, b| b.1.total_cmp(&a.1));
    scored.truncate(limit);
    Ok(scored)
}

fn fuse_rrf(
    fts: Vec<(DocumentRow, f32)>,
    vector: Vec<(DocumentRow, f32)>,
    limit: usize,
) -> Vec<SearchHit> {
    let mut fused: HashMap<i64, SearchHit> = HashMap::new();
    for (rank, (doc, bm25)) in fts.into_iter().enumerate() {
        let entry = fused.entry(doc.id).or_insert_with(|| hit_from_doc(doc, None, None, 0.0));
        entry.fts_rank = Some(bm25);
        entry.fused_score += rrf_score(rank);
    }
    for (rank, (doc, score)) in vector.into_iter().enumerate() {
        let entry = fused
            .entry(doc.id)
            .or_insert_with(|| hit_from_doc(doc, None, None, 0.0));
        entry.vector_score = Some(score);
        entry.fused_score += rrf_score(rank);
    }
    let mut out: Vec<SearchHit> = fused.into_values().collect();
    out.sort_by(|a, b| b.fused_score.total_cmp(&a.fused_score));
    out.truncate(limit);
    out
}

fn recent_as_hits(store: &Store, limit: usize) -> anyhow::Result<Vec<SearchHit>> {
    Ok(store
        .recent_documents(limit)?
        .into_iter()
        .enumerate()
        .map(|(rank, doc)| hit_from_doc(doc, None, None, rrf_score(rank)))
        .collect())
}

fn hit_from_doc(
    doc: DocumentRow,
    fts_rank: Option<f32>,
    vector_score: Option<f32>,
    fused_score: f32,
) -> SearchHit {
    SearchHit {
        id: doc.id,
        kind: doc.kind,
        ts: doc.ts,
        title: doc.title,
        body: doc.body,
        source: doc.source,
        fts_rank,
        vector_score,
        fused_score,
    }
}

fn rrf_score(rank: usize) -> f32 {
    1.0 / (RRF_K + rank as f32 + 1.0)
}

fn tokenize(text: &str) -> Vec<&str> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 2)
        .collect()
}

fn accumulate(vec: &mut [f32; EMBED_DIM], token: &str) {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    token.hash(&mut hasher);
    let h = hasher.finish();
    let idx = (h as usize) % EMBED_DIM;
    let sign = if h & 1 == 0 { 1.0 } else { -1.0 };
    vec[idx] += sign;
}

fn l2_normalize(vec: &mut [f32; EMBED_DIM]) {
    let mag = vec.iter().map(|v| v * v).sum::<f32>().sqrt();
    if mag > 1e-8 {
        for v in vec.iter_mut() {
            *v /= mag;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use crate::utils::time::now_unix_secs;

    #[test]
    fn similar_text_has_higher_cosine() {
        let a = embed_text("sshd network listener process");
        let b = embed_text("sshd listening on network port");
        let c = embed_text("disk write throughput on nvme0n1");
        assert!(cosine(&a, &b) > cosine(&a, &c));
    }

    #[test]
    fn hybrid_search_finds_indexed_document() {
        let path = std::env::temp_dir().join(format!(
            "manticore-search-{}-{}.sqlite",
            std::process::id(),
            now_unix_secs()
        ));
        let store = Store::open(&path).expect("open");
        store.write_document(
            "process",
            "nginx",
            "pid 441 nginx worker process handling http",
            "host:local",
            None,
        );
        store.write_document(
            "audit",
            "kill_process",
            "denied kill pid 441 by operator",
            "audit",
            None,
        );
        store.flush().expect("flush");
        let hits = hybrid_search(&store, "nginx http", SearchMode::Hybrid, 8).expect("search");
        assert!(!hits.is_empty());
        assert!(hits.iter().any(|h| h.title.contains("nginx") || h.body.contains("nginx")));
        let _ = std::fs::remove_file(path);
    }
}
