//! Web category files (format defined by agent/categories.py): b"OEMSCAT1", a big-endian u32
//! count, then sorted unique u64 domain hashes (first eight bytes of SHA-256 of the name).
use crate::error::{AgentError, Result};
use crate::policy::normalize_domain;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

const MAGIC: &[u8; 8] = b"OEMSCAT1";
const MAX_ENTRIES: usize = 20_000_000;

fn hash_normalized(domain: &str) -> u64 {
    let digest = Sha256::digest(domain.as_bytes());
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(prefix)
}

pub fn domain_hash(name: &str) -> Option<u64> {
    normalize_domain(name).ok().map(|domain| hash_normalized(&domain))
}

/// SHA-256 of a whole category file, as published in the server manifest.
pub fn file_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CategorySet {
    hashes: Vec<u64>,
}

impl CategorySet {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let invalid = || AgentError::Policy("invalid category file".into());
        if bytes.len() < 12 || &bytes[..8] != MAGIC {
            return Err(invalid());
        }
        let count = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        if count > MAX_ENTRIES || bytes.len() != 12 + 8 * count {
            return Err(invalid());
        }
        let hashes: Vec<u64> = bytes[12..].as_chunks::<8>().0.iter().map(|chunk| u64::from_be_bytes(*chunk)).collect();
        if hashes.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(invalid());
        }
        Ok(CategorySet { hashes })
    }

    /// Build from raw list entries; invalid names are skipped, like the server builder.
    pub fn from_domains(domains: &[String]) -> Self {
        let mut hashes: Vec<u64> = domains.iter().filter_map(|domain| domain_hash(domain)).collect();
        hashes.sort_unstable();
        hashes.dedup();
        CategorySet { hashes }
    }

    pub fn hashes(&self) -> &[u64] {
        &self.hashes
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// The name or any parent domain of two labels or more is listed.
    pub fn contains(&self, name: &str) -> bool {
        let Ok(domain) = normalize_domain(name) else { return false };
        let labels: Vec<&str> = domain.split('.').collect();
        (0..labels.len().saturating_sub(1))
            .any(|start| self.hashes.binary_search(&hash_normalized(&labels[start..].join("."))).is_ok())
    }
}

/// Category membership as seen by block decisions.
pub trait CategoryLookup {
    fn contains(&self, category: &str, name: &str) -> bool;
}

/// No category data: categories never block.
pub struct NoCategories;

impl CategoryLookup for NoCategories {
    fn contains(&self, _: &str, _: &str) -> bool {
        false
    }
}

/// Loaded categories, replaced whole per id so readers never see a partial set.
#[derive(Default)]
pub struct CategoryStore(RwLock<HashMap<String, Arc<CategorySet>>>);

impl CategoryStore {
    pub fn insert(&self, id: &str, set: CategorySet) {
        self.0.write().unwrap_or_else(|poison| poison.into_inner()).insert(id.to_owned(), Arc::new(set));
    }

    /// Drop categories the current policy no longer uses.
    pub fn retain(&self, ids: &[String]) {
        self.0.write().unwrap_or_else(|poison| poison.into_inner()).retain(|id, _| ids.contains(id));
    }

    pub fn loaded(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.0.read().unwrap_or_else(|poison| poison.into_inner()).keys().cloned().collect();
        ids.sort();
        ids
    }
}

impl CategoryLookup for CategoryStore {
    fn contains(&self, category: &str, name: &str) -> bool {
        let set = self.0.read().unwrap_or_else(|poison| poison.into_inner()).get(category).cloned();
        set.is_some_and(|set| set.contains(name))
    }
}
