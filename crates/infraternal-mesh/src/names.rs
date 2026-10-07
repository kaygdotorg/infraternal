//! Suffix-scoped name table with atomic validation and compact record deltas (D165).
use crate::model::{Addresses, MeshError, NodeId, validate_dns};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Shared DNS update: deliver once to each resolver, independently of peer policy updates.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameDiff {
    pub removed: Vec<String>,
    pub upserted: BTreeMap<String, Addresses>,
    pub suffix: Option<String>,
}

/// Lookup is exact and suffix-scoped; an external name is never answered by this table.
#[derive(Clone, Debug)]
pub struct NameTable {
    suffix: String,
    hosts: BTreeMap<NodeId, (String, Addresses)>,
    records: BTreeMap<String, Addresses>,
}
impl NameTable {
    /// # Errors
    /// Rejects an invalid DNS suffix.
    pub fn new(suffix: String) -> Result<Self, MeshError> {
        validate_dns(&suffix, false)?;
        Ok(Self {
            suffix,
            hosts: BTreeMap::new(),
            records: BTreeMap::new(),
        })
    }
    pub(crate) fn check_host(&self, node: NodeId, host: &str) -> Result<(), MeshError> {
        validate_dns(host, true)?;
        if host.len() + self.suffix.len() + 1 > 253 {
            return Err(MeshError::InvalidName);
        }
        if self
            .records
            .contains_key(&format!("{host}.{}", self.suffix))
            && self.hosts.get(&node).is_none_or(|entry| entry.0 != host)
        {
            return Err(MeshError::DuplicateName);
        }
        Ok(())
    }
    /// # Errors
    /// Rejects invalid, oversized, or duplicate names without changing records.
    pub fn upsert(
        &mut self,
        node: NodeId,
        host: String,
        addresses: Addresses,
    ) -> Result<NameDiff, MeshError> {
        self.check_host(node, &host)?;
        if self
            .hosts
            .get(&node)
            .is_some_and(|entry| entry == &(host.clone(), addresses))
        {
            return Ok(NameDiff::default());
        }
        let mut diff = self.remove(node);
        let name = format!("{host}.{}", self.suffix);
        self.records.insert(name.clone(), addresses);
        self.hosts.insert(node, (host, addresses));
        diff.upserted.insert(name, addresses);
        Ok(diff)
    }
    pub fn remove(&mut self, node: NodeId) -> NameDiff {
        let mut diff = NameDiff::default();
        if let Some((host, _)) = self.hosts.remove(&node) {
            let name = format!("{host}.{}", self.suffix);
            self.records.remove(&name);
            diff.removed.push(name);
        }
        diff
    }
    /// # Errors
    /// Rejects invalid suffixes or names exceeding the DNS length limit.
    pub fn set_suffix(&mut self, suffix: String) -> Result<NameDiff, MeshError> {
        validate_dns(&suffix, false)?;
        if self
            .hosts
            .values()
            .any(|(host, _)| host.len() + suffix.len() + 1 > 253)
        {
            return Err(MeshError::InvalidName);
        }
        if suffix == self.suffix {
            return Ok(NameDiff::default());
        }
        let mut diff = NameDiff {
            removed: self.records.keys().cloned().collect(),
            suffix: Some(suffix.clone()),
            ..NameDiff::default()
        };
        self.suffix = suffix;
        self.records.clear();
        for (host, addresses) in self.hosts.values() {
            self.records
                .insert(format!("{host}.{}", self.suffix), *addresses);
        }
        diff.upserted.clone_from(&self.records);
        Ok(diff)
    }
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<Addresses> {
        self.records.get(name).copied()
    }
    #[must_use]
    pub fn records(&self) -> &BTreeMap<String, Addresses> {
        &self.records
    }
    #[must_use]
    pub fn suffix(&self) -> &str {
        &self.suffix
    }
}
