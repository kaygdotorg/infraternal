//! The mesh's DNS records (D165): one name per node, `<host>.<suffix>`, mapped
//! to the node's addresses.
//!
//! [`NameTable`] validates every change before applying it, and each change
//! returns a small [`NameDiff`] so resolvers only receive what changed.
use crate::model::{Addresses, MeshError, NodeId, validate_dns};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A change to the name table. Send it once to each resolver; it is
/// independent of peer policy updates.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameDiff {
    /// Full names (`host.suffix`) to delete.
    pub removed: Vec<String>,
    /// Full names to add, or to overwrite with these addresses.
    pub upserted: BTreeMap<String, Addresses>,
    /// The new DNS suffix when the change renamed the whole table; otherwise
    /// `None`.
    pub suffix: Option<String>,
}

/// The set of mesh names and the addresses they resolve to.
///
/// Lookup is exact and suffix-scoped: only a complete `host.suffix` name
/// answers. An outside name is never answered by this table.
#[derive(Clone, Debug)]
pub struct NameTable {
    suffix: String,
    hosts: BTreeMap<NodeId, (String, Addresses)>,
    records: BTreeMap<String, Addresses>,
}
impl NameTable {
    /// Creates an empty table for `suffix`, for example `internal`.
    ///
    /// # Errors
    /// Returns `InvalidName` if the suffix is not valid.
    pub fn new(suffix: String) -> Result<Self, MeshError> {
        validate_dns(&suffix, false)?;
        Ok(Self {
            suffix,
            hosts: BTreeMap::new(),
            records: BTreeMap::new(),
        })
    }
    /// Checks that `node` may use `host` as its name: the name must be valid,
    /// the full name must fit the DNS length limit, and no other node may
    /// already use it.
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
    /// Sets the name and addresses of `node`, replacing any earlier record of
    /// the same node.
    ///
    /// Returns the change to deliver to resolvers, which is empty if the node
    /// already has exactly this name and these addresses.
    ///
    /// # Errors
    /// Returns `InvalidName` for an invalid or oversized name and
    /// `DuplicateName` if another node uses it. The table is unchanged then.
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
    /// Deletes the record of `node`, if it has one. Returns the change to
    /// deliver, which is empty for an unknown node.
    pub fn remove(&mut self, node: NodeId) -> NameDiff {
        let mut diff = NameDiff::default();
        if let Some((host, _)) = self.hosts.remove(&node) {
            let name = format!("{host}.{}", self.suffix);
            self.records.remove(&name);
            diff.removed.push(name);
        }
        diff
    }
    /// Changes the suffix of every name at once.
    ///
    /// The returned change removes all old names and adds all new ones, and
    /// carries the new suffix. It is empty if the suffix did not change.
    ///
    /// # Errors
    /// Returns `InvalidName` if the suffix is not valid or if any existing
    /// full name would be longer than 253 bytes. The table is unchanged then.
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
    /// The addresses for a complete name such as `web.internal`, if it exists.
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<Addresses> {
        self.records.get(name).copied()
    }
    /// All records, keyed by full name.
    #[must_use]
    pub fn records(&self) -> &BTreeMap<String, Addresses> {
        &self.records
    }
    /// The current DNS suffix.
    #[must_use]
    pub fn suffix(&self) -> &str {
        &self.suffix
    }
}
