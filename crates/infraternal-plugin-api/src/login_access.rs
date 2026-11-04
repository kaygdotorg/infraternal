//! Login access: which person may become which account on a host [D235, D252, D319], #186, #221.
//!
//! One rule check serves every way to a shell (browser terminals, app windows,
//! mesh `ssh`), so there is never a path that ignores the rules (D235 Q14).
//! The check is split in two pure halves, because no single side knows every
//! fact it needs:
//!
//! 1. [`grant`] runs on the server, which owns the rules, the people and the
//!    machine provenance. It reduces the rules that match one (person, host)
//!    pair to a [`LoginGrant`].
//! 2. [`LoginGrant::allows`] runs on the target host, whose account database
//!    is authoritative. It checks the account the host actually resolved,
//!    including D231's fallback to root, against that grant.
//!
//! Invariants (security review):
//! - There are no negative rules. A grant only ever widens, and the empty
//!   grant refuses everything, including a grant decoded from `{}`.
//! - Rules for another person never contribute. `Everyone` is the only
//!   subject that matches more than one person.
//! - "Their own username" matches only the person's exact current username,
//!   only on a machine that person added or one an administrator marked
//!   "Names match people here" (D319, R3S-01), and only for an ordinary
//!   account ([`OrdinaryUids`]). It never reaches root or a system account,
//!   even when that account carries the person's name.
//! - Root is reachable only through `any account` or a rule that names
//!   `root`. A missing preferred account that falls back to root needs that
//!   separate rule; it never inherits the own-username grant.
//! - Account names compare byte for byte. Nothing is case-folded or trimmed.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The range of ordinary (person) accounts on one operating system.
///
/// The upper bound stays below the `nobody`/`nfsnobody` accounts (65534) and
/// the default `UID_MAX` of `login.defs` (60000), so a system or overflow
/// account is never mistaken for a person's own account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrdinaryUids {
    pub first: u32,
    pub last: u32,
}
impl OrdinaryUids {
    /// Ordinary accounts on Linux.
    pub const LINUX: Self = Self {
        first: 1000,
        last: 59_999,
    };
    /// Ordinary accounts on macOS.
    pub const MACOS: Self = Self {
        first: 501,
        last: 59_999,
    };
    /// The range for the operating system this binary runs on.
    #[must_use]
    pub const fn host() -> Self {
        if cfg!(target_os = "macos") {
            Self::MACOS
        } else {
            Self::LINUX
        }
    }
    /// Whether `uid` is an ordinary (person) account in this range.
    #[must_use]
    pub const fn contains(self, uid: u32) -> bool {
        uid >= self.first && uid <= self.last
    }
}

/// Which machine a rule or a check is about. The server's own host is reached
/// through its embedded infraternal agent and has no remote host ID (D231).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostRef {
    Embedded,
    Remote([u8; 16]),
}

/// Who a rule is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Subject {
    Everyone,
    /// A person by their stable ID, never by a display name or username.
    Person(String),
}

/// Which account a rule lets its subject become.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Account {
    /// The person's own username, under the conditions in the module doc.
    OwnUsername,
    /// Any account, including root (the D235 starter entitlement).
    Any,
    /// Exactly this account name.
    Named(String),
}

/// Where a rule applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hosts {
    All,
    Host(HostRef),
}

/// One stored login rule: subject, account and hosts must all match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub subject: Subject,
    pub account: Account,
    pub hosts: Hosts,
}

/// Server-verified facts about the target host for one person.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostFacts {
    pub host: HostRef,
    /// The person added this machine, from enrollment provenance, never a
    /// mutable label.
    pub added_by_person: bool,
    /// An administrator marked this machine "Names match people here".
    pub names_match_people: bool,
}

/// The accounts one person may become on one host. It travels from the
/// server to the host with each open; the host decides with [`Self::allows`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginGrant {
    #[serde(default)]
    pub any_account: bool,
    #[serde(default)]
    pub accounts: BTreeSet<String>,
    /// Set only where name matching applies on this host.
    #[serde(default)]
    pub own_username: Option<String>,
}

impl LoginGrant {
    /// Whether this grant lets the person become `account` (resolved on the
    /// host to `uid`). `ordinary` is the host's ordinary account range.
    #[must_use]
    pub fn allows(&self, account: &str, uid: u32, ordinary: OrdinaryUids) -> bool {
        if account.is_empty() {
            return false;
        }
        self.any_account
            || self.accounts.contains(account)
            || (self.own_username.as_deref() == Some(account) && ordinary.contains(uid))
    }
}

/// Reduce the rules that match `person` on `host` to one grant.
/// `username` is the person's current infraternal username.
#[must_use]
pub fn grant(rules: &[Rule], person: &str, username: &str, host: &HostFacts) -> LoginGrant {
    let mut grant = LoginGrant::default();
    // Sign-up refuses reserved names; this keeps an own-username grant from
    // ever naming root even if such a username reached the server.
    let names_match = (host.added_by_person || host.names_match_people)
        && !username.is_empty()
        && username != "root";
    for rule in rules {
        let subject = match &rule.subject {
            Subject::Everyone => true,
            Subject::Person(id) => id == person,
        };
        let hosts = match rule.hosts {
            Hosts::All => true,
            Hosts::Host(target) => target == host.host,
        };
        if !subject || !hosts {
            continue;
        }
        match &rule.account {
            Account::Any => grant.any_account = true,
            Account::Named(name) => {
                if !name.is_empty() {
                    grant.accounts.insert(name.clone());
                }
            }
            Account::OwnUsername => {
                if names_match {
                    grant.own_username = Some(username.to_owned());
                }
            }
        }
    }
    grant
}

#[cfg(test)]
#[path = "login_access_tests.rs"]
mod tests;
