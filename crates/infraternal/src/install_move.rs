//! Moves an existing server install's data folder to its D395 standard location [D395, #516].
//!
//! Red-first stage: the interface and its behavioural tests exist; the move
//! itself is not built yet, so every behaviour test fails.

use std::{
    fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

/// The marker file a move leaves in the data folder until it has finished.
pub const MARKER: &str = ".infraternal-move";

/// Why a folder could not be moved; the text says what to do instead.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct MoveError(String);

/// The service manager calls a move needs; tests use a fake.
pub trait Service {
    /// Whether the service is running or on its way up or down.
    fn active(&self) -> io::Result<bool>;
    /// Whether the service starts at boot or login.
    fn enabled(&self) -> io::Result<bool>;
    /// Stop the service and wait until it has stopped.
    fn stop(&self) -> io::Result<()>;
    /// Make the manager read the rewritten unit files.
    fn reload(&self) -> io::Result<()>;
    /// Start the service.
    fn start(&self) -> io::Result<()>;
}

/// Where an interrupted or new move resumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Nothing moved yet.
    Move,
    /// A copy finished but the unit was never switched.
    Redo,
    /// The folder was renamed but the unit was never switched.
    Switch,
    /// The unit is switched; only cleanup is left.
    Cleanup,
}

/// A checked move, ready for [`apply`].
#[derive(Debug, Clone)]
pub struct Relocation {
    /// The folder the unit records now.
    pub from: PathBuf,
    /// The D395 standard folder.
    pub to: PathBuf,
    /// Where this run starts.
    pub stage: Stage,
    /// Whether both folders are on one filesystem.
    pub same_filesystem: bool,
}

/// What [`apply`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The read-only copy of the old folder, kept after a copy.
    pub leftover: Option<PathBuf>,
    /// Whether the data was copied (true) or renamed (false).
    pub copied: bool,
    /// A step after the switch that did not finish.
    pub warning: Option<String>,
}

/// Check a move; not built yet.
pub fn plan(_from: &Path, _to: &Path, _unit: &Path) -> Result<Option<Relocation>, MoveError> {
    Err(MoveError("not built yet".to_owned()))
}

impl Relocation {
    /// The unit files this move rewrites; not built yet.
    pub fn unit_files(&self) -> impl Iterator<Item = &Path> {
        std::iter::empty()
    }
}

impl Outcome {
    /// What happened; not built yet.
    #[must_use]
    pub fn describe(&self, _relocation: &Relocation) -> String {
        String::new()
    }
}

/// Carry out a move; not built yet.
pub fn apply(
    _relocation: &Relocation,
    _service: &dyn Service,
    _now: SystemTime,
) -> Result<Outcome, MoveError> {
    Err(MoveError("not built yet".to_owned()))
}

/// Rename hook the tests force into the copy path; not built yet.
fn copy_tree(_from: &Path, _to: &Path) -> io::Result<()> {
    Err(io::Error::other("not built yet"))
}

/// Byte-for-byte check of a copy; not built yet.
fn verify_tree(_original: &Path, _copy: &Path) -> io::Result<()> {
    Err(io::Error::other("not built yet"))
}

/// Write the marker; not built yet.
fn write_marker(_folder: &Path, _from: &Path) -> io::Result<()> {
    Err(io::Error::other("not built yet"))
}

/// Map one `ExecStart` word; not built yet.
fn map_word(word: &str, _from: &str, _to: &str) -> String {
    word.to_owned()
}

/// Whether a line names the folder; not built yet.
fn names_path(_text: &str, _path: &str) -> bool {
    false
}

/// UTC stamp for leftover names; not built yet.
fn utc_stamp(_seconds: u64) -> String {
    String::new()
}

#[cfg(test)]
#[path = "install_move_tests.rs"]
mod tests;
