//! The seam between the owner controls (#211 S5) and the apply step (#211 S4).
//!
//! S5 decides WHO may ask for an update or a rollback (the owner, with a fresh passkey) and
//! shows the answer; S4 decides HOW the switch happens (the pre-update database copy, the warm
//! exec, the health check and the D295 undo). This trait is the whole contract between them, so
//! S4 plugs in without touching the RPCs: it implements [`UpdateApplier`] and hands it to
//! [`crate::service::ReleaseService::with_applier`].
//!
//! Until S4 is merged the service uses [`Unavailable`], which refuses every call with a plain
//! sentence and reports nothing to roll back. The owner controls therefore ship without being
//! able to change anything, which is the safe default.
use crate::update::Confirmed;
use infraternal_plugin_api::Operation;
use serde::Serialize;

/// Why apply and rollback refuse while S4 is not part of this build.
pub const NOT_BUILT: &str = "applying updates is not available in this build yet";

/// What a manual rollback would do, so the owner is told before pressing it (D295).
///
/// D295 keeps ONE database copy, taken right before the switch to the running version. Going back
/// restores it, so every write made after `copy_taken_at` is lost.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RollbackPlan {
    /// The previous version the server would go back to.
    pub to: String,
    /// When the pre-update database copy was taken, in Unix seconds. Data written after this is lost.
    pub copy_taken_at: i64,
}

/// What was started, for the answer to the caller. The server restarts warm, so the
/// connection that asked may drop right after this is sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Started {
    /// The version the server is going to.
    pub to: String,
    /// For a rollback, when the database copy being restored was taken (Unix seconds): every
    /// write after it is lost. `None` for an update, which loses nothing.
    pub lost_since: Option<i64>,
}

/// Applies a verified staged release and undoes the last update. S4 implements it.
pub trait UpdateApplier: Send + Sync {
    /// Switch to `release`, the release [`crate::update::Updater::confirm_staged`] just
    /// re-verified. The implementation holds `release` (and so the folder lock) until the switch
    /// is done, and records `applied` or `failed` in the history.
    /// # Errors
    /// A fixed public sentence saying why nothing was started.
    fn apply(&self, release: Confirmed) -> Operation<'_, Result<Started, &'static str>>;

    /// Go back to the previous version with the pre-update database copy (D295). It needs no
    /// passkey: the CA frame travels with the warm restart.
    /// # Errors
    /// A fixed public sentence saying why nothing was started (for example, nothing to go back to).
    fn rollback(&self) -> Operation<'_, Result<Started, &'static str>>;

    /// What [`UpdateApplier::rollback`] would do now, or `None` when there is nothing to go back to.
    fn rollback_plan(&self) -> Option<RollbackPlan>;
}

/// The applier of a build without S4: refuses everything.
pub struct Unavailable;

impl UpdateApplier for Unavailable {
    fn apply(&self, _release: Confirmed) -> Operation<'_, Result<Started, &'static str>> {
        Box::pin(async { Err(NOT_BUILT) })
    }
    fn rollback(&self) -> Operation<'_, Result<Started, &'static str>> {
        Box::pin(async { Err(NOT_BUILT) })
    }
    fn rollback_plan(&self) -> Option<RollbackPlan> {
        None
    }
}
