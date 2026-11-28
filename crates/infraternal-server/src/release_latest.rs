//! Supplies the existing HTTP/signature engines to the removable release plugin [198,224,226].
use infraternal_plugin_api::Operation;
use infraternal_plugin_release::{
    ReleasePlugin,
    latest::{DownloadError, ReleaseEngine, VerifiedLookup},
    service::ReleaseService,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
struct Engine {
    #[cfg(test)]
    trust: Option<String>,
}
impl ReleaseEngine for Engine {
    fn download<'a>(
        &'a self,
        address: &'a str,
        destination: &'a Path,
        max: u64,
    ) -> Operation<'a, Result<(), DownloadError>> {
        Box::pin(async move {
            crate::release_http::download(address, destination, max)
                .await
                .map_err(|error| match error {
                    crate::release_http::DownloadError::Missing => DownloadError::Missing,
                    error => DownloadError::Refused(error.reason()),
                })
        })
    }
    fn verify_version(
        &self,
        file: &std::fs::File,
        sums: &[u8],
        signature: &[u8],
    ) -> Result<(), &'static str> {
        #[cfg(test)]
        if let Some(trust) = &self.trust {
            return crate::release_verify::verify_with_trust(
                file, "VERSION", sums, signature, trust,
            )
            .map_err(|_| "release VERSION could not be verified");
        }
        crate::release_verify::verify_release_file(file, "VERSION", sums, signature)
            .map_err(|_| "release VERSION could not be verified")
    }
    fn verify_image(
        &self,
        version: &std::fs::File,
        image: &std::fs::File,
        name: &str,
        sums: &[u8],
        signature: &[u8],
    ) -> Result<String, &'static str> {
        use crate::release_verify::ReleaseError;
        #[cfg(test)]
        let result = match &self.trust {
            Some(trust) => crate::release_verify::verify_identity_with_trust(
                version, image, name, sums, signature, trust,
            ),
            None => crate::release_verify::verify_release_identity(
                version, image, name, sums, signature,
            ),
        };
        #[cfg(not(test))]
        let result =
            crate::release_verify::verify_release_identity(version, image, name, sums, signature);
        result.map_err(|error| match error {
            ReleaseError::Signature | ReleaseError::Untrusted | ReleaseError::Invalid => {
                "the release signature could not be verified"
            }
            ReleaseError::Checksums => "the signed checksums do not list this release image",
            ReleaseError::Digest => "the release does not match its signed checksums",
            ReleaseError::Read => "the downloaded release could not be read",
            ReleaseError::Version => "the signed release version is malformed",
        })
    }
}

/// The builds host every release lookup and update check uses (D184).
const ORIGIN: &str = "https://infraternal.com";

/// The builds host to use: [`ORIGIN`], or in a `staging-trust` build only, the
/// `INFRATERNAL_STAGING_BUILDS_ORIGIN` loopback channel a root staging proof serves.
fn origin() -> String {
    #[cfg(feature = "staging-trust")]
    if let Ok(origin) = std::env::var("INFRATERNAL_STAGING_BUILDS_ORIGIN")
        && origin.starts_with("http://127.0.0.1:")
    {
        return origin;
    }
    ORIGIN.into()
}

/// Start the server's periodic update check and the S4 apply for the data folder
/// `data` (#211 S3, S4).
///
/// It runs only where an update could ever be applied: a pipeline release build
/// (`INFRATERNAL_RELEASE_BUILD=1`, so the version is a real signed identity), running
/// as root (the D295 switch replaces a root-owned binary, and the staging folder must
/// be root-only), on a platform with a published server image. Everywhere else it
/// returns `None` and starts nothing. The check task sleeps between checks and is
/// stopped by aborting it. The apply task ([`crate::update_apply`]) waits for a staged
/// release and a quiet window, and runs this process's trial if it is one. `listen` is
/// the HTTP listener the trial's health check calls. `executable` is the
/// embedded infraternal agent image that the trial checks for local logins.
pub(crate) fn start_updates(
    pool: sqlx::SqlitePool,
    data: &Path,
    listen: std::net::SocketAddr,
    executable: std::path::PathBuf,
) -> Option<tokio::task::JoinHandle<()>> {
    let artifact = infraternal_plugin_release::update::availability(release_build()).ok()?;
    let timing = crate::update_apply::Timing::from_environment();
    let mut updater = infraternal_plugin_release::update::Updater::new(
        data,
        origin(),
        infraternal_plugin_api::VERSION.into(),
        artifact.into(),
        Arc::new(Engine {
            #[cfg(test)]
            trust: None,
        }),
        infraternal_plugin_release::service::settings_reader(pool.clone()),
    );
    if let Some(period) = timing.checks {
        updater = updater.with_period(period);
    }
    let updater = Arc::new(updater);
    crate::update_apply::start(
        Arc::clone(&updater),
        pool,
        data.to_owned(),
        listen,
        artifact,
        executable,
    );
    Some(match timing.checks {
        Some(first) => updater.spawn_after(first),
        None => updater.spawn(),
    })
}
/// Whether this binary is a pipeline release build (`INFRATERNAL_RELEASE_BUILD=1`).
pub(crate) fn release_build() -> bool {
    env!("INFRATERNAL_RELEASE_BUILD") == "1"
}

/// Bind declared release actions to an existing private state directory; never initialize a server.
///
/// Where updates can run (see [`infraternal_plugin_release::update::availability`]) the service also gets
/// an updater for the owner controls (#211 S5): check now, stage a version, apply, cancel. It shares
/// nothing with the timer's updater but the folder and its lock, so one check runs at a time. Apply and
/// rollback refuse until S4's applier is plugged in with `with_applier`.
#[must_use]
pub fn release_service(pool: sqlx::SqlitePool, state: &Path) -> ReleaseService {
    let availability = infraternal_plugin_release::update::availability(release_build());
    let engine = || {
        Arc::new(Engine {
            #[cfg(test)]
            trust: None,
        })
    };
    let mut lookup = VerifiedLookup::new(state.to_owned(), origin(), engine())
        .with_updates(availability.map(|_| ()));
    if let Ok(artifact) = availability {
        lookup = lookup.with_updater(Arc::new(infraternal_plugin_release::update::Updater::new(
            state,
            origin(),
            infraternal_plugin_api::VERSION.into(),
            artifact.into(),
            engine(),
            infraternal_plugin_release::service::settings_reader(pool.clone()),
        )));
    }
    let service = ReleaseService::new(pool, Arc::new(lookup));
    // S4 does the switching and the undo; the owner controls only decide who may ask for them (#211 S5).
    match availability {
        Ok(artifact) => service.with_applier(Arc::new(crate::update_apply::ServerApplier::new(
            state, artifact,
        ))),
        Err(_) => service,
    }
}

/// Build the release plugin for the server whose database is `pool`.
///
/// The state folder is the database file's folder (in-memory fixtures get a path that does not
/// exist). The same service is also registered for the private control socket, so
/// `infraternal server update` runs through it (D400).
pub(crate) async fn plugin(
    pool: sqlx::SqlitePool,
) -> Result<ReleasePlugin, crate::plugins::PluginError> {
    let (_, _, filename): (i64, String, String) =
        sqlx::query_as("SELECT seq,name,file FROM pragma_database_list WHERE name='main'")
            .fetch_one(&pool)
            .await
            .map_err(|_| crate::plugins::PluginError::Storage)?;
    // In-memory fixtures have no retained server state; lookup must not use the current directory.
    let state = Path::new(&filename)
        .parent()
        .filter(|_| !filename.is_empty())
        .map_or_else(
            || PathBuf::from("/nonexistent/infraternal-release-state"),
            Path::to_owned,
        );
    let service = release_service(pool, &state);
    // The private control socket runs `infraternal server update` through this same service (D400).
    if !filename.is_empty() {
        crate::release_control::register(&state, service.clone());
    }
    Ok(ReleasePlugin(service))
}

#[cfg(all(test, feature = "ssh"))]
#[path = "release_latest_tests.rs"]
mod tests;

/// End-to-end update check and staging against a loopback test channel (#211 S3).
#[cfg(all(test, feature = "ssh"))]
#[path = "release_update_tests.rs"]
mod update_tests;
