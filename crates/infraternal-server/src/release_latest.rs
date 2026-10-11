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
}
/// Bind declared release actions to an existing private state directory; never initialize a server.
#[must_use]
pub fn release_service(pool: sqlx::SqlitePool, state: &Path) -> ReleaseService {
    ReleaseService::new(
        pool,
        Arc::new(VerifiedLookup::new(
            state.to_owned(),
            "https://builds.infraternal.com".into(),
            Arc::new(Engine {
                #[cfg(test)]
                trust: None,
            }),
        )),
    )
}
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
    Ok(ReleasePlugin(release_service(pool, &state)))
}
