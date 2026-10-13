//! Shares the internal shim startup schema and identity checks across executable build profiles (D13, D255).

/// One schema supplies the full CLI and the private session payload's parser.
#[derive(Debug, clap::Args)]
pub(crate) struct Options {
    #[arg(long)]
    pub(crate) session: String,
    #[arg(long)]
    pub(crate) uid: u32,
    #[arg(long, default_value_t = 80)]
    pub(crate) cols: u16,
    #[arg(long, default_value_t = 24)]
    pub(crate) rows: u16,
    #[arg(long)]
    pub(crate) state: Option<std::path::PathBuf>,
    #[arg(long)]
    pub(crate) detach: bool,
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    pub(crate) ring_capacity: usize,
    /// Internal test/startup override, clamped to the production ceiling.
    #[arg(long, default_value_t = 600_000)]
    pub(crate) exit_retention_ms: u64,
    /// Private fixed-command readiness probe; never reads login startup.
    #[arg(long)]
    pub(crate) readiness: bool,
}

impl Options {
    /// Validate the session identifier before any fork or filesystem operation.
    pub(crate) fn run(self) -> std::io::Result<()> {
        let Self {
            session,
            uid,
            cols,
            rows,
            state,
            detach,
            ring_capacity,
            exit_retention_ms,
            readiness,
        } = self;

        if session.len() != 32 || !session.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "session must be 32 hexadecimal characters",
            ));
        }
        let mut id = [0; 16];
        for (i, value) in id.iter_mut().enumerate() {
            *value = u8::from_str_radix(&session[i * 2..i * 2 + 2], 16)
                .map_err(std::io::Error::other)?;
        }
        if detach && !infraternal_shim::detach()? {
            return Ok(());
        }
        infraternal_shim::run_with_retention(
            infraternal_shim::Config {
                session: id,
                uid,
                cols,
                rows,
                state,
                ring_capacity,
                readiness,
            },
            std::time::Duration::from_millis(exit_retention_ms),
        )
    }
}
