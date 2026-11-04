//! Generates compact static `SQLx` migration data with checksums of the unchanged source files [19,243].
use sha2::{Digest, Sha384};
use std::{fmt::Write as _, fs, io, path::Path};

#[path = "compact_sql.rs"]
mod compact_sql;

// Match the pinned source filter exactly; uppercase extensions are not migrations.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
pub fn generate(directory: &Path, output: &Path) -> io::Result<()> {
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some((prefix, rest)) = name.split_once('_') else {
            continue;
        };
        if !rest.ends_with(".sql") {
            continue;
        }
        let version = prefix.parse::<i64>().map_err(io::Error::other)?;
        files.push((version, name, entry.path()));
    }
    files.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    let mut generated = String::from(
        "// Static executable SQL; checksums identify the immutable original migration sources.\n\
         pub(super) static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate::Migrator {\n\
         migrations: std::borrow::Cow::Borrowed(&[\n",
    );
    for (version, name, path) in files {
        // Match the pinned migration source's naming and transaction conventions.
        let (kind, suffix) = if name.ends_with(".up.sql") {
            ("ReversibleUp", ".up.sql")
        } else if name.ends_with(".down.sql") {
            ("ReversibleDown", ".down.sql")
        } else {
            ("Simple", ".sql")
        };
        let (_, rest) = name
            .split_once('_')
            .ok_or_else(|| io::Error::other("migration name"))?;
        let description = rest.trim_end_matches(suffix).replace('_', " ");
        let sql = fs::read_to_string(&path)?;
        let checksum = Sha384::digest(sql.as_bytes());
        let no_tx = sql.starts_with("-- no-transaction");
        let executable = compact_sql::compact(&sql);
        writeln!(generated,
            "sqlx::migrate::Migration {{ version: {}, description: std::borrow::Cow::Borrowed({description:?}), migration_type: sqlx::migrate::MigrationType::{kind}, sql: std::borrow::Cow::Borrowed({executable:?}), checksum: std::borrow::Cow::Borrowed(&{:?}), no_tx: {no_tx} }},",
            grouped(version), &checksum[..]).map_err(io::Error::other)?;
    }
    generated.push_str("] ), ..sqlx::migrate::Migrator::DEFAULT };\n");
    fs::write(output.join("compact_migrations.rs"), generated)
}

/// A version as a Rust literal with `_` between groups of three digits.
/// D347 names new migrations by UTC timestamp (14 digits); grouping keeps
/// the generated code clean under `clippy::unreadable_literal`, and the value
/// is unchanged.
fn grouped(version: i64) -> String {
    let digits = version.to_string();
    let (sign, digits) = digits
        .strip_prefix('-')
        .map_or(("", digits.as_str()), |rest| ("-", rest));
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push('_');
        }
        out.push(digit);
    }
    format!("{sign}{out}")
}
