//! Builds SFTP directory entries with stable, English UTC longname timestamps.

use time::{macros::format_description, OffsetDateTime};

use super::FileAttributes;

/// A directory entry containing its wire name, display listing and attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct File {
    /// The entry name sent to the SFTP client.
    pub filename: String,
    /// The human-readable directory listing built from the attributes.
    pub longname: String,
    /// Metadata used for the listing and protocol attribute fields.
    pub attrs: FileAttributes,
}

impl File {
    /// Omits `longname` and set dummy `attributes`. This is mainly used for [`crate::server::Handler::realpath`] as per the standard
    pub fn dummy<S: Into<String>>(filename: S) -> Self {
        Self {
            filename: filename.into(),
            longname: "".to_string(),
            attrs: FileAttributes::dummy(),
        }
    }

    /// Implies the use of longname
    pub fn new<S: Into<String>>(filename: S, attrs: FileAttributes) -> Self {
        let mut file = Self {
            filename: filename.into(),
            longname: "".to_string(),
            attrs,
        };
        file.longname = file.longname();
        file
    }

    /// Build a listing with an English UTC timestamp, independent of host locale.
    ///
    /// SFTP v3 mtimes are u32 Unix seconds, all within the calendar range.
    /// Missing mtimes retain the epoch display used by the original formatter.
    pub fn longname(&self) -> String {
        let directory = if self.attrs.is_dir() { "d" } else { "-" };
        let permissions = self.attrs.permissions().to_string();

        let size = self.attrs.size.unwrap_or(0);
        let mtime = self.attrs.mtime.unwrap_or(0);

        let datetime = OffsetDateTime::from_unix_timestamp(i64::from(mtime))
            .expect("every SFTP v3 u32 timestamp fits the calendar range");
        let delayed = datetime
            .format(format_description!(
                "[month repr:short] [day] [year] [hour]:[minute]"
            ))
            .expect("the UTC listing format only needs date and time fields");

        format!(
            "{directory}{permissions} 0 {} {} {size} {delayed} {}",
            if let Some(user) = &self.attrs.user {
                user.to_string()
            } else {
                self.attrs.uid.unwrap_or(0).to_string()
            },
            if let Some(group) = &self.attrs.group {
                group.to_string()
            } else {
                self.attrs.gid.unwrap_or(0).to_string()
            },
            self.filename
        )
    }
}

#[cfg(test)]
mod tests {
    //! Pin the original listing's English months, zero padding and UTC calendar.

    use super::{File, FileAttributes};

    /// Keep the exact directory listing at epoch, leap day and the wire limit.
    #[test]
    fn longname_preserves_utc_timestamp_text() {
        let cases = [
            (0, "Jan 01 1970 00:00"),
            (951_827_696, "Feb 29 2000 12:34"),
            (1_700_000_000, "Nov 14 2023 22:13"),
            (u32::MAX, "Feb 07 2106 06:28"),
        ];
        for (mtime, expected) in cases {
            let attrs = FileAttributes {
                size: Some(42),
                uid: Some(1000),
                gid: Some(1000),
                permissions: Some(0o100644),
                mtime: Some(mtime),
                ..FileAttributes::dummy()
            };
            let file = File::new("example", attrs);
            assert_eq!(
                file.longname,
                format!("-rw-r--r-- 0 1000 1000 42 {expected} example"),
                "mtime {mtime}"
            );
        }
    }
}
