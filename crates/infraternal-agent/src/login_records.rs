//! Reserves stable host login record identifiers without merging people that share an account [D240,D247].
#![forbid(unsafe_code)]

use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};

/// Encode every bit of the person identity into a record line shorter than Linux `ut_line`.
#[must_use]
pub fn line(person: uuid::Uuid, record: &str) -> String {
    let mut value = person.as_u128();
    let mut bytes = Vec::new();
    loop {
        let digit = u8::try_from(value % 36).unwrap_or(0);
        bytes.push(if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        });
        value /= 36;
        if value == 0 {
            break;
        }
    }
    bytes.reverse();
    format!("i{}-{record}", String::from_utf8_lossy(&bytes))
}

/// Allocate once per person/account, using exclusive reservations to avoid four-byte record collisions.
/// # Errors
/// Refuses exposed/unowned registry paths, links, malformed records and exhausted storage.
pub fn identifier(root: &Path, unit: &str) -> io::Result<String> {
    if unit.is_empty()
        || unit.len() > 128
        || !unit
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(io::Error::other("invalid login record unit"));
    }
    match DirBuilder::new().mode(0o700).create(root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "login record directory is not private",
        ));
    }
    let mapping = root.join(format!("{unit}.record"));
    let existing = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(&mapping)
    {
        Ok(file) => Some(file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    if let Some(mut file) = existing {
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != metadata.uid()
            || meta.mode() & 0o777 != 0o600
            || meta.len() != 4
        {
            return Err(io::Error::other("invalid login record mapping"));
        }
        let mut value = [0; 4];
        file.read_exact(&mut value)?;
        if value.iter().all(u8::is_ascii_alphanumeric) {
            return String::from_utf8(value.to_vec()).map_err(io::Error::other);
        }
        return Err(io::Error::other("invalid login record identifier"));
    }
    for _ in 0..256 {
        let random = uuid::Uuid::new_v4();
        let alphabet = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let value: String = random.as_bytes()[..4]
            .iter()
            .map(|byte| char::from(alphabet[usize::from(*byte) % alphabet.len()]))
            .collect();
        let reservation = root.join(format!("{value}.reserved"));
        let mut reserved = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&reservation)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        reserved.write_all(value.as_bytes())?;
        drop(reserved);
        #[cfg(test)]
        before_publish(unit);
        // Publish only the completed inode. A suspended or abruptly stopped
        // opener cannot expose a zero-length record to another terminal.
        match fs::hard_link(&reservation, &mapping) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                fs::remove_file(reservation)?;
                return identifier(root, unit);
            }
            Err(error) => {
                let _ = fs::remove_file(reservation);
                return Err(error);
            }
        }
        return Ok(value);
    }
    Err(io::Error::other(
        "host login record identifiers unavailable",
    ))
}

#[cfg(test)]
static PUBLICATION: std::sync::Mutex<
    Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
> = std::sync::Mutex::new(None);
#[cfg(test)]
fn before_publish(unit: &str) {
    if unit == "paused" {
        let pause = PUBLICATION.lock().unwrap().take();
        if let Some((ready, resume)) = pause {
            ready.send(()).unwrap();
            resume.recv().unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    //! Distinct people and accounts must remain distinct in the host's bounded records.
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    #[test]
    fn records_preserve_full_person_identity_and_reserve_distinct_ids() {
        for person in [
            uuid::Uuid::nil(),
            uuid::Uuid::max(),
            uuid::Uuid::from_u128(1),
        ] {
            assert!(line(person, "aB09").len() < 32);
        }
        assert_ne!(
            line(uuid::Uuid::from_u128(1), "aB09"),
            line(uuid::Uuid::from_u128(2), "aB09")
        );
        assert_ne!(
            line(uuid::Uuid::nil(), "aB09"),
            line(uuid::Uuid::nil(), "aB10")
        );
        let root = std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/real-logins/records-{}",
            std::process::id()
        ));
        let first = identifier(&root, "one").unwrap();
        assert_eq!(first, identifier(&root, "one").unwrap());
        assert_ne!(first, identifier(&root, "two").unwrap());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn concurrent_same_login_publishes_one_complete_mapping() {
        let root = std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/real-logins/record-race-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let mut jobs = Vec::new();
        for _ in 0..16 {
            let root = root.clone();
            let barrier = barrier.clone();
            jobs.push(std::thread::spawn(move || {
                barrier.wait();
                identifier(&root, "same")
            }));
        }
        let values: Vec<_> = jobs.into_iter().map(|job| job.join().unwrap()).collect();
        fs::remove_dir_all(root).unwrap();
        assert!(
            values.iter().all(Result::is_ok),
            "a concurrent opener observed partial publication: {values:?}"
        );
        assert!(
            values
                .windows(2)
                .all(|pair| pair[0].as_ref().unwrap() == pair[1].as_ref().unwrap())
        );
    }

    #[test]
    fn suspended_publisher_never_exposes_partial_mapping() {
        let root = std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/real-logins/record-pause-{}",
            std::process::id()
        ));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        *PUBLICATION.lock().unwrap() = Some((ready_tx, resume_rx));
        let worker_root = root.clone();
        let writer = std::thread::spawn(move || identifier(&worker_root, "paused"));
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let concurrent = identifier(&root, "paused");
        resume_tx.send(()).unwrap();
        let original = writer.join().unwrap();
        fs::remove_dir_all(root).unwrap();
        assert!(
            concurrent.is_ok(),
            "concurrent opener saw a partial record: {concurrent:?}"
        );
        assert_eq!(original.unwrap(), concurrent.unwrap());
    }
}
