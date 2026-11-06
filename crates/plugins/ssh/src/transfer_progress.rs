//! Validates exact remote byte counters without accepting output chatter as upload progress.

use crate::model::Failure;

/// One public payload has a fixed wire length, regardless of its encoding.
pub(crate) struct Progress {
    /// Bytes the authored remote reader has acknowledged consuming.
    consumed: u64,
    /// Declared wire bytes; acknowledgements cannot exceed this boundary.
    total: u64,
}

impl Progress {
    /// Start a counter for the exact selected public source, excluding private input.
    pub(crate) fn new(total: u64) -> Self {
        Self { consumed: 0, total }
    }

    /// Accept only canonical, strictly increasing counters within this payload.
    pub(crate) fn accept(&mut self, line: &[u8]) -> Result<(), Failure> {
        let count = line
            .strip_prefix(b"PROGRESS ")
            .and_then(|line| line.strip_suffix(b"\n"))
            .and_then(|number| std::str::from_utf8(number).ok())
            .and_then(|number| number.parse::<u64>().ok());
        let Some(count) = count else {
            return Err(invalid());
        };
        if count <= self.consumed
            || count > self.total
            || line != format!("PROGRESS {count}\n").as_bytes()
        {
            return Err(invalid());
        }
        self.consumed = count;
        Ok(())
    }

    /// Completion begins its own bounded exchange after the last remote byte.
    pub(crate) fn complete(&self) -> bool {
        self.consumed == self.total
    }
}

/// Hide arbitrary protocol input from diagnostics.
fn invalid() -> Failure {
    Failure::install("The SSH upload progress receipt was invalid.")
}

/// Read exactly the declared public payload and acknowledge actual remote reads.
/// `dd count=1` deliberately permits short reads: a slow link need not fill a
/// 64 KiB block before reporting progress. No private invitation byte is read.
/// Each temporary chunk is at most 64 KiB inside the owned transaction directory.
pub(crate) const READER: &str = r#"
exec 3>&1
read_payload() {
 remaining=$1
 consumed=0
 progress_dir=${progress_dir:-$stage}
 while [ "$remaining" -gt 0 ]; do
  block=65536
  [ "$remaining" -ge "$block" ] || block=$remaining
  dd bs="$block" count=1 > "$progress_dir/transfer-chunk" 2>/dev/null || return 1
  count=$(stat -c '%s' "$progress_dir/transfer-chunk") || return 1
  [ "$count" -gt 0 ] && [ "$count" -le "$block" ] || return 1
  cat "$progress_dir/transfer-chunk" || return 1
  # Keep noclobber enabled: the next read must create its own fresh chunk.
  rm "$progress_dir/transfer-chunk" || return 1
  consumed=$((consumed + count))
  remaining=$((remaining - count))
  prior=0
  if [ -f "$progress_dir/transfer-progress" ]; then IFS= read -r prior < "$progress_dir/transfer-progress" || return 1; fi
  case "$prior" in ''|*[!0-9]*) return 1;; esac
  [ "${#prior}" -le 18 ] || return 1
  printf '%s\n' "$((prior + count))" > "$progress_dir/transfer-progress-next" || return 1
  mv -f "$progress_dir/transfer-progress-next" "$progress_dir/transfer-progress" || return 1
  printf 'PROGRESS %s\n' "$consumed" >&3 || return 1
 done
}
"#;

/// Counters are a protocol boundary, so chatter and noncanonical values never renew a clock.
#[cfg(test)]
mod tests {
    use super::*;

    /// Reject forged, repeated, regressing and out-of-range receipts.
    #[test]
    fn accepts_only_strict_consumption_within_the_wire_length() {
        for line in [
            b"PROGRESS 0\n".as_slice(),
            b"PROGRESS 01\n",
            b"PROGRESS +1\n",
            b"PROGRESS 11\n",
            b"PROGRESS 18446744073709551616\n",
            b"keepalive\n",
            b"PROGRESS 1\r\n",
        ] {
            assert!(Progress::new(10).accept(line).is_err());
        }
        let mut progress = Progress::new(10);
        assert!(progress.accept(b"PROGRESS 2\n").is_ok());
        assert!(progress.accept(b"PROGRESS 2\n").is_err());
        assert!(progress.accept(b"PROGRESS 1\n").is_err());
        assert!(!progress.complete());
        assert!(progress.accept(b"PROGRESS 10\n").is_ok());
        assert!(progress.complete());
    }
}
