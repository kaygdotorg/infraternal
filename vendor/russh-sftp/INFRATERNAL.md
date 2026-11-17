<!-- Records the origin and local ownership fix for the SFTP dependency. -->
# Pinned SFTP server

Published russh-sftp 3.0.1, checksum
9bb17f72aba4314656b359ffba72c68dcbd70ed9e97497898b75498fe7198042. Original license and notices retained.
The protocol ownership change adds serve_with_config: an owned protocol future, so
channel teardown cancels the current file operation as well as stream I/O.
It terminates on protocol/I/O errors rather than retrying a broken stream.
The existing run entry points still spawn the protocol future.
This supports D235/D289, issue #221.

J847 (#532, 2026-11-17) removes the chrono dependency from this copy. File
timestamps use std's duration since the Unix epoch, keeping the previous
flooring of negative fractional seconds and wrapping to SFTP v3's u32 wire
field. Directory listings use the existing time crate for the same English UTC
month/day/year/hour/minute text. Unit cases cover epoch, pre-epoch, leap day
and post-2106 wrapping. The remaining chrono lockfile entry comes only from russh-util's wasm32 clock.
