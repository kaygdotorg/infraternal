<!-- Records the origin and local ownership fix for the SFTP dependency. -->
# Pinned SFTP server

Published russh-sftp 3.0.1, checksum
9bb17f72aba4314656b359ffba72c68dcbd70ed9e97497898b75498fe7198042. Original license and notices retained.
The sole local change adds serve_with_config: an owned protocol future, so
channel teardown cancels the current file operation as well as stream I/O.
It terminates on protocol/I/O errors rather than retrying a broken stream.
The existing run entry points still spawn the protocol future.
This supports D235/D289, issue #221.
