<!-- Role: Preserves the initial benchmark matrix that exposed harness timing and descriptor-limit issues. -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# First-pass data

This complete initial matrix is retained for auditability. Its Quinn delayed-handshake samples are excluded because the client closed connections before server-side acceptance completed. Its OpenSSL 1,000-connection memory sample is incomplete because the process ran with a 1,024 soft file-descriptor limit. The final report uses the corrected matrix in the parent `raw/` directory.
