<!-- Documents authenticated immutable replacement admission and live-service recovery for #157, D217/D224/D226. -->
# Safe server replacement

Stage the native architecture binary with `MANIFEST`, `MANIFEST.sig` and
`VERSION` in the same directory. The manifest is the hardened signer's canonical
`infraternal-release-manifest-v1` document: version and channel headers followed
by the exact checksum list. The release signature covers the whole document in
the existing `infraternal-release` namespace. Both compiled release keys remain
trusted. Legacy `SHA256SUMS` metadata alone cannot admit a replacement.

Keep the executable and its parents owned by the service account or root, with
no writable executable permissions for group or others, no set-ID bits, symlinks
or parent-directory escapes. Warm CA handoff additionally requires root, a
root-owned protected path and the existing compatible binary marker. Rootless
replacement retains the explicit cold behavior.

Run the service account's `infraternal server --data <existing-state> restart
--binary <staged-executable>`, then check health and administrator CA status.
The receiver owns admission; the CLI sends the original absolute path once.
An accepted request acknowledges intent. Health and CA status establish the
actual outcome. No private signing material enters a pathname, argument or
replacement metadata.

On Linux the receiver copies the bounded image (maximum 128 MiB) into a memfd,
applies `F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL`, and verifies
the signature and hash against those immutable bytes. VERSION is separately
frozen, authenticated and compared with the signed identity. The file at the
original pathname can be renamed or rewritten afterward without changing what
executes. The same descriptor supplies the compatibility check and `fexecve`.

A secret-free `--version` probe of that image must succeed within two seconds
before the serving future is dropped or the runtime shuts down. The probe has
null standard streams, an empty environment, restored child signals and a
bounded stop/reap path. Unsigned, changed, truncated, oversized or unusable
images are refused while the existing listeners stay live.

Before shutdown, retain the kernel's current image and a separate anonymous CA
handoff receiver. If replacement exec is refused late, re-exec the retained
current image with the original invocation and PID. Its independent frame
restores the unlocked CA through the same authenticated import. If the kernel
refuses both exec attempts, the already-loaded current code re-enters the same
CLI action dispatch with recovery stdin. No supervisor cold start is needed for
normal exec-refusal recovery. A failed CA import still follows D168's cold rule.

Default restart and SIGHUP may reuse bytes exactly equal to the kernel-pinned
running image, even for an unstamped development build. This exception applies
only to self reload. A changed installation image and every explicit replacement
must have signed metadata. The larger 512 MiB current-image bound accommodates
local debug sections; it does not increase the candidate admission limit.

Embedded subprocesses execute the running kernel image. Anonymous-image
infraternal agents launch independent shims directly in the existing detached
mode: an intermediate shell would change `/proc/self/exe`. The audited child
policy closes trusted control fd3 and restores signals before that direct exec.
Existing shims remain independent of the server runtime.

SSH prompt helpers also use the kernel running image. External SSH cannot use
`/proc/self/exe` as the server's pathname, so each credential scope creates a
0500 executable copy inside its existing private directory and removes it on
scope cleanup. Before releasing a reply, the server checks the kernel peer's
UID, registered direct parent, executable device/inode and the original running
image digest. An in-place rewrite or pathname replacement is refused. The
server remains nondumpable; only the existing prompt mode becomes dumpable after
clearing stdin. Adjacent development payload discovery retains the original
absolute invocation directory after anonymous replacement.

## macOS qualification

The alternative copies into a random owner-only directory, closes its writable
descriptor, applies executable/read-only mode, verifies that private copy and
executes it. macOS has no equivalent memfd seals here: the same owner can still
chmod, rewrite or rename a verified copy before exec. Authentication does not
eliminate that residual race. Self reload requires signed metadata there because
reading an installation pathname cannot authenticate the loaded image.
Successful exec bypasses Rust destructors; private copies can remain until
operator cleanup. The server is a Linux target (D20); this conditional path was
not runtime-tested on a Mac in this lane. Do not claim Linux's immutable-image or
measured listener guarantees for it.
