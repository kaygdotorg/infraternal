#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Installs the signed Infraternal Linux x86-64 server binary by resolving the
# release channel pointer (stable by default; edge only when explicitly asked
# with `--channel edge`), verifying the OpenSSH signature over SHA256SUMS
# against the embedded release trust anchors, verifying the signed VERSION file
# matches the pointer, and verifying the downloaded binary's SHA-256 digest
# before moving it into place (#211, D184, D223, D224, D226).
#
# Usage:
#   curl -fsSL https://builds.infraternal.com/install.sh | sh
#   curl -fsSL https://builds.infraternal.com/install.sh | sh -s -- --channel edge
#   sh install.sh [--channel stable|edge] [--output PATH]
set -eu

channel="stable"
output="./infraternal"
origin="${INFRATERNAL_RELEASE_ORIGIN:-https://builds.infraternal.com}"

usage() {
  printf 'usage: install.sh [--channel stable|edge] [--output PATH]\n' >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --channel)
      [ "$#" -ge 2 ] || usage
      channel="$2"
      shift 2
      ;;
    --channel=*)
      channel="${1#--channel=}"
      shift
      ;;
    --output)
      [ "$#" -ge 2 ] || usage
      output="$2"
      shift 2
      ;;
    --output=*)
      output="${1#--output=}"
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      ;;
  esac
done

case "$channel" in
  stable|edge) ;;
  *)
    printf 'invalid channel "%s" (expected stable or edge)\n' "$channel" >&2
    exit 2
    ;;
esac

# Strip trailing slashes and refuse non-HTTPS origins except loopback test fixtures.
origin="$(printf '%s' "$origin" | sed 's:/*$::')"
case "$origin" in
  https://*) ;;
  http://127.0.0.1:*)
    printf '%s\n' "$origin" | awk '/^http:\/\/127\.0\.0\.1:[0-9]+$/ { ok = 1 } END { exit(ok ? 0 : 1) }' || {
      printf 'invalid release origin\n' >&2
      exit 2
    }
    ;;
  *)
    printf 'release origin must use https://\n' >&2
    exit 2
    ;;
esac

for tool in curl ssh-keygen sha256sum awk cmp mktemp; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'missing required tool: %s\n' "$tool" >&2
    exit 1
  }
done

os="$(uname -s)"
arch="$(uname -m)"
if [ "$os" != "Linux" ] || [ "$arch" != "x86_64" ]; then
  printf 'the Infraternal server binary is built for Linux x86_64 (this host is %s %s)\n' "$os" "$arch" >&2
  exit 1
fi

umask 077
staging="$(mktemp -d "${TMPDIR:-/tmp}/infraternal-install.XXXXXX")"
trap 'rm -rf -- "$staging"' EXIT HUP INT TERM

# Embedded release signing public keys from release/allowed_signers (D184, D224).
cat <<'EOF' > "$staging/allowed_signers"
release@infraternal.com namespaces="infraternal-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFuyvevVswnws0hN+Ch12peOKEEivKh/FBTN7+SN59HE release-key-1
release@infraternal.com namespaces="infraternal-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKaaLYxFOfvYIE4SOReWCtfFPuygJh58hbWQGgUVk5Wk release-key-2-spare
EOF

fetch_bounded() {
  url="$1"
  dest="$2"
  max_bytes="$3"
  allow_missing="${4:-0}"
  status="$(curl --silent --show-error --location --connect-timeout 10 --max-time 180 \
    --max-filesize "$max_bytes" -o "$dest" -w '%{http_code}' "$url")"
  if [ "$allow_missing" = "1" ] && [ "$status" = "404" ]; then
    return 44
  fi
  if [ "$status" != "200" ]; then
    printf 'download failed (%s): %s\n' "$status" "$url" >&2
    return 1
  fi
  size="$(wc -c < "$dest" | tr -d '[:space:]')"
  if [ "$size" -gt "$max_bytes" ]; then
    printf 'downloaded file exceeded size limit: %s\n' "$url" >&2
    return 1
  fi
}

# 1. Fetch the channel pointer (stable never falls back to edge).
pointer_rc=0
fetch_bounded "$origin/releases/channels/$channel.json" "$staging/pointer.json" 65536 1 || pointer_rc=$?
if [ "$pointer_rc" -eq 44 ]; then
  if [ "$channel" = "stable" ]; then
    printf 'no stable release yet\n' >&2
  else
    printf 'no edge release yet\n' >&2
  fi
  exit 1
elif [ "$pointer_rc" -ne 0 ]; then
  exit 1
fi

# 2. Extract and validate the candidate version from the pointer JSON.
version="$(awk '
  BEGIN { RS = "\0"; FS = "" }
  {
    raw = $0
    sub(/^[ \t\r\n]+/, "", raw)
    if (substr(raw, 1, 1) != "{") exit 1
    count = 0
    rest = raw
    while (match(rest, /"version"[ \t\r\n]*:[ \t\r\n]*"[^"]*"/)) {
      count++
      tok = substr(rest, RSTART, RLENGTH)
      sub(/^"version"[ \t\r\n]*:[ \t\r\n]*"/, "", tok)
      sub(/"$/, "", tok)
      ver = tok
      rest = substr(rest, RSTART + RLENGTH)
    }
    if (count != 1) exit 1
    print ver
  }
' "$staging/pointer.json")" || {
  printf 'invalid release pointer\n' >&2
  exit 1
}

if [ "$channel" = "stable" ]; then
  printf '%s\n' "$version" | awk '/^[0-9]+\.[0-9]+\.[0-9]+$/ { ok = 1 } END { exit(ok ? 0 : 1) }' || {
    printf 'release pointer belongs to another channel\n' >&2
    exit 1
  }
else
  printf '%s\n' "$version" | awk '/^edge-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z$/ { ok = 1 } END { exit(ok ? 0 : 1) }' || {
    printf 'release pointer belongs to another channel\n' >&2
    exit 1
  }
fi

# 3. Fetch signed metadata and verify the OpenSSH signature.
base="$origin/releases/$version"
fetch_bounded "$base/SHA256SUMS" "$staging/SHA256SUMS" 65536
fetch_bounded "$base/SHA256SUMS.sig" "$staging/SHA256SUMS.sig" 1024
fetch_bounded "$base/VERSION" "$staging/VERSION" 128

if ! ssh-keygen -Y verify -f "$staging/allowed_signers" -I release@infraternal.com \
    -n infraternal-release -s "$staging/SHA256SUMS.sig" < "$staging/SHA256SUMS" >/dev/null 2>&1; then
  printf 'release signature could not be verified\n' >&2
  exit 1
fi

# 4. Validate SHA256SUMS grammar and extract signed digests for VERSION and infraternal.
digests="$(awk '
  {
    if (NF != 2) exit 1
    if ($1 !~ /^[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]$/) exit 1
    if (index($2, "..") > 0 || substr($2, 1, 1) == "/") exit 1
    if (seen[$2]++) exit 1
    digest[$2] = $1
  }
  END {
    if (!seen["VERSION"] || !seen["infraternal"]) exit 1
    print digest["VERSION"] " " digest["infraternal"]
  }
' "$staging/SHA256SUMS")" || {
  printf 'invalid release manifest\n' >&2
  exit 1
}

version_sha="${digests%% *}"
binary_sha="${digests#* }"

# 5. Verify signed VERSION digest and exact match against the pointer version.
if ! printf '%s  %s\n' "$version_sha" "$staging/VERSION" | sha256sum -c - >/dev/null 2>&1; then
  printf 'signed VERSION checksum mismatch\n' >&2
  exit 1
fi
if ! printf '%s\n' "$version" | cmp -s - "$staging/VERSION"; then
  printf 'signed VERSION does not match the release pointer\n' >&2
  exit 1
fi

# 6. Download the server image, verify its signed SHA-256 digest, and move into place.
fetch_bounded "$base/infraternal" "$staging/infraternal" 134217728
if ! printf '%s  %s\n' "$binary_sha" "$staging/infraternal" | sha256sum -c - >/dev/null 2>&1; then
  printf 'server binary checksum mismatch\n' >&2
  exit 1
fi

chmod 0755 "$staging/infraternal"
mv -f "$staging/infraternal" "$output"
printf 'Verified and saved infraternal %s to %s\n' "$version" "$output"
printf 'Next: %s server init --dry-run\n' "$output"
