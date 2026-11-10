#!/bin/bash
#
# fetch-real-corpus.sh — fetch the pinned real-firmware corpus (Phase 0.1)
#
# Downloads the clean corpus (legitimate firmware + signed boot loaders)
# described by test-data/real/manifest.toml, verifying every artifact
# against its pinned SHA-256. Malicious samples are never fetched: see
# the manifest for manual placement instructions.
#
# The downloaded binaries are covered by .gitignore (*.efi, *.fd) and
# never enter the repository.
#
# Requirements: curl, python3 (>= 3.11 for tomllib), tar, ar (binutils),
# zstd (for Arch .pkg.tar.zst archives).
#
# Usage: ./scripts/fetch-real-corpus.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MANIFEST="$PROJECT_ROOT/test-data/real/manifest.toml"
DEST="$PROJECT_ROOT/test-data/real"

command -v curl >/dev/null 2>&1 || { echo "✗ curl is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 1; }

echo "▶ Fetching real-firmware corpus into: $DEST"

python3 - "$MANIFEST" "$DEST" <<'PYEOF'
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib

manifest_path, dest = sys.argv[1], sys.argv[2]
with open(manifest_path, "rb") as f:
    manifest = tomllib.load(f)

clean_dir = os.path.join(dest, "clean")
malicious_dir = os.path.join(dest, "malicious")
os.makedirs(clean_dir, exist_ok=True)
os.makedirs(malicious_dir, exist_ok=True)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_member(archive, fmt, member, out_path):
    """Extract `member` from `archive` (deb or pkg.tar.zst) to out_path."""
    tmp = out_path + ".extract"
    os.makedirs(tmp, exist_ok=True)
    if fmt == "deb":
        # data.tar.* inside the .deb ar archive
        with open(archive, "rb") as f:
            head = f.read(8)
        if head[:6] != b"!<arch":
            raise RuntimeError("not a deb archive")
        # Let ar + tar do the work (ar is part of binutils).
        inner = subprocess.run(
            ["ar", "t", archive], capture_output=True, text=True, check=True
        ).stdout.split()
        data_member = next(m for m in inner if m.startswith("data.tar."))
        comp = data_member.rsplit(".", 1)[-1]
        tar_flag = {"xz": "-xJ", "gz": "-xZ", "zst": "--zstd", "bz2": "-xj"}.get(comp)
        if tar_flag is None:
            raise RuntimeError(f"unsupported deb compression: {data_member}")
        with open(os.path.join(tmp, "data.tar"), "wb") as out:
            subprocess.run(["ar", "p", archive, data_member], stdout=out, check=True)
        # deb data.tar entries usually carry a "./" prefix
        candidates = [member, "./" + member]
        last_err = None
        extracted = None
        for cand in candidates:
            proc = subprocess.run(
                ["tar", tar_flag, "-xf", os.path.join(tmp, "data.tar"), "-C", tmp, cand],
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                extracted = os.path.join(tmp, cand)
                break
            last_err = proc.stderr
        if extracted is None or not os.path.exists(extracted):
            raise RuntimeError(f"member {member} not found in archive: {last_err}")
    elif fmt == "pkg.tar.zst":
        subprocess.run(["tar", "--zstd", "-xf", archive, "-C", tmp, member], check=True)
        extracted = os.path.join(tmp, member)
    else:
        raise RuntimeError(f"unknown archive format: {fmt}")

    shutil.move(extracted, out_path)
    shutil.rmtree(tmp, ignore_errors=True)


entries = manifest.get("clean", [])
archives = {}  # url -> (local_path, expected_sha256, fmt)

with tempfile.TemporaryDirectory() as tmp:
    for e in entries:
        out = os.path.join(clean_dir, e["name"])
        if os.path.exists(out) and sha256_file(out) == e["sha256"]:
            print(f"  = {e['name']} (already present, hash verified)")
            continue
        print(f"  ↓ {e['name']}")

        url = e["archive_url"]
        if url not in archives:
            archive_path = os.path.join(tmp, f"archive{len(archives)}")
            print(f"      downloading {url}")
            subprocess.run(
                ["curl", "-fL", "--retry", "8", "--retry-delay", "5", "--retry-all-errors", "-o", archive_path, url], check=True
            )
            got = sha256_file(archive_path)
            if got != e["archive_sha256"]:
                raise RuntimeError(
                    f"archive hash mismatch for {url}:\n"
                    f"  expected {e['archive_sha256']}\n"
                    f"  got      {got}"
                )
            archives[url] = archive_path

        extract_member(archives[url], e["archive_format"], e["member"], out)
        got = sha256_file(out)
        if got != e["sha256"]:
            os.unlink(out)
            raise RuntimeError(
                f"file hash mismatch for {e['name']}:\n"
                f"  expected {e['sha256']}\n"
                f"  got      {got}"
            )
        print(f"  ✓ {e['name']} verified")

print(f"\n✓ Clean corpus ready: {len(entries)} files in {clean_dir}")

mal = manifest.get("malicious", [])
present = [m for m in mal if os.path.exists(os.path.join(malicious_dir, m["name"]))]
missing = [m for m in mal if not os.path.exists(os.path.join(malicious_dir, m["name"]))]
if present:
    print(f"✓ Malicious samples present: {', '.join(m['name'] for m in present)}")
if missing:
    print("\nMalicious samples are fetched manually (never automatically):")
    for m in missing:
        print(f"  - {m['name']}: {m['note']}")
    print(f"Place them in: {malicious_dir}")
    print("The malicious-recall gate (TPR >= 90%) is skipped while the directory is empty.")
PYEOF

echo "▶ Done. Validate with: cd src/barzakh-scanner-rs && cargo test -p barzakh-adversary --test real_corpus -- --nocapture"
