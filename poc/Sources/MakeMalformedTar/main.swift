import Foundation

// Build a 512-byte "tar header" with ustar magic but wrong checksum field.
// libarchive verifies the checksum on archive_read_next_header2; a mismatch
// returns ARCHIVE_FATAL (not ARCHIVE_WARN, not ARCHIVE_EOF).
//
// Tar header layout (POSIX ustar):
//   [0..99]   name
//   [100..107] mode (octal, null-terminated)
//   [108..115] uid
//   [116..123] gid
//   [124..135] size
//   [136..147] mtime
//   [148..155] checksum field — we corrupt this deliberately
//   [156]     type flag
//   [257..262] magic "ustar"
//   [263..264] version "00"

var header = [UInt8](repeating: 0, count: 512)

// file name
let name = Array("malicious_layer_entry.txt".utf8)
for (i, b) in name.enumerated() { header[i] = b }

// mode (0644 → "0000644\0")
let mode = Array("0000644\0".utf8)
for (i, b) in mode.enumerated() { header[100 + i] = b }

// uid/gid
let uid = Array("0000000\0".utf8)
let gid = Array("0000000\0".utf8)
for (i, b) in uid.enumerated() { header[108 + i] = b }
for (i, b) in gid.enumerated() { header[116 + i] = b }

// size = 0
let sz = Array("00000000000\0".utf8)
for (i, b) in sz.enumerated() { header[124 + i] = b }

// mtime
let mt = Array("00000000000\0".utf8)
for (i, b) in mt.enumerated() { header[136 + i] = b }

// type flag '0' = regular file
header[156] = 0x30

// magic + version
let magic = Array("ustar".utf8)
for (i, b) in magic.enumerated() { header[257 + i] = b }
header[263] = 0x30; header[264] = 0x30  // "00"

// Set checksum field to all spaces (standard before computing)
for i in 148..<156 { header[i] = 0x20 }

// CORRUPT: write a wrong checksum (all 9s instead of real value)
// This guarantees ARCHIVE_FATAL on archive_read_next_header2
let badChecksum = Array("9999999\0".utf8)
for (i, b) in badChecksum.enumerated() { header[148 + i] = b }

// Append a second all-zero block (EOF marker) so total file is 1024 bytes
// The archive_read_open_fd will succeed (valid file), but next_header → FATAL
let eof = [UInt8](repeating: 0, count: 512)

let outputPath = CommandLine.arguments.count > 1
    ? CommandLine.arguments[1]
    : "/tmp/malformed_layer.tar"

var data = Data(header)
data.append(contentsOf: eof)
try! data.write(to: URL(fileURLWithPath: outputPath))
print("Wrote malformed tar to: \(outputPath)")
print("Header size: \(header.count) bytes (corrupt checksum at offset 148)")
