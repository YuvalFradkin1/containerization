# SIG-NEW — Source Provenance & Call Path

## Repository
- Fork: https://github.com/YuvalFradkin1/containerization
- Upstream: https://github.com/apple/containerization
- PoC root: `poc-real/`

## Vulnerable file (upstream, unmodified)
`Sources/ContainerizationArchive/ArchiveWriter.swift` — line 226
  - Containment guard uses `FilePath.appending(String)` instead of `FilePath.pushing(FilePath(target))`
  - Absolute symlink targets pass the guard; stored verbatim as `entry.symlinkTarget`

## Production call chain to vulnerable line
```
container cp <ctr>:/dir ./out/
  → LinuxContainer.copyOut()           [LinuxContainer.swift:1363]
  → vminitd gRPC copy(direction:.copyOut)
  → handleCopyOut()                    [Server+GRPC.swift:556]
  → ArchiveWriter.archiveDirectory()   [Server+GRPC.swift:596]  ← VULNERABLE
  → ArchiveReader.extractContents()    [LinuxContainer.swift:1394] → symlinkat(2) on HOST
```
Steps 4–5 (ArchiveWriter / ArchiveReader) are exercised directly by this PoC.
Steps 1–3 (CLI → gRPC → vminitd) are verified by static analysis.

## Vendored source files (verbatim from upstream)
- `poc-real/Sources/VendoredContainerizationArchive/ArchiveError.swift`  sha256=5a6dc4c1b8b94835b4c50950191b6a23cb1709381f44a581840fb6ab02ab270a
- `poc-real/Sources/VendoredContainerizationArchive/ArchiveReader.swift`  sha256=2b047577976a7348a2ddb732901053546242427404028356a7eb3e0485844b70
- `poc-real/Sources/VendoredContainerizationArchive/ArchiveWriter.swift`  sha256=f905c3d0525090965c4f6c8443e551c7af5ad65a613b3bfce76618c38c645cf0
- `poc-real/Sources/VendoredContainerizationArchive/ArchiveWriterConfiguration.swift`  sha256=bd61b25051b2f5ec155d1d3242351e5873e10a808632f581cf0c88be0a4e7341
- `poc-real/Sources/VendoredContainerizationArchive/TempDir.swift`  sha256=0fab56a29c81b7a88e6793e7cf8387455bf2412826130753e8f36ae1e66e22cc
- `poc-real/Sources/VendoredContainerizationArchive/WriteEntry.swift`  sha256=36c7f6871c9521ad73acfba0b18608236a54b1e47f3c5f949a1a2b074ed00ed4

## PoC commit
- Commit SHA: 148fdb57f0eac157ec9f4f34ed7ee04311ebcd1b
- Date: 2026-10-13
- CI workflow: `.github/workflows/poc-symlink-escape.yml`

## CI runs (hardened workflow — stage marker + exit-code enforcement)
| Run | Commit | Date | Platform | Result |
|-----|--------|------|----------|--------|
| #38264650576 | 5c56d70 | 2026-10-12 | macOS 15 arm64 | ✅ All 4 stages PASS |
| #38340497557 | 148fdb5 | 2026-10-13 | macOS 15 arm64 | ✅ All 4 stages PASS |

