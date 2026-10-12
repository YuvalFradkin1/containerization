// Stub — ContainerizationOS module shim for PoC compilation.
// The PoC exercises ArchiveReader.makeStreamingIterator() which does NOT
// call FileDescriptorOps. This stub satisfies the compiler for extractContents()
// and extractFile() which ARE compiled but NOT executed in the PoC.
import SystemPackage
import Foundation

public enum FileDescriptorOps {
    public enum Error: Swift.Error, CustomStringConvertible, Equatable {
        case invalidRelativePath
        case invalidPathComponent
        case cannotFollowSymlink
        case systemError(String, Int32)

        public var description: String { "\(self)" }
    }

    public static func mkdir(
        _ fd: FileDescriptor,
        _ path: FilePath,
        makeIntermediates: Bool,
        body: (FileDescriptor) throws -> Void
    ) throws {
        throw Error.systemError("mkdir", ENOSYS)
    }

    public static func unlinkRecursive(_ fd: FileDescriptor, filename: FilePath.Component) throws {
        throw Error.systemError("unlink", ENOSYS)
    }
}
