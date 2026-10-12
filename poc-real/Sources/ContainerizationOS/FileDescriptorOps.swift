// Vendored from apple/containerization Sources/ContainerizationOS/FileDescriptorOps.swift
// Apache-2.0
import SystemPackage

#if canImport(Darwin)
import Darwin
private let os_dup = Darwin.dup
private let os_S_IFMT = mode_t(Darwin.S_IFMT)
private let os_S_IFREG = mode_t(Darwin.S_IFREG)
private let os_S_IFDIR = mode_t(Darwin.S_IFDIR)
private let os_S_IFLNK = mode_t(Darwin.S_IFLNK)
#elseif canImport(Musl)
import CSystem
import Musl
private let os_dup = Musl.dup
private let os_S_IFMT = Musl.S_IFMT
private let os_S_IFREG = Musl.S_IFREG
private let os_S_IFDIR = Musl.S_IFDIR
private let os_S_IFLNK = Musl.S_IFLNK
#elseif canImport(Glibc)
import Glibc
private let os_dup = Glibc.dup
private let os_S_IFMT = mode_t(Glibc.S_IFMT)
private let os_S_IFREG = mode_t(Glibc.S_IFREG)
private let os_S_IFDIR = mode_t(Glibc.S_IFDIR)
private let os_S_IFLNK = mode_t(Glibc.S_IFLNK)
#endif

public enum FileDescriptorOps {

    public enum Error: Swift.Error, CustomStringConvertible, Equatable {
        case invalidRelativePath
        case invalidPathComponent
        case cannotFollowSymlink
        case systemError(String, Int32)

        public var description: String {
            switch self {
            case .invalidRelativePath:
                return "invalid relative path supplied to file descriptor operation"
            case .invalidPathComponent:
                return "an intermediate path component is missing or is not a directory"
            case .cannotFollowSymlink:
                return "cannot follow a symlink in a file descriptor operation"
            case .systemError(let operation, let err):
                return "\(operation) returned error: \(err)"
            }
        }
    }

    public enum EntryType: Sendable, Equatable {
        case regular
        case directory
        case symlink
        case other
    }

    public static func mkdir(
        _ fd: FileDescriptor,
        _ relativePath: FilePath,
        permissions: FilePermissions? = nil,
        makeIntermediates: Bool = false,
        completion: (FileDescriptor) throws -> Void = { _ in }
    ) throws {
        try validateRelativePath(relativePath)
        try mkdir(
            fd,
            relativePath.components,
            permissions: permissions,
            makeIntermediates: makeIntermediates,
            completion: completion
        )
    }

    public static func unlinkRecursive(_ fd: FileDescriptor, filename: FilePath.Component) throws {
        guard filename.string != "." && filename.string != ".." else { return }
        guard unlinkat(fd.rawValue, filename.string, 0) != 0 else { return }
        guard errno != ENOENT else { return }
        guard errno == EPERM || errno == EISDIR else {
            throw Error.systemError("file removal during file descriptor unlink", errno)
        }
        let componentFd = openat(fd.rawValue, filename.string, O_NOFOLLOW | O_RDONLY | O_DIRECTORY)
        guard componentFd >= 0 else {
            throw Error.systemError("directory open during file descriptor unlink", errno)
        }
        let componentFileDescriptor = FileDescriptor(rawValue: componentFd)
        defer { try? componentFileDescriptor.close() }
        let ownedFd = os_dup(componentFd)
        guard let dir = fdopendir(ownedFd) else {
            throw Error.systemError("directory opendir during file descriptor unlink", errno)
        }
        defer { closedir(dir) }
        while let entry = readdir(dir) {
            let childComponent = withUnsafePointer(to: entry.pointee.d_name) {
                $0.withMemoryRebound(to: UInt8.self, capacity: Int(NAME_MAX) + 1) {
                    let name = String(decodingCString: $0, as: UTF8.self)
                    return FilePath.Component(name)
                }
            }
            guard let childComponent else {
                throw Error.systemError("directory entry processing during file descriptor unlink", errno)
            }
            try unlinkRecursive(componentFileDescriptor, filename: childComponent)
        }
        if unlinkat(fd.rawValue, filename.string, AT_REMOVEDIR) != 0 {
            throw Error.systemError("directory removal during file descriptor unlink", errno)
        }
    }

    public static func enumerate(
        _ fd: FileDescriptor,
        _ body: (_ path: FilePath, _ type: EntryType, _ parentFd: FileDescriptor) throws -> Void
    ) throws {
        try enumerateHelper(fd, relativePath: FilePath(""), body: body)
    }

    #if canImport(Darwin)
    public static func getCanonicalPath(_ fd: FileDescriptor) throws -> FilePath {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard fcntl(fd.rawValue, F_GETPATH, &buffer) != -1 else {
            throw Errno(rawValue: errno)
        }
        let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return FilePath(String(decoding: bytes, as: UTF8.self))
    }
    #elseif canImport(Glibc) || canImport(Musl)
    public static func getCanonicalPath(_ fd: FileDescriptor) throws -> FilePath {
        let fdPath = "/proc/self/fd/\(fd.rawValue)"
        var buffer = [CChar](repeating: 0, count: 4096)
        let len = readlink(fdPath, &buffer, buffer.count - 1)
        guard len > 0 else { throw Error.systemError("readlink", errno) }
        let bytes = buffer.prefix(len).map { UInt8(bitPattern: $0) }
        return FilePath(String(decoding: bytes, as: UTF8.self))
    }
    #endif

    private static func mkdir(
        _ fd: FileDescriptor,
        _ relativeComponents: FilePath.ComponentView,
        permissions: FilePermissions? = nil,
        makeIntermediates: Bool,
        completion: (FileDescriptor) throws -> Void
    ) throws {
        guard let currentComponent = relativeComponents.first else {
            try completion(fd)
            return
        }
        let childComponents = FilePath.ComponentView(relativeComponents.dropFirst())
        var componentFd = openat(fd.rawValue, currentComponent.string, O_NOFOLLOW | O_RDONLY | O_DIRECTORY)
        if componentFd < 0 {
            guard makeIntermediates || childComponents.isEmpty else {
                throw Error.invalidPathComponent
            }
            if errno != ENOENT {
                try unlinkRecursive(fd, filename: currentComponent)
            }
            guard mkdirat(fd.rawValue, currentComponent.string, permissions?.rawValue ?? 0o755) == 0 else {
                throw Error.systemError("directory creation during file descriptor mkdir", errno)
            }
            componentFd = openat(fd.rawValue, currentComponent.string, O_NOFOLLOW | O_RDONLY | O_DIRECTORY)
            guard componentFd >= 0 else {
                throw Error.systemError("directory open during file descriptor mkdir", errno)
            }
        }
        let componentFileDescriptor = FileDescriptor(rawValue: componentFd)
        defer { try? componentFileDescriptor.close() }
        guard !childComponents.isEmpty else {
            try completion(componentFileDescriptor)
            return
        }
        try mkdir(componentFileDescriptor, childComponents,
                  permissions: permissions, makeIntermediates: makeIntermediates, completion: completion)
    }

    private static func enumerateHelper(
        _ fd: FileDescriptor,
        relativePath: FilePath,
        body: (_ path: FilePath, _ type: EntryType, _ parentFd: FileDescriptor) throws -> Void
    ) throws {
        let dupFd = os_dup(fd.rawValue)
        guard dupFd >= 0 else {
            throw Error.systemError("dup during file descriptor enumerate", errno)
        }
        guard let dir = fdopendir(dupFd) else {
            let savedErrno = errno
            try? FileDescriptor(rawValue: dupFd).close()
            throw Error.systemError("fdopendir during file descriptor enumerate", savedErrno)
        }
        defer { closedir(dir) }
        while let entry = readdir(dir) {
            let name = withUnsafePointer(to: entry.pointee.d_name) {
                $0.withMemoryRebound(to: UInt8.self, capacity: Int(NAME_MAX) + 1) {
                    String(decodingCString: $0, as: UTF8.self)
                }
            }
            guard name != "." && name != ".." else { continue }
            guard let component = FilePath.Component(name) else { continue }
            let entryPath = relativePath.appending(component)
            let entryType = resolveEntryType(parentFd: fd.rawValue, name: name, dtype: entry.pointee.d_type)
            try body(entryPath, entryType, fd)
            guard entryType == .directory else { continue }
            let childFd = openat(fd.rawValue, name, O_NOFOLLOW | O_RDONLY | O_DIRECTORY)
            guard childFd >= 0 else {
                throw Error.systemError("openat during file descriptor enumerate", errno)
            }
            let childDescriptor = FileDescriptor(rawValue: childFd)
            defer { try? childDescriptor.close() }
            try enumerateHelper(childDescriptor, relativePath: entryPath, body: body)
        }
    }

    private static func resolveEntryType(parentFd: Int32, name: String, dtype: UInt8) -> EntryType {
        switch dtype {
        case UInt8(DT_REG): return .regular
        case UInt8(DT_DIR): return .directory
        case UInt8(DT_LNK): return .symlink
        case UInt8(DT_UNKNOWN):
            var stbuf = stat()
            guard fstatat(parentFd, name, &stbuf, AT_SYMLINK_NOFOLLOW) == 0 else { return .other }
            switch stbuf.st_mode & os_S_IFMT {
            case os_S_IFREG: return .regular
            case os_S_IFDIR: return .directory
            case os_S_IFLNK: return .symlink
            default: return .other
            }
        default: return .other
        }
    }

    private static func validateRelativePath(_ path: FilePath) throws {
        guard !(path.components.contains { $0 == ".." }) else {
            throw Error.invalidRelativePath
        }
    }
}
