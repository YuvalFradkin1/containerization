// Verbatim copy from Sources/ContainerizationExtras/FileManager+Temporary.swift
// apple/containerization — Apache-2.0
import Foundation

extension FileManager {
    public func uniqueTemporaryDirectory(create: Bool = true) -> URL {
        let tempDirectoryURL = temporaryDirectory
        let uniqueDirectoryURL = tempDirectoryURL.appendingPathComponent(UUID().uuidString)
        if create {
            try? createDirectory(at: uniqueDirectoryURL, withIntermediateDirectories: true, attributes: nil)
        }
        return uniqueDirectoryURL
    }
}
