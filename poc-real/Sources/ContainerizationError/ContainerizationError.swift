// Stub — ContainerizationError module shim for PoC compilation
// ContainerizationArchive imports this module but ArchiveError.swift
// does not actually use any types from it; the import satisfies
// the compiler without requiring the full module.
public enum ContainerizationError: Error {
    case stub
}
