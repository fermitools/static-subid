/**
 * test_helper_mock_stat.h - File stat mock functions
 *
 * Provides mock implementations of lstat() and fstat() for testing path
 * validation and security checks without requiring actual filesystem setup.
 *
 * Mock functions simulate various file states:
 * - Error conditions (ENOENT, EPERM, EIO)
 * - Different ownership (root vs non-root)
 * - Different file types (directory, regular file, symlink)
 * - Different permissions (safe vs world-writable)
 *
 * This header is self-contained but assumes autoconf.h and static-subid.h
 * have been included first (handled automatically by test_helper_all.h).
 *
 * Usage:
 *   #include "test_helper_all.h"
 *
 *   // Test path validation with root-owned directory
 *   old_lstat = lstat;
 *   lstat = mock_lstat_root_dir;
 *   result = validate_path(path);
 *   lstat = old_lstat;
 */

#ifndef TEST_HELPER_MOCK_STAT_H
#define TEST_HELPER_MOCK_STAT_H

#include <errno.h>
#include <sys/stat.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

/* ============================================================================
 * lstat() Mock Implementations
 * ============================================================================
 */

/**
 * mock_lstat_enoent - Mock lstat that fails with ENOENT
 * @pathname: Path to stat (ignored)
 * @statbuf: Stat buffer (unused)
 *
 * Simulates file not found condition.
 *
 * Return: -1 with errno set to ENOENT
 */
static int mock_lstat_enoent(const char *pathname, struct stat *statbuf) {
  (void)pathname;
  (void)statbuf;
  errno = ENOENT;
  return -1;
}

/**
 * mock_lstat_eperm - Mock lstat that fails with EPERM
 * @pathname: Path to stat (ignored)
 * @statbuf: Stat buffer (unused)
 *
 * Simulates permission denied condition.
 *
 * Return: -1 with errno set to EPERM
 */
static int mock_lstat_eperm(const char *pathname, struct stat *statbuf) {
  (void)pathname;
  (void)statbuf;
  errno = EPERM;
  return -1;
}

/**
 * mock_lstat_eio - Mock lstat that fails with EIO
 * @pathname: Path to stat (ignored)
 * @statbuf: Stat buffer (unused)
 *
 * Simulates I/O error condition.
 *
 * Return: -1 with errno set to EIO
 */
static int mock_lstat_eio(const char *pathname, struct stat *statbuf) {
  (void)pathname;
  (void)statbuf;
  errno = EIO;
  return -1;
}

/**
 * mock_lstat_root_dir - Mock lstat for root-owned directory
 * @pathname: Path to stat (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a directory owned by root with safe permissions (0755).
 *
 * Return: 0 (success)
 */
static int mock_lstat_root_dir(const char *pathname, struct stat *statbuf) {
  (void)pathname;
  statbuf->st_uid = 0;
  statbuf->st_mode = S_IFDIR | 0755;
  return 0;
}

/**
 * mock_lstat_root_dir_world_write - Mock lstat for world-writable root
 * directory
 * @pathname: Path to stat (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a directory owned by root with unsafe permissions (0777).
 * Used to test world-writable path detection.
 *
 * Return: 0 (success)
 */
static int mock_lstat_root_dir_world_write(const char *pathname,
                                           struct stat *statbuf) {
  (void)pathname;
  statbuf->st_uid = 0;
  statbuf->st_mode = S_IFDIR | 0777;
  return 0;
}

/**
 * mock_lstat_root_symlink - Mock lstat for root-owned symbolic link
 * @pathname: Path to stat (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a symlink owned by root. Used to test symlink detection.
 *
 * Return: 0 (success)
 */
static int mock_lstat_root_symlink(const char *pathname, struct stat *statbuf) {
  (void)pathname;
  statbuf->st_uid = 0;
  statbuf->st_mode = S_IFLNK | 0777;
  return 0;
}

/**
 * mock_lstat_root_file - Mock lstat for root-owned regular file
 * @pathname: Path to stat (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a regular file owned by root with safe permissions (0644).
 *
 * Return: 0 (success)
 */
static int mock_lstat_root_file(const char *pathname, struct stat *statbuf) {
  (void)pathname;
  statbuf->st_uid = 0;
  statbuf->st_mode = S_IFREG | 0644;
  return 0;
}

/**
 * mock_lstat_root_file_world_write - Mock lstat for world-writable root file
 * @pathname: Path to stat (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a regular file owned by root with unsafe permissions (0666).
 *
 * Return: 0 (success)
 */
static int mock_lstat_root_file_world_write(const char *pathname,
                                            struct stat *statbuf) {
  (void)pathname;
  statbuf->st_uid = 0;
  statbuf->st_mode = S_IFREG | 0666;
  return 0;
}

/**
 * mock_lstat_non_root_dir - Mock lstat for non-root owned directory
 * @pathname: Path to stat (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a directory owned by UID 1000 (typical first user).
 * Used to test ownership validation.
 *
 * Return: 0 (success)
 */
static int mock_lstat_non_root_dir(const char *pathname, struct stat *statbuf) {
  (void)pathname;
  statbuf->st_uid = 1000;
  statbuf->st_mode = S_IFDIR | 0755;
  return 0;
}

/**
 * mock_lstat_non_root_file - Mock lstat for non-root owned file
 * @pathname: Path to stat (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a regular file owned by UID 1000 (typical first user).
 *
 * Return: 0 (success)
 */
static int mock_lstat_non_root_file(const char *pathname,
                                    struct stat *statbuf) {
  (void)pathname;
  statbuf->st_uid = 1000;
  statbuf->st_mode = S_IFREG | 0644;
  return 0;
}

/* ============================================================================
 * fstat() Mock Implementations
 * ============================================================================
 */

/**
 * mock_fstat_enoent - Mock fstat that fails with ENOENT
 * @fd: File descriptor (ignored)
 * @statbuf: Stat buffer (unused)
 *
 * Simulates file descriptor not found condition (rare but possible).
 *
 * Return: -1 with errno set to ENOENT
 */
static int mock_fstat_enoent(int fd, struct stat *statbuf) {
  (void)fd;
  (void)statbuf;
  errno = ENOENT;
  return -1;
}

/**
 * mock_fstat_eperm - Mock fstat that fails with EPERM
 * @fd: File descriptor (ignored)
 * @statbuf: Stat buffer (unused)
 *
 * Simulates permission denied condition.
 *
 * Return: -1 with errno set to EPERM
 */
static int mock_fstat_eperm(int fd, struct stat *statbuf) {
  (void)fd;
  (void)statbuf;
  errno = EPERM;
  return -1;
}

/**
 * mock_fstat_eio - Mock fstat that fails with EIO
 * @fd: File descriptor (ignored)
 * @statbuf: Stat buffer (unused)
 *
 * Simulates I/O error condition.
 *
 * Return: -1 with errno set to EIO
 */
static int mock_fstat_eio(int fd, struct stat *statbuf) {
  (void)fd;
  (void)statbuf;
  errno = EIO;
  return -1;
}

/**
 * mock_fstat_root_dir - Mock fstat for root-owned directory
 * @fd: File descriptor (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a directory owned by root with safe permissions (0755).
 *
 * Return: 0 (success)
 */
static int mock_fstat_root_dir(int fd, struct stat *statbuf) {
  (void)fd;
  statbuf->st_uid = 0;
  statbuf->st_mode = S_IFDIR | 0755;
  return 0;
}

/**
 * mock_fstat_root_dir_world_write - Mock fstat for world-writable root
 * directory
 * @fd: File descriptor (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a directory owned by root with unsafe permissions (0777).
 *
 * Return: 0 (success)
 */
static int mock_fstat_root_dir_world_write(int fd, struct stat *statbuf) {
  (void)fd;
  statbuf->st_uid = 0;
  statbuf->st_mode = S_IFDIR | 0777;
  return 0;
}

/**
 * mock_fstat_root_symlink - Mock fstat for root-owned symlink
 * @fd: File descriptor (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a symlink owned by root (note: fstat on symlink fd is rare).
 *
 * Return: 0 (success)
 */
static int mock_fstat_root_symlink(int fd, struct stat *statbuf) {
  (void)fd;
  statbuf->st_uid = 0;
  statbuf->st_mode = S_IFLNK | 0777;
  return 0;
}

/**
 * mock_fstat_root_file - Mock fstat for root-owned regular file
 * @fd: File descriptor (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a regular file owned by root with safe permissions (0644).
 *
 * Return: 0 (success)
 */
static int mock_fstat_root_file(int fd, struct stat *statbuf) {
  (void)fd;
  statbuf->st_uid = 0;
  statbuf->st_mode = S_IFREG | 0644;
  return 0;
}

/**
 * mock_fstat_root_file_world_write - Mock fstat for world-writable root file
 * @fd: File descriptor (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a regular file owned by root with unsafe permissions (0666).
 *
 * Return: 0 (success)
 */
static int mock_fstat_root_file_world_write(int fd, struct stat *statbuf) {
  (void)fd;
  statbuf->st_uid = 0;
  statbuf->st_mode = S_IFREG | 0666;
  return 0;
}

/**
 * mock_fstat_non_root_dir - Mock fstat for non-root directory
 * @fd: File descriptor (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a directory owned by UID 1000.
 *
 * Return: 0 (success)
 */
static int mock_fstat_non_root_dir(int fd, struct stat *statbuf) {
  (void)fd;
  statbuf->st_uid = 1000;
  statbuf->st_mode = S_IFDIR | 0755;
  return 0;
}

/**
 * mock_fstat_non_root_file - Mock fstat for non-root file
 * @fd: File descriptor (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a regular file owned by UID 1000.
 *
 * Return: 0 (success)
 */
static int mock_fstat_non_root_file(int fd, struct stat *statbuf) {
  (void)fd;
  statbuf->st_uid = 1000;
  statbuf->st_mode = S_IFREG | 0644;
  return 0;
}

/**
 * mock_fstat_root_chardev - Mock fstat for root-owned character device
 * @fd: File descriptor (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a character device owned by root (e.g., /dev/null, /dev/tty).
 *
 * Return: 0 (success)
 */
static int mock_fstat_root_chardev(int fd, struct stat *statbuf) {
  (void)fd;
  statbuf->st_uid = 0;
  statbuf->st_mode = S_IFCHR | 0644;
  return 0;
}

/**
 * mock_fstat_root_blockdev - Mock fstat for root-owned block device
 * @fd: File descriptor (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a block device owned by root (e.g., /dev/sda, /dev/loop0).
 *
 * Return: 0 (success)
 */
static int mock_fstat_root_blockdev(int fd, struct stat *statbuf) {
  (void)fd;
  statbuf->st_uid = 0;
  statbuf->st_mode = S_IFBLK | 0644;
  return 0;
}

/**
 * mock_fstat_root_fifo - Mock fstat for root-owned FIFO
 * @fd: File descriptor (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a FIFO/named pipe owned by root.
 *
 * Return: 0 (success)
 */
static int mock_fstat_root_fifo(int fd, struct stat *statbuf) {
  (void)fd;
  statbuf->st_uid = 0;
  statbuf->st_mode = S_IFIFO | 0644;
  return 0;
}

/**
 * mock_fstat_root_socket - Mock fstat for root-owned socket
 * @fd: File descriptor (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a Unix domain socket owned by root.
 *
 * Return: 0 (success)
 */
static int mock_fstat_root_socket(int fd, struct stat *statbuf) {
  (void)fd;
  statbuf->st_uid = 0;
  statbuf->st_mode = S_IFSOCK | 0644;
  return 0;
}

/* ============================================================================
 * stat() Mock Implementations
 *
 * These follow symlinks (unlike lstat) and are used to test symlink target
 * validation in validate_config_dir().
 * ============================================================================
 */

/**
 * mock_stat_enoent - Mock stat that fails with ENOENT
 * @pathname: Path to stat (ignored)
 * @statbuf: Stat buffer (unused)
 *
 * Simulates broken symlink or file not found condition.
 *
 * Return: -1 with errno set to ENOENT
 */
static int mock_stat_enoent(const char *pathname, struct stat *statbuf) {
  (void)pathname;
  (void)statbuf;
  errno = ENOENT;
  return -1;
}

/**
 * mock_stat_eperm - Mock stat that fails with EPERM
 * @pathname: Path to stat (ignored)
 * @statbuf: Stat buffer (unused)
 *
 * Simulates permission denied on symlink target.
 *
 * Return: -1 with errno set to EPERM
 */
static int mock_stat_eperm(const char *pathname, struct stat *statbuf) {
  (void)pathname;
  (void)statbuf;
  errno = EPERM;
  return -1;
}

/**
 * mock_stat_root_dir - Mock stat for root-owned directory
 * @pathname: Path to stat (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates a directory owned by root with safe permissions (0755).
 * Used to test valid symlink targets.
 *
 * Return: 0 (success)
 */
static int mock_stat_root_dir(const char *pathname, struct stat *statbuf) {
  (void)pathname;
  statbuf->st_uid = 0;
  statbuf->st_mode = S_IFDIR | 0755;
  return 0;
}

/**
 * mock_stat_root_dir_world_write - Mock stat for world-writable root directory
 * @pathname: Path to stat (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates symlink target that's world-writable (unsafe).
 *
 * Return: 0 (success)
 */
static int mock_stat_root_dir_world_write(const char *pathname,
                                          struct stat *statbuf) {
  (void)pathname;
  statbuf->st_uid = 0;
  statbuf->st_mode = S_IFDIR | 0777;
  return 0;
}

/**
 * mock_stat_root_file - Mock stat for root-owned regular file
 * @pathname: Path to stat (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates symlink pointing to a regular file (invalid for config dir).
 *
 * Return: 0 (success)
 */
static int mock_stat_root_file(const char *pathname, struct stat *statbuf) {
  (void)pathname;
  statbuf->st_uid = 0;
  statbuf->st_mode = S_IFREG | 0644;
  return 0;
}

/**
 * mock_stat_non_root_dir - Mock stat for non-root owned directory
 * @pathname: Path to stat (ignored)
 * @statbuf: Stat buffer (populated)
 *
 * Simulates symlink target owned by non-root user (unsafe).
 *
 * Return: 0 (success)
 */
static int mock_stat_non_root_dir(const char *pathname, struct stat *statbuf) {
  (void)pathname;
  statbuf->st_uid = 1000;
  statbuf->st_mode = S_IFDIR | 0755;
  return 0;
}

#pragma GCC diagnostic pop
#endif /* TEST_HELPER_MOCK_STAT_H */
