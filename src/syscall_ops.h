/**
 * syscall_ops.h - System call abstraction layer for dependency injection
 *
 * WHY THIS EXISTS:
 * Unit testing code that makes system calls is difficult because:
 * - Tests require root privileges (usermod, file ownership checks)
 * - Tests have side effects (creating users, modifying /etc files)
 * - Tests depend on system state (existing users, file permissions)
 * - Process spawning is hard to verify in tests
 *
 * This abstraction layer solves these problems by:
 * 1. Separating interface (what operations we need) from implementation
 * 2. Allowing tests to provide mock implementations without syscall privileges
 * 3. Making dependencies explicit in function signatures
 * 4. Enabling isolated testing without system resources
 *
 * PATTERN:
 * Production code uses syscall_ops_default (maps to actual system calls).
 * Test code creates custom ops structures with controlled behavior.
 * Functions receive ops as first parameter (kernel convention).
 */

#ifndef SYSCALL_OPS_H
#define SYSCALL_OPS_H

#include <dirent.h>
#include <pwd.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

/**
 * struct syscall_ops - Operations structure for system call abstraction
 *
 * Function pointer table that wraps all external system dependencies.
 * Follows the Linux kernel pattern of embedding operations in a structure
 * (e.g., struct file_operations, struct inode_operations).
 *
 * WHY FUNCTION POINTERS:
 * - Type-safe: compiler verifies signatures match POSIX prototypes
 * - Runtime swappable: same binary can use different implementations
 * - Thread-safe: no global state, each context gets its own ops
 * - Explicit: dependencies are visible in function signatures
 *
 * SIGNATURE MATCHING:
 * All function pointers match their POSIX/libc prototypes exactly.
 * This ensures drop-in compatibility and correct calling conventions.
 *
 * USAGE PATTERN:
 * Pass as first parameter (like kernel "ops" convention):
 *   int some_function(const struct syscall_ops *ops, ...)
 *
 * Access members via pointer:
 *   ops->posix_spawn(...)
 *   ops->getpwuid(uid)
 *   ops->open(path, flags)
 */
struct syscall_ops {
  /*
   * File operations
   *
   * WHY WE NEED THESE:
   * Configuration files must be validated for security (root-owned,
   * not world-writable). Tests need to simulate different file states
   * without creating actual filesystem entries with specific permissions.
   */
  int (*open)(const char *pathname, int flags, ...);
  int (*close)(int fd);
  int (*stat)(const char *pathname, struct stat *buf);
  int (*fstat)(int fd, struct stat *statbuf);
  int (*lstat)(const char *pathname, struct stat *statbuf);
  FILE *(*fdopen)(int fd, const char *mode);
  int (*fclose)(FILE *stream);
  char *(*fgets)(char *str, int n, FILE *stream);
  int (*scandir)(const char *dirp, struct dirent ***namelist,
                 int (*filter)(const struct dirent *),
                 int (*compar)(const struct dirent **, const struct dirent **));

  /*
   * User database operations
   *
   * WHY WE NEED THESE:
   * Must resolve usernames to UIDs and vice versa. Production reads from
   * /etc/passwd + NSS. Tests provide controlled user database without
   * requiring actual system users.
   *
   * THREAD SAFETY:
   * getpwnam_r is the reentrant version (vs getpwnam).
   * getpwuid is non-reentrant but simple for read-only access.
   */
  struct passwd *(*getpwuid)(uid_t uid);
  int (*getpwnam_r)(const char *name, struct passwd *pwd, char *buf,
                    size_t buflen, struct passwd **result);

  /*
   * Process management (using posix_spawn)
   *
   * WHY WE NEED THESE:
   * Must invoke usermod(8) and getsubids(1) as child processes.
   * Tests need to verify command construction and argument passing
   * without actually executing privileged commands.
   *
   * POSIX_SPAWN ADVANTAGES:
   * - Simpler than fork/exec (single function call)
   * - More efficient on some systems (no full address space copy)
   * - Built-in file action support (redirect stdin/stdout/stderr)
   * - Thread-safe by design
   *
   * SECURITY NOTE:
   * posix_spawn() takes absolute path (no PATH lookup).
   * File actions close/redirect stdin to prevent TTY interaction.
   * Exit codes carefully checked for error conditions.
   */
  int (*posix_spawn)(pid_t *restrict pid, const char *restrict path,
                     const posix_spawn_file_actions_t *file_actions,
                     const posix_spawnattr_t *restrict attrp,
                     char *const argv[restrict], char *const envp[restrict]);
  int (*posix_spawn_file_actions_init)(
      posix_spawn_file_actions_t *file_actions);
  int (*posix_spawn_file_actions_destroy)(
      posix_spawn_file_actions_t *file_actions);
  int (*posix_spawn_file_actions_addopen)(
      posix_spawn_file_actions_t *restrict file_actions, int fd,
      const char *restrict path, int oflag, mode_t mode);
  pid_t (*waitpid)(pid_t pid, int *wstatus, int options);

  /*
   * Memory management
   *
   * WHY WE NEED THESE:
   * Must ensure our memory allocation checks have tests for
   * when allocation fails.
   */
  void *(*calloc)(size_t nmemb, size_t size);
};

/**
 * syscall_ops_default - Production system call implementation
 *
 * Global constant structure containing pointers to actual POSIX system calls
 * and C library functions. Use this in production code paths.
 *
 * WHY EXTERN:
 * - Declared in header, defined in syscall_ops_default.c
 * - Single instance shared across all translation units
 * - Linker resolves references to the one definition
 *
 * WHY CONST:
 * - Read-only after initialization (security)
 * - Can be placed in .rodata segment (write-protected memory)
 * - Multiple threads can safely share (no synchronization needed)
 * - Prevents accidental modification at runtime
 *
 * PRODUCTION USAGE:
 *   resolve_user(&syscall_ops_default, username, ...);
 *   load_configuration(&syscall_ops_default, &config, ...);
 *
 * TEST USAGE (override specific operations):
 *   // Copy default, then override specific fields
 *   struct syscall_ops test_ops = syscall_ops_default;
 *   test_ops.getpwuid = mock_getpwuid;
 *   test_ops.posix_spawn = mock_posix_spawn;
 *
 *   // Use in test
 *   resolve_user(&test_ops, "testuser", ...);
 *
 * TEST ISOLATION:
 * Each test creates its own local copy of syscall_ops_default,
 * modifies only the fields it needs to mock, and passes that
 * local copy. This ensures tests don't interfere with each other.
 */
extern const struct syscall_ops syscall_ops_default;

#endif /* SYSCALL_OPS_H */
