/**
 * syscall_ops_default.c - Production system call implementation
 *
 * Provides the canonical implementation that maps function pointers
 * directly to POSIX system calls and C library functions.
 *
 * WHY THIS FILE EXISTS:
 * Separates the abstract interface (syscall_ops.h) from the concrete
 * implementation. This allows:
 * - Production code to link against real system calls
 * - Test code to link against mock implementations
 * - Clear separation between interface and implementation
 *
 * MODIFICATION:
 * When adding new system call dependencies:
 * 1. Add function pointer to struct syscall_ops (syscall_ops.h)
 * 2. Add mapping here in syscall_ops_default
 * 3. Update test mocks as needed
 */

#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "syscall_ops.h"

/**
 * syscall_ops_default - Global production syscall implementation
 *
 * Maps each function pointer in the ops structure to its corresponding
 * POSIX/libc function.
 *
 * INITIALIZATION ORDER:
 * Uses C99 designated initializers (.field = value) which:
 * - Make order independent (can add/remove/reorder freely)
 * - Are self-documenting (field name visible at each assignment)
 * - Catch typos at compile time (unknown field = error)
 * - Allow partial initialization (unmapped fields = NULL)
 *
 * CONST CORRECTNESS:
 * The structure itself is const (immutable after initialization).
 * The function pointers point to system calls (not const, they're code).
 * This is correct: we can't change the pointers, but we can call the
 * functions.
 *
 * STORAGE LINKAGE:
 * - extern in header makes it visible across translation units
 * - const makes it immutable (placed in .rodata, write-protected)
 * - Single definition here (not in header, avoids multiple definition errors)
 * - Production code: use &syscall_ops_default directly
 * - Test code: copy to local variable, override specific fields
 */
const struct syscall_ops syscall_ops_default = {
    /*
     * File operations
     * Direct mapping to POSIX file I/O functions
     */
    .open = open,
    .close = close,
    .stat = stat,
    .fstat = fstat,
    .lstat = lstat,
    .fdopen = fdopen,
    .fclose = fclose,
    .fgets = fgets,
    .scandir = scandir,

    /*
     * User database operations
     * Maps to NSS-backed user lookup functions
     */
    .getpwuid = getpwuid,
    .getpwnam_r = getpwnam_r,

    /*
     * Process management (using posix_spawn)
     * Direct mapping to POSIX spawn functions and wait
     */
    .posix_spawn = posix_spawn,
    .posix_spawn_file_actions_init = posix_spawn_file_actions_init,
    .posix_spawn_file_actions_destroy = posix_spawn_file_actions_destroy,
    .posix_spawn_file_actions_addopen = posix_spawn_file_actions_addopen,
    .waitpid = waitpid,

    /*
     * Memory allocation
     * Maps to standard C library allocator
     */
    .calloc = calloc,
};
