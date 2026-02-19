/**
 * subid.c - Subordinate ID operations
 */

/* clang-format off */
#include "autoconf.h"
#include "static-subid.h"
#include "syscall_ops.h"
/* clang-format on */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * check_subid_exists - Check if user already has subordinate IDs assigned
 * @ops: Operations structure for system call abstraction (kernel-style ops
 * pattern)
 * @username: Username to check
 * @mode: SUBUID or SUBGID
 * @debug: Enable debug output
 *
 * Uses getsubids(1) to check for existing assignments. This checks both
 * /etc/subuid (or /etc/subgid) and any NSS sources configured on the system.
 *
 * Uses exit code to determine if ranges exist:
 * - Exit 0: Ranges exist
 * - Exit 1: Ranges do not exist
 * - Other: Error
 *
 * Return: 1 if exists, 0 if not exists, -1 on error
 */
int check_subid_exists(const struct syscall_ops *ops, const char *username,
                       subid_mode_t mode, bool debug) {
  if (ops == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: ops is NULL\n", PROJECT_NAME);
    return -1;
  }
  if (username == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: username is NULL\n", PROJECT_NAME);
    return -1;
  }

  const char *mode_str = NULL;
  if (mode == SUBUID) {
    mode_str = "subuid";
  } else if (mode == SUBGID) {
    mode_str = "subgid";
  } else {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: invalid mode\n", PROJECT_NAME);
    return -1;
  }

  if (debug) {
    (void)fprintf(stderr, "%s: debug: checking if %s exists for %s\n",
                  PROJECT_NAME, mode_str, username);
  }

  /* Build argument list for getsubids */
  /*
   * POSIX API LIMITATION: posix_spawn takes char *const argv[] instead of
   * const char *const argv[] for historical reasons. We must cast away const
   * even though posix_spawn won't modify the strings. Disable cast-qual
   * warning for this section.
   *
   * Yes, this is ugly.
   */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
  char *argv[4] = { NULL, NULL, NULL, NULL };
  argv[0] = (char *)"getsubids";
  if (mode == SUBGID) {
    argv[1] = (char *)"-g";
    argv[2] = (char *)username;
    argv[3] = NULL;
  } else {
    argv[1] = (char *)username;
    argv[2] = NULL;
  }
#pragma GCC diagnostic pop

  /* Set up file actions to redirect stdin and stdout to /dev/null */
  posix_spawn_file_actions_t actions;
  int ret = ops->posix_spawn_file_actions_init(&actions);
  if (ret != 0) {
    (void)fprintf(stderr,
                  "%s: error: posix_spawn_file_actions_init failed: %s\n",
                  PROJECT_NAME, strerror(ret));
    return -1;
  }

  /*
   * Redirect stdin, stdout, and stderr to /dev/null, return code is our signal
   */
  ret = ops->posix_spawn_file_actions_addopen(&actions, STDIN_FILENO,
                                              "/dev/null", O_RDONLY, 0);
  if (ret != 0) {
    ops->posix_spawn_file_actions_destroy(&actions);
    (void)fprintf(stderr,
                  "%s: error: posix_spawn_file_actions_addopen failed: %s\n",
                  PROJECT_NAME, strerror(ret));
    return -1;
  }

  if (!debug) {
    ret = ops->posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO,
                                                "/dev/null", O_WRONLY, 0);
    if (ret != 0) {
      ops->posix_spawn_file_actions_destroy(&actions);
      (void)fprintf(stderr,
                    "%s: error: posix_spawn_file_actions_addopen failed: %s\n",
                    PROJECT_NAME, strerror(ret));
      return -1;
    }

    ret = ops->posix_spawn_file_actions_addopen(&actions, STDERR_FILENO,
                                                "/dev/null", O_WRONLY, 0);
    if (ret != 0) {
      ops->posix_spawn_file_actions_destroy(&actions);
      (void)fprintf(stderr,
                    "%s: error: posix_spawn_file_actions_addopen failed: %s\n",
                    PROJECT_NAME, strerror(ret));
      return -1;
    }
  }

  /* Spawn the child process */
  pid_t pid;
  ret = ops->posix_spawn(&pid, GETSUBIDS_PATH, &actions, NULL, argv, environ);
  ops->posix_spawn_file_actions_destroy(&actions);

  if (ret != 0) {
    (void)fprintf(stderr, "%s: error: posix_spawn failed: %s\n", PROJECT_NAME,
                  strerror(ret));
    return -1;
  }

  /* Wait for child and check exit code */
  int status = 0;
  if (ops->waitpid(pid, &status, 0) < 0) {
    (void)fprintf(stderr, "%s: error: waitpid() failed: %s\n", PROJECT_NAME,
                  strerror(errno));
    return -1;
  }

  if (!WIFEXITED(status)) {
    (void)fprintf(stderr, "%s: error: getsubids terminated abnormally\n",
                  PROJECT_NAME);
    return -1;
  }

  int exit_code = WEXITSTATUS(status);

  if (exit_code == 0) {
    if (debug) {
      (void)fprintf(stderr, "%s: debug: %s exists for %s\n", PROJECT_NAME,
                    mode_str, username);
    }
    return 1; /* Subids exist */
  } else if (exit_code == 1) {
    if (debug) {
      (void)fprintf(stderr, "%s: debug: %s does not exist for %s\n",
                    PROJECT_NAME, mode_str, username);
    }
    return 0; /* Subids don't exist */
  } else {
    /* Other exit code indicates error */
    (void)fprintf(stderr, "%s: error: getsubids failed with exit code %d\n",
                  PROJECT_NAME, exit_code);
    return -1;
  }
}

/**
 * set_subid_range - Assign subordinate ID range to user using usermod
 * @ops: Operations structure for system call abstraction (kernel-style ops
 * pattern)
 * @username: Username to assign range to
 * @mode: SUBUID or SUBGID
 * @start: Start of subordinate ID range
 * @count: Number of IDs in range
 * @noop: If true, print command but don't execute
 * @debug: If true, print debug messages to stderr
 *
 * Uses usermod(8) with --add-subuids or --add-subgids to assign the
 * specified subordinate ID range. Converts range from (start, count)
 * format to "start-end" format required by usermod.
 *
 * WARNING: Range validation (start < end, no overflow) must be
 * completed by calc_subid_range before calling this function.
 *
 * Note:
 * - Closes stdin in child to prevent TTY interaction
 * - Preserves stdout and stderr so usermod output/errors are visible
 * - Uses absolute path to avoid PATH injection
 * - Validates usermod exit code and reports errors clearly
 *
 * Note: usermod is smart enough to not add subids for a user
 * if that user already has that exact subid set. This does
 * not check for overlap with either this user or any other.
 *
 * Return: 0 on success, -1 on error
 */
int set_subid_range(const struct syscall_ops *ops, const char *username,
                    subid_mode_t mode, uint32_t start, uint32_t count,
                    bool noop, bool debug) {
  if (ops == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: ops is NULL\n", PROJECT_NAME);
    return -1;
  }
  if (username == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: username is NULL\n", PROJECT_NAME);
    return -1;
  }

  if (count == 0) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: count cannot be zero\n", PROJECT_NAME);
    return -1;
  }

  /*
   * Build range string in "start-end" format for usermod
   * end_id = start + count - 1
   *
   * Note: Overflow must have been checked by calc_subid_range.
   *       This calculation should never overflow if that function ran.
   */
  uint32_t end_id = start + count - 1;

  /* Sanity check: verify start < end (should be guaranteed by caller) */
  if (end_id < start) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: invalid range [%u, %u] - end < start\n",
                  PROJECT_NAME, start, end_id);
    return -1;
  }

  char range_str[RANGE_STR_MAX] = {0};
  int ret = snprintf(range_str, sizeof(range_str), "%u-%u", start, end_id);
  // LCOV_EXCL_START
  if (ret < 0 || (size_t)ret >= sizeof(range_str)) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: range string formatting failed\n",
                  PROJECT_NAME);
    return -1;
  }
  // LCOV_EXCL_STOP

  const char *flag = NULL;
  const char *mode_str = NULL;
  if (mode == SUBUID) {
    flag = "--add-subuids";
    mode_str = "subuid";
  } else if (mode == SUBGID) {
    flag = "--add-subgids";
    mode_str = "subgid";
  } else {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: invalid mode\n", PROJECT_NAME);
    return -1;
  }

  if (debug) {
    (void)fprintf(stderr,
                  "%s: debug: assigning %s range %s (%u:%u) to user %s\n",
                  PROJECT_NAME, mode_str, range_str, start, count, username);
  }

  if (noop) {
    (void)printf("%s: noop: would execute: %s %s %s %s\n", PROJECT_NAME,
                 USERMOD_PATH, flag, range_str, username);
    return 0;
  }

  if (debug) {
    (void)fprintf(stderr, "%s: debug: will execute: %s %s %s %s\n",
                  PROJECT_NAME, USERMOD_PATH, flag, range_str, username);
  }

  /* Build argument list for usermod */
  /*
   * POSIX API LIMITATION: posix_spawn takes char *const argv[] instead of
   * const char *const argv[] for historical reasons. We must cast away const
   * even though posix_spawn won't modify the strings. Disable cast-qual
   * warning for this section.
   *
   * Yes, this is ugly.
   */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
  char *argv[] = {(char *)"usermod", (char *)flag, (char *)range_str,
                  (char *)username, NULL};
#pragma GCC diagnostic pop

  /* Set up file actions - close stdin, keep stdout/stderr */
  posix_spawn_file_actions_t actions;
  ret = ops->posix_spawn_file_actions_init(&actions);
  if (ret != 0) {
    (void)fprintf(stderr,
                  "%s: error: posix_spawn_file_actions_init failed: %s\n",
                  PROJECT_NAME, strerror(ret));
    return -1;
  }

  ret = ops->posix_spawn_file_actions_addopen(&actions, STDIN_FILENO,
                                              "/dev/null", O_RDONLY, 0);
  if (ret != 0) {
    ops->posix_spawn_file_actions_destroy(&actions);
    (void)fprintf(stderr,
                  "%s: error: posix_spawn_file_actions_addopen failed: %s\n",
                  PROJECT_NAME, strerror(ret));
    return -1;
  }

  /* Spawn the child process */
  pid_t pid;
  ret = ops->posix_spawn(&pid, USERMOD_PATH, &actions, NULL, argv, environ);
  ops->posix_spawn_file_actions_destroy(&actions);

  if (ret != 0) {
    (void)fprintf(stderr, "%s: error: posix_spawn failed: %s\n", PROJECT_NAME,
                  strerror(ret));
    return -1;
  }

  /* Wait for usermod to complete */
  int status = 0;
  if (ops->waitpid(pid, &status, 0) < 0) {
    (void)fprintf(stderr, "%s: error: waitpid() failed: %s\n", PROJECT_NAME,
                  strerror(errno));
    return -1;
  }

  if (WIFSIGNALED(status)) {
    (void)fprintf(stderr, "%s: error: usermod terminated by signal %d\n",
                  PROJECT_NAME, WTERMSIG(status));
    return -1;
  }

  // LCOV_EXCL_START
  if (!WIFEXITED(status)) {
    (void)fprintf(stderr, "%s: error: usermod terminated abnormally\n",
                  PROJECT_NAME);
    return -1;
  }
  // LCOV_EXCL_STOP

  int exit_code = WEXITSTATUS(status);

  if (exit_code == 0) {
    if (debug) {
      (void)fprintf(stderr, "%s: debug: successfully assigned %s range to %s\n",
                    PROJECT_NAME, mode_str, username);
    }
    return 0; /* Success */
  } else {
    /* usermod failed - print exit code for debugging */
    (void)fprintf(stderr, "%s: error: usermod failed with exit code %d\n",
                  PROJECT_NAME, exit_code);
    return -1;
  }
}
