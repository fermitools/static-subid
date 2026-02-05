/**
 * util.c - Utility functions
 */

/* clang-format off */
#include "autoconf.h"
#include "static-subid.h"
#include "syscall_ops.h"
/* clang-format on */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Forward declarations for internal functions
 *
 * We can use nonnull on static functions because they can only be called
 * from inside here and we're careful to check the pointers in our visible
 * function(s).
 * */
static int lookup_user(const struct syscall_ops *ops, const char *username,
                       uint32_t *uid_out) __attribute__((nonnull(1, 2, 3)))
__attribute__((warn_unused_result));

/**
 * resolve_user - Resolve user argument to UID and username
 * @ops: Operations structure providing system call interface
 *       (use &syscall_ops_real in production, mock ops in tests)
 * @user_arg: User argument (username or UID string)
 * @uid: Pointer to store resolved UID
 * @username: Buffer to store resolved username
 * @username_size: Size of username buffer
 * @debug: Enable debug output
 *
 * Tries to parse user_arg as UID first. If that succeeds, looks up
 * username for that UID. Otherwise, treats user_arg as username and
 * looks up the UID.
 *
 * Return: 0 on success with uid and username populated, -1 on error
 */
int resolve_user(const struct syscall_ops *ops, const char *user_arg,
                 uint32_t *uid, char *username, size_t username_size,
                 bool debug) {
  if (ops == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: ops is NULL\n", PROJECT_NAME);
    return -1;
  }
  if (user_arg == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: user_arg is NULL\n", PROJECT_NAME);
    return -1;
  }
  if (uid == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: uid is NULL\n", PROJECT_NAME);
    return -1;
  }
  if (username == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: username is NULL\n", PROJECT_NAME);
    return -1;
  }

  /* for sanity, init everything to 0/NULL */
  *uid = 0;
  memset(username, 0, username_size);
  uint32_t parsed_uid = 0;

  if (debug) {
    (void)fprintf(stderr, "%s: debug: resolving user argument: %s\n",
                  PROJECT_NAME, user_arg);
  }

  /* Try to parse as UID first */
  if (parse_uint32_strict(user_arg, &parsed_uid) == 0) {
    if (debug) {
      (void)fprintf(stderr, "%s: debug: parsed as UID: %u\n", PROJECT_NAME,
                    parsed_uid);
    }

    /* Look up username for this UID */
    struct passwd *pwd = ops->getpwuid(parsed_uid);
    if (pwd == NULL) {
      errno = ENOENT;
      (void)fprintf(stderr, "%s: error: no user found with UID %u\n",
                    PROJECT_NAME, parsed_uid);
      return -1;
    }

    /* Defensive check: pwd->pw_name must not be NULL */
    if (pwd->pw_name == NULL) {
      errno = EINVAL;
      (void)fprintf(stderr, "%s: error: user lookup returned NULL username\n",
                    PROJECT_NAME);
      return -1;
    }

    /* Copy username using snprintf for safety */
    int ret = snprintf(username, username_size, "%s", pwd->pw_name);
    if (ret < 0 || (size_t)ret >= username_size) {
      errno = ENAMETOOLONG;
      (void)fprintf(stderr, "%s: error: username %s too long\n", PROJECT_NAME,
                    pwd->pw_name);
      return -1;
    }

    *uid = parsed_uid;

    if (debug) {
      (void)fprintf(stderr, "%s: debug: resolved to username: %s\n",
                    PROJECT_NAME, username);
    }

    return 0;
  }

  /* Not a UID - treat as username */
  if (debug) {
    (void)fprintf(stderr, "%s: debug: treating as username\n", PROJECT_NAME);
  }

  /* Validate username before attempting lookup - garbage can be dropped */
  if (validate_username(user_arg) != 0) {
    /* errno already set by validate_username */
    return -1;
  }

  /* Look up UID for this username */
  if (lookup_user(ops, user_arg, uid) != 0) {
    /* errno already set by lookup_user */
    return -1;
  }

  /* Copy username using snprintf */
  int ret = snprintf(username, username_size, "%s", user_arg);
  if (ret < 0 || (size_t)ret >= username_size) {
    errno = ENAMETOOLONG;
    (void)fprintf(stderr, "%s: error: username %s too long\n", PROJECT_NAME,
                  user_arg);
    return -1;
  }

  if (debug) {
    (void)fprintf(stderr, "%s: debug: resolved to UID: %u\n", PROJECT_NAME,
                  *uid);
  }

  return 0;
}

/**
 * lookup_user - Look up UID for username using getpwnam_r
 * @ops: Operations structure (needed for getpwnam_r and calloc/free)
 * @username: Username to look up
 * @uid_out: Pointer to store found UID
 *
 * Performs thread-safe username lookup using getpwnam_r(3).
 * Buffer size is determined at runtime via sysconf() and allocated
 * on the heap (not stack, since size is runtime-determined).
 *
 * Return: 0 on success, -1 if user not found or error
 */
static int lookup_user(const struct syscall_ops *ops, const char *username,
                       uint32_t *uid_out) {
  *uid_out = 0;

  /* Query recommended buffer size at runtime */
  long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
  // LCOV_EXCL_START
  if (bufsize == -1) {
    /*
     * Your system is too messed up to run on with any confidence
     */
    errno = ENOSYS;
    (void)fprintf(stderr, "%s: error: sysconf(_SC_GETPW_R_SIZE_MAX) failed\n",
                  PROJECT_NAME);
    return -1;
  }
  // LCOV_EXCL_STOP

  /* Allocate on heap since size is runtime-determined - use calloc to zero */
  char *buf = ops->calloc(1, (size_t)bufsize);
  if (buf == NULL) {
    errno = ENOMEM;
    (void)fprintf(stderr, "%s: error: memory allocation failed\n",
                  PROJECT_NAME);
    return -1;
  }

  struct passwd pwd = {0};
  struct passwd *result = NULL;

  int ret = ops->getpwnam_r(username, &pwd, buf, (size_t)bufsize, &result);

  if (ret != 0) {
    errno = ret;
    (void)fprintf(stderr, "%s: error: failed to look up user '%s': %s\n",
                  PROJECT_NAME, username, strerror(ret));
    (void)free(buf);
    return -1;
  }

  if (result == NULL) {
    errno = ENOENT;
    (void)fprintf(stderr, "%s: error: user not found: %s\n", PROJECT_NAME,
                  username);
    (void)free(buf);
    return -1;
  }

  /* Defensive check: pwd.pw_name must not be NULL */
  if (pwd.pw_name == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: user lookup returned NULL username\n",
                  PROJECT_NAME);
    (void)free(buf);
    return -1;
  }

  *uid_out = pwd.pw_uid;
  (void)free(buf);
  return 0;
}

/**
 * normalize_config_line - Strip comments and trim whitespace from config line
 * @line: Line buffer to normalize (modified in-place)
 *
 * Processing order:
 * 1. Strip comments (# to end of line)
 * 2. Trim trailing whitespace
 * 3. Trim leading whitespace
 *
 * This ordering ensures "KEY VALUE # comment" is handled correctly.
 *
 * Return: Pointer to first non-whitespace character, or empty string if blank
 */
char *normalize_config_line(char *line) {
  if (line == NULL) {
    return NULL;
  }

  /* Strip comments first so "KEY VALUE # comment" works correctly */
  char *comment = strchr(line, '#');
  if (comment != NULL) {
    *comment = '\0';
  }

  /* Trim trailing whitespace */
  char *end = line + strlen(line);
  while (end > line && isspace((unsigned char)end[-1])) {
    *--end = '\0';
  }

  /* Trim leading whitespace and return pointer to first non-space char */
  char *start = line;
  while (*start && isspace((unsigned char)*start)) {
    start++;
  }

  return start;
}

/**
 * filter_conf_files - Filter function for scandir() to select .conf files
 * @entry: Directory entry to check
 *
 * Selects only non-hidden files ending in .conf.
 *
 * Return: 1 to include entry, 0 to skip
 */
int filter_conf_files(const struct dirent *entry) {
  if (entry == NULL) {
    return 0;
  }

  const char *name = entry->d_name;

  /* Reject any dotfile (includes "." and "..") */
  if (name[0] == '.') {
    return 0;
  }

  /* Defensive check: d_name should never contain '/' */
  if (strchr(name, '/') != NULL) {
    return 0;
  }

  /* Only accept files ending with ".conf" */
  size_t len = strlen(name);
  if (len > 5 && strcmp(name + len - 5, ".conf") == 0) {
    return 1;
  }

  return 0;
}
