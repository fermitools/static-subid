/**
 * validate.c - Input validation functions
 *
 * ERROR HANDLING CONTRACT:
 * All validation functions return:
 *   0 on success
 *  -1 on error
 *
 * On error:
 *  - Error message written to stderr (includes program name and context)
 *  - errno may be set if validation failed due to a system call
 *  - errno is preserved from system calls (stat, sysconf, etc.)
 *  - errno is set to EINVAL for pure validation failures (bad format, etc.)
 */

/* clang-format off */
#include "autoconf.h"
#include "static-subid.h"
#include "syscall_ops.h"
/* clang-format on */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * validate_path - Validate path for security issues
 * @path: Path to validate
 *
 * Checks for:
 * - NULL or empty path
 * - Relative path
 * - Path length exceeds PATH_MAX (compile-time constant)
 * - Path traversal attempts ("../" or "/..")
 *
 * Return: 0 if valid, -1 if invalid
 */
int validate_path(const char *path) {
  if (path == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: path is NULL\n", PROJECT_NAME);
    return -1;
  }
  if (*path == '\0') {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: path is empty\n", PROJECT_NAME);
    return -1;
  }

  /* Use PATH_MAX directly - it's a compile-time constant from limits.h */
  size_t path_len = strlen(path);
  if (path_len >= PATH_MAX) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: path exceeds PATH_MAX (%d): %s\n",
                  PROJECT_NAME, PATH_MAX, path);
    return -1;
  }

  /* absolute paths only */
  if (path[0] != '/') {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: path does not start with '/': %s\n",
                  PROJECT_NAME, path);
    return -1;
  }

  /* Check for directory traversal attempts */
  if (strstr(path, "/../") != NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: path contains traversal sequence: %s\n",
                  PROJECT_NAME, path);
    return -1;
  }

  /* Reject paths ending in "/.." */
  if (path_len >= 3 && strcmp(path + path_len - 3, "/..") == 0) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: path must not end with '/..': %s\n",
                  PROJECT_NAME, path);
    return -1;
  }

  return 0;
}

/**
 * validate_config_dir - Validate configuration directory security
 * @ops: Operations structure for system call abstraction (kernel-style ops
 * pattern)
 * @dirpath: Path to directory to validate
 * @debug: Enable debug output
 *
 * Performs security validation on configuration directory:
 * - Path validation (no traversal)
 * - Target must be a directory (follows symlinks)
 * - Must be owned by root (UID 0)
 * - Must not be world-writable (S_IWOTH)
 *
 * Uses stat() to follow symlinks and validate the final target. The path
 * may contain symlinks at any level. If the directory doesn't exist, this
 * is not an error (returns 0) - caller handles missing dirs.
 *
 * Return: 0 on success or if directory doesn't exist, -1 on security error
 */
int validate_config_dir(const struct syscall_ops *ops, const char *dirpath,
                        bool debug) {
  if (ops == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: ops is NULL\n", PROJECT_NAME);
    return -1;
  }
  if (dirpath == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: dirpath is NULL\n", PROJECT_NAME);
    return -1;
  }

  if (validate_path(dirpath) != 0) {
    /* errno already set by validate_path */
    return -1;
  }

  struct stat st = {0};

  /* Use stat to follow symlinks and check the final target */
  if (ops->stat(dirpath, &st) != 0) {
    if (errno == ENOENT) {
      /* Directory doesn't exist - not an error, caller will handle */
      if (debug) {
        (void)fprintf(stderr,
                      "%s: debug: config directory does not exist: %s\n",
                      PROJECT_NAME, dirpath);
      }
      return 0;
    }
    /* errno already set by stat */
    (void)fprintf(stderr, "%s: error: cannot stat config directory %s: %s\n",
                  PROJECT_NAME, dirpath, strerror(errno));
    return -1;
  }

  /* Must be a directory */
  if (!S_ISDIR(st.st_mode)) {
    errno = ENOTDIR;
    (void)fprintf(
        stderr,
        "%s: error: config path %s is not a directory (or link to one)\n",
        PROJECT_NAME, dirpath);
    return -1;
  }

  /* Must be owned by root (UID 0) */
  if (st.st_uid != 0) {
    errno = EPERM;
    (void)fprintf(stderr,
                  "%s: error: config directory %s not owned by root (owned by "
                  "UID %u)\n",
                  PROJECT_NAME, dirpath, st.st_uid);
    return -1;
  }

  /* Must not be world-writable */
  if (st.st_mode & S_IWOTH) {
    errno = EPERM;
    (void)fprintf(
        stderr,
        "%s: error: config directory %s is world-writable (mode %04o)\n",
        PROJECT_NAME, dirpath, st.st_mode & 07777);
    return -1;
  }

  return 0;
}

/**
 * is_valid_username_char - Check if character is valid at given position
 * @c: Character to check
 * @pos: Position in username (0-based)
 * @len: Total length of username
 *
 * Return: true if valid, false if invalid
 */
static inline bool is_valid_username_char(char c, size_t pos, size_t len) {
  /* First character: must be lowercase letter or underscore */
  if (pos == 0) {
    return islower((unsigned char)c) || c == '_';
  }

  /* Last character: may be $ in addition to other valid chars */
  if (pos == len - 1 && c == '$') {
    return true;
  }

  /* Any position: lowercase, digit, dot, underscore, hyphen */
  return islower((unsigned char)c) || isdigit((unsigned char)c) || c == '.' ||
         c == '_' || c == '-';
}

/**
 * validate_username - Validate username per shadow-utils rules
 * @username: Username to validate
 *
 * Validates according to useradd(8) restrictions:
 * - Must start with lowercase letter or underscore
 * - May contain lowercase, digits, underscore, hyphen, dollar
 * - Cannot end with hyphen
 * - Cannot contain path traversal
 * - Cannot be "." or ".."
 * - Must not exceed LOGIN_NAME_MAX (runtime limit)
 *
 * Return: 0 if valid, -1 if invalid
 */
int validate_username(const char *username) {
  if (username == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: username is NULL\n", PROJECT_NAME);
    return -1;
  }
  if (*username == '\0') {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: username is empty\n", PROJECT_NAME);
    return -1;
  }

  /* Query runtime limit for username length (for validation only, not
   * allocation) */
  long name_max = sysconf(_SC_LOGIN_NAME_MAX);
  // LCOV_EXCL_START
  if (name_max == -1) {
    /*
     * Your system is too messed up to run on with any confidence
     */
    return -1;
  }
  // LCOV_EXCL_STOP

  size_t len = strlen(username);
  if (len >= (size_t)name_max) {
    errno = ENAMETOOLONG;
    (void)fprintf(stderr,
                  "%s: error: username exceeds LOGIN_NAME_MAX (%ld): %s\n",
                  PROJECT_NAME, name_max, username);
    return -1;
  }

  /* Check for path traversal attempts */
  if (strstr(username, "/") != NULL) {
    errno = EINVAL;
    (void)fprintf(stderr,
                  "%s: error: username contains traversal sequence: %s\n",
                  PROJECT_NAME, username);
    return -1;
  }

  /* Check for command injection attempts */
  if (strstr(username, ";") != NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: username contains ';': %s\n",
                  PROJECT_NAME, username);
    return -1;
  }

  /* Validate each character using helper function */
  for (size_t i = 0; i < len; i++) {
    if (!is_valid_username_char(username[i], i, len)) {
      errno = EINVAL;
      (void)fprintf(stderr,
                    "%s: error: invalid character '%c' at position %zu in "
                    "username: %s\n",
                    PROJECT_NAME, username[i], i, username);
      return -1;
    }
  }

  /* Username cannot end with hyphen (historical restriction) */
  if (username[len - 1] == '-') {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: username cannot end with hyphen: %s\n",
                  PROJECT_NAME, username);
    return -1;
  }

  return 0;
}

/**
 * parse_bool - Parse boolean value from string
 * @str: String to parse
 * @default_val: Default value if string is NULL or unrecognized
 *
 * Accepts: yes/true/1 (true), no/false/0 (false)
 * Case-insensitive comparison.
 *
 * Return: Parsed boolean value or default_val
 */
bool parse_bool(const char *str, bool default_val) {
  if (str == NULL) {
    return default_val;
  }

  if (strcasecmp(str, "yes") == 0) {
    return true;
  }
  if (strcasecmp(str, "true") == 0) {
    return true;
  }
  if (strcmp(str, "1") == 0) {
    return true;
  }

  if (strcasecmp(str, "no") == 0) {
    return false;
  }
  if (strcasecmp(str, "false") == 0) {
    return false;
  }
  if (strcmp(str, "0") == 0) {
    return false;
  }

  return default_val;
}

/**
 * parse_uint32_strict - Parse string to uint32_t with strict validation
 * @str: String to parse
 * @result: Pointer to store result (zero on error)
 *
 * Parses decimal unsigned integer with strict validation:
 * - Only digits allowed (no whitespace, signs, etc.)
 * - Trim leading zeros except "0" itself (prevents octal confusion)
 * - Must fit in uint32_t (0 to 4,294,967,295)
 * - Uses strtoull for standards-compliant parsing
 *
 * This strict validation prevents configuration errors like:
 * - "0123" being interpreted as octal (83 decimal)
 * - "123abc" being partially parsed as 123
 * - " 123" with leading whitespace
 *
 * Return: 0 on success, -1 on error
 */
int parse_uint32_strict(const char *str, uint32_t *result) {
  if (str == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (result == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (*str == '\0') {
    errno = EINVAL;
    return -1;
  }

  /* Reject leading signs or whitespace to prevent confusion */
  if (*str == '-') {
    errno = EINVAL;
    return -1;
  }
  if (*str == '+') {
    errno = EINVAL;
    return -1;
  }
  if (isspace((unsigned char)*str)) {
    errno = EINVAL;
    return -1;
  }

  /* Skip leading zeros (except "0" by itself) */
  while (*str == '0' && *(str + 1) != '\0') {
    str++;
  }

  /* Verify all characters are digits before parsing */
  for (const char *p = str; *p != '\0'; p++) {
    if (!isdigit((unsigned char)*p)) {
      errno = EINVAL;
      return -1;
    }
  }

  /* We got far enough we should set a safe value */
  *result = (uint32_t)0;

  /* Parse with overflow detection */
  errno = 0;
  char *endptr = NULL;
  unsigned long long val = strtoull(str, &endptr, 10);
  if (errno == ERANGE) {
    return -1;
  }
  if (val > UINT32_MAX_VAL) {
    errno = ERANGE;
    return -1;
  }

  /* Verify entire string was consumed */
  // LCOV_EXCL_START
  if (endptr == NULL || *endptr != '\0') {
    /* should be impossible to get here */
    errno = EINVAL;
    return -1;
  }
  // LCOV_EXCL_STOP

  *result = (uint32_t)val;
  return 0;
}

/**
 * validate_uid_range - Check UID is within configured allowed range
 * @uid: UID to validate
 * @config: Configuration with UID range
 *
 * Verifies uid_min <= UID <= uid_max to ensure we only assign
 * subordinate IDs to regular users, not system accounts.
 *
 * Return: 0 if in range, -1 if outside range
 */
int validate_uid_range(uint32_t uid, const config_t *config) {
  if (config == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: config is NULL\n", PROJECT_NAME);
    return -1;
  }

  if (uid < config->uid_min) {
    errno = ERANGE;
    (void)fprintf(stderr, "%s: error: UID %u outside allowed range %u-%u\n",
                  PROJECT_NAME, uid, config->uid_min, config->uid_max);
    return -1;
  }
  if (uid > config->uid_max) {
    errno = ERANGE;
    (void)fprintf(stderr, "%s: error: UID %u outside allowed range %u-%u\n",
                  PROJECT_NAME, uid, config->uid_min, config->uid_max);
    return -1;
  }

  return 0;
}

/**
 * validate_uid_subid_overlap - Ensure UID doesn't overlap subordinate range
 * @uid: UID to check
 * @subid_cfg: Subordinate ID configuration
 *
 * Verifies the primary UID doesn't fall within the subordinate ID range.
 * This prevents namespace confusion where a user's primary UID could
 * conflict with another user's subordinate IDs.
 *
 * Example problem without this check:
 * - User A (UID 1000) gets subuid range 100000-165535
 * - User B has UID 100000 (overlaps A's subordinate range)
 * - Inside A's container, files owned by subuid 100000 map to user B!
 *
 * Return: 0 if no overlap, -1 if overlap detected
 */
int validate_uid_subid_overlap(uint32_t uid, const subid_config_t *subid_cfg) {
  if (subid_cfg == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: subid_cfg is NULL\n", PROJECT_NAME);
    return -1;
  }

  if (uid >= subid_cfg->min_val) {
    if (uid <= subid_cfg->max_val) {
      errno = EINVAL;
      (void)fprintf(stderr,
                    "%s: error: UID %u overlaps subordinate ID range %u-%u\n",
                    PROJECT_NAME, uid, subid_cfg->min_val, subid_cfg->max_val);
      return -1;
    }
  }

  return 0;
}
