/**
 * config.c - Configuration file loading and parsing
 */

/* clang-format off */
#include "autoconf.h"
#include "static-subid.h"
#include "syscall_ops.h"
/* clang-format on */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/**
 * Forward declarations for internal functions
 *
 * We can use nonnull on static functions because they can only be called
 * from inside here and we're careful to check the pointers in our visible
 * function(s).
 *
 */
static FILE *safe_open_config(const struct syscall_ops *ops,
                              const char *filepath, bool debug)
    __attribute__((nonnull(1, 2))) __attribute__((warn_unused_result));
static int load_config_from_dir(const struct syscall_ops *ops, config_t *config,
                                const char *dirpath, bool debug)
    __attribute__((nonnull(1, 2, 3))) __attribute__((warn_unused_result));
static void apply_config_value(const char *key, const char *value,
                               config_t *config, const char *filepath)
    __attribute__((nonnull(1, 2, 3)));
static void parse_config_file(const struct syscall_ops *ops,
                              const char *filepath, config_t *config,
                              bool debug) __attribute__((nonnull(1, 2, 3)));

/**
 * safe_open_config - Safely open configuration file with security checks
 * @ops: Operations structure for system call abstraction (kernel-style ops
 * pattern)
 * @filepath: Path to configuration file (may be a symlink)
 * @debug: Enable debug output
 *
 * Performs security validation:
 * 1. Path validation (no traversal)
 * 2. Open file (follows symlinks if present)
 * 3. Target must be regular file (not device, directory, etc.)
 * 4. Target must be owned by root (UID 0)
 * 5. Target must not be world-writable
 *
 * Follows symlinks during open(), then performs all security checks on the
 * opened file descriptor via fstat() to verify the target file meets security
 * requirements. This eliminates TOCTOU races since checks are performed on
 * the already-opened fd. Finally converts fd to FILE* via fdopen() for use
 * with fgets().
 *
 * Return: FILE pointer on success, NULL on error or non-existent file
 */
static FILE *safe_open_config(const struct syscall_ops *ops,
                              const char *filepath, bool debug) {
  // LCOV_EXCL_START
  if (validate_path(filepath) != 0) {
    /* should be impossible to get here */
    errno = EINVAL;
    return NULL;
  }
  // LCOV_EXCL_STOP

  if (debug) {
    (void)fprintf(stderr, "%s: debug: opening config file: %s\n", PROJECT_NAME,
                  filepath);
  }

  /*
   * Open file, following symlinks in path and final component
   * fstat() on the opened fd checks security properties of the target,
   * eliminating TOCTOU races
   */
  int fd = ops->open(filepath, O_RDONLY);
  if (fd < 0) {
    if (errno != ENOENT) {
      (void)fprintf(stderr, "%s: error: cannot open %s: %s\n", PROJECT_NAME,
                    filepath, strerror(errno));
      return NULL;
    }

    /* Not an error: file doesn't exist (root might create it later) */
    if (debug) {
      (void)fprintf(stderr, "%s: debug: config file does not exist: %s\n",
                    PROJECT_NAME, filepath);
    }
    return NULL;
  }

  /* Get file info after opening (avoid TOCTOU) - use fstat on fd */
  struct stat st = {0};
  if (ops->fstat(fd, &st) != 0) {
    (void)fprintf(stderr, "%s: error: cannot fstat %s: %s\n", PROJECT_NAME,
                  filepath, strerror(errno));
    (void)ops->close(fd);
    return NULL;
  }

  /* Target must be regular file (not fifo, device, etc.) */
  if (!S_ISREG(st.st_mode)) {
    /* Type can never be a link since we follow those automatically */
    if (S_ISDIR(st.st_mode)) {
      (void)fprintf(stderr,
                    "%s: error: %s is not a regular file, is a directory\n",
                    PROJECT_NAME, filepath);
    } else if (S_ISCHR(st.st_mode)) {
      (void)fprintf(stderr,
                    "%s: error: %s is not a regular file, is "
                    "a character device\n",
                    PROJECT_NAME, filepath);
    } else if (S_ISBLK(st.st_mode)) {
      (void)fprintf(stderr,
                    "%s: error: %s is not a regular file, is "
                    "a block device\n",
                    PROJECT_NAME, filepath);
    } else if (S_ISFIFO(st.st_mode)) {
      (void)fprintf(stderr,
                    "%s: error: %s is not a regular file, is a FIFO/pipe\n",
                    PROJECT_NAME, filepath);
    } else if (S_ISSOCK(st.st_mode)) {
      (void)fprintf(stderr,
                    "%s: error: %s is not a regular file, is a socket\n",
                    PROJECT_NAME, filepath);
    }
    // LCOV_EXCL_START
    else {
      (void)fprintf(stderr,
                    "%s: error: %s is not a regular file, is an "
                    "unknown type (0%06o)\n",
                    PROJECT_NAME, filepath, st.st_mode & S_IFMT);
    }
    // LCOV_EXCL_STOP

    errno = EBADF;
    (void)ops->close(fd);
    return NULL;
  }

  /* Target file must be owned by root for security */
  if (st.st_uid != 0) {
    errno = EPERM;
    (void)fprintf(stderr, "%s: error: %s must be owned by root (uid 0)\n",
                  PROJECT_NAME, filepath);
    (void)ops->close(fd);
    return NULL;
  }

  /* Target file must not be world-writable */
  if ((st.st_mode & S_IWOTH) != 0) {
    errno = EPERM;
    (void)fprintf(stderr,
                  "%s: error: config file %s is world-writable (mode %04o)\n",
                  PROJECT_NAME, filepath, st.st_mode & 07777);
    (void)ops->close(fd);
    return NULL;
  }

  /* Convert fd to FILE* for use with fgets */
  FILE *fp = ops->fdopen(fd, "r");
  if (fp == NULL) {
    errno = EBADF;
    (void)fprintf(stderr, "%s: error: cannot fdopen %s: %s\n", PROJECT_NAME,
                  filepath, strerror(errno));
    (void)ops->close(fd);
    return NULL;
  }

  /* fd now owned by fp, don't close fd! */
  return fp;
}

/**
 * apply_config_value - Apply a parsed key-value pair to configuration
 * @key: Configuration key
 * @value: Configuration value string
 * @config: Configuration structure to update
 * @filepath: Source filepath (for error messages)
 *
 * Matches key against known configuration parameters and updates the
 * corresponding field in the config structure. Invalid values are silently
 * ignored to handle mixed config files like login.defs.
 *
 * For count values, enforces MAX_RANGES limit and logs errors on overflow.
 * Last value wins for repeated keys (no warning).
 */
static void apply_config_value(const char *key, const char *value,
                               config_t *config, const char *filepath) {
  uint32_t val = 0;

  /* UID range configuration */
  if (strcmp(key, config->key_uid_min) == 0) {
    if (parse_uint32_strict(value, &val) == 0) {
      config->uid_min = val;
    }
  } else if (strcmp(key, config->key_uid_max) == 0) {
    if (parse_uint32_strict(value, &val) == 0) {
      config->uid_max = val;
    }
  }
  /* Sub UID configuration */
  else if (strcmp(key, config->subuid.key_min) == 0) {
    if (parse_uint32_strict(value, &val) == 0) {
      config->subuid.min_val = val;
    }
  } else if (strcmp(key, config->subuid.key_max) == 0) {
    if (parse_uint32_strict(value, &val) == 0) {
      config->subuid.max_val = val;
    }
  } else if (strcmp(key, config->subuid.key_count) == 0) {
    if (parse_uint32_strict(value, &val) == 0) {
      if (val <= MAX_RANGES) {
        config->subuid.count_val = val;
      } else {
        errno = ERANGE;
        (void)fprintf(stderr,
                      "%s: error: file %s %s %u exceeds defined "
                      "limit of %u\n",
                      PROJECT_NAME, filepath, config->subuid.key_count, val,
                      MAX_RANGES);
      }
    }
  }
  /* Sub GID configuration */
  else if (strcmp(key, config->subgid.key_min) == 0) {
    if (parse_uint32_strict(value, &val) == 0) {
      config->subgid.min_val = val;
    }
  } else if (strcmp(key, config->subgid.key_max) == 0) {
    if (parse_uint32_strict(value, &val) == 0) {
      config->subgid.max_val = val;
    }
  } else if (strcmp(key, config->subgid.key_count) == 0) {
    if (parse_uint32_strict(value, &val) == 0) {
      if (val <= MAX_RANGES) {
        config->subgid.count_val = val;
      } else {
        errno = ERANGE;
        (void)fprintf(stderr,
                      "%s: error: file %s %s %u exceeds defined "
                      "limit of %u\n",
                      PROJECT_NAME, filepath, config->subgid.key_count, val,
                      MAX_RANGES);
      }
    }
  }
  /* Boolean options */
  else if (strcmp(key, config->key_skip_if_exists) == 0) {
    config->skip_if_exists = parse_bool(value, config->skip_if_exists);
  } else if (strcmp(key, config->key_allow_subid_wrap) == 0) {
    config->allow_subid_wrap = parse_bool(value, config->allow_subid_wrap);
  }

  /* Silently ignore unknown keys for compatibility with login.defs */
}

/**
 * parse_config_file - Parse configuration file and update config structure
 * @ops: Structure for system call abstraction (kernel-style ops pattern)
 * @filepath: Path to configuration file
 * @config: Configuration structure to update
 * @debug: Enable debug output
 *
 * Parses KEY VALUE pairs from config file. Lines are normalized (comments
 * stripped, whitespace trimmed) before parsing. Invalid lines are silently
 * skipped to handle mixed config files like login.defs.
 *
 * File must pass security validation (root-owned, not world-writable).
 * Non-existent files are silently skipped (not an error).
 */
static void parse_config_file(const struct syscall_ops *ops,
                              const char *filepath, config_t *config,
                              bool debug) {
  FILE *fp = safe_open_config(ops, filepath, debug);
  if (fp == NULL) {
    return; /* File doesn't exist or failed security checks */
  }

  if (debug) {
    (void)fprintf(stderr, "%s: debug: parsing config file: %s\n", PROJECT_NAME,
                  filepath);
  }

  char line[MAX_LINE_LEN] = {0};
  while (ops->fgets(line, sizeof(line), fp) != NULL) {
    /* Normalize: strip comments and trim whitespace */
    char *clean = normalize_config_line(line);

    /* Skip blank lines */
    if (*clean == '\0') {
      continue;
    }

    /* Parse KEY VALUE format (whitespace-separated) */
    char *key = clean;
    char *value = key;

    /* Find first whitespace to split key and value */
    while (*value && !isspace((unsigned char)*value)) {
      value++;
    }

    /* If no whitespace found, skip line (key without value) */
    if (*value == '\0') {
      if (debug) {
        (void)fprintf(stderr, "%s: debug: skipping key without value: %s\n",
                      PROJECT_NAME, key);
      }
      continue;
    }

    /* Null-terminate key and advance to value */
    *value = '\0';
    value++;

    /* Skip whitespace before value */
    while (*value && isspace((unsigned char)*value)) {
      value++;
    }

    /* Apply configuration if value is not empty */
    if (*value != '\0') {
      apply_config_value(key, value, config, filepath);
    }
  }

  (void)ops->fclose(fp);
}

/**
 * load_config_from_dir - Load configuration from drop-in directory
 * @ops: Operations structure for system call abstraction (kernel-style ops
 * pattern)
 * @config: Configuration structure to update
 * @dirpath: Path to directory containing .conf files
 * @debug: Enable debug output
 *
 * Validates directory security (root-owned, not world-writable), then
 * scans for .conf files and processes them in alphabetical order.
 * Non-existent directory is not an error (returns 0).
 * Security violations or other errors return -1.
 *
 * Return: 0 on success, -1 on error
 */
static int load_config_from_dir(const struct syscall_ops *ops, config_t *config,
                                const char *dirpath, bool debug) {
  /*
   * Validate directory security before processing
   * This function handles ENOENT gracefully (returns 0)
   */
  if (validate_config_dir(ops, dirpath, debug) != 0) {
    return -1;
  }

  if (debug) {
    (void)fprintf(stderr, "%s: debug: scanning config directory if found: %s\n",
                  PROJECT_NAME, dirpath);
  }

  /*
   * Scan directory for .conf files
   * scandir() handles ENOENT by returning -1 with errno == ENOENT
   * This is the ONLY place we need to check for ENOENT in this function
   */
  struct dirent **namelist = NULL;
  int n = ops->scandir(dirpath, &namelist, filter_conf_files, alphasort);

  if (n < 0) {
    if (errno == ENOENT) {
      /*
       * Directory doesn't exist - this is fine
       * validate_config_dir already logged this in debug mode
       */
      return 0;
    }
    /* Other scandir errors are real problems */
    (void)fprintf(stderr, "%s: error: cannot scan directory %s: %s\n",
                  PROJECT_NAME, dirpath, strerror(errno));
    return -1;
  }

  if (debug && n > 0) {
    (void)fprintf(stderr, "%s: debug: found %d config file%s in %s\n",
                  PROJECT_NAME, n, n == 1 ? "" : "s", dirpath);
  }

  /* Process each file in sorted order */
  for (int i = 0; i < n; i++) {
    const char *name = namelist[i]->d_name;

    /*
     * Defense-in-depth: Validate filename before constructing path
     * This catches malicious entries even if filter_conf_files was bypassed
     */

    /* Reject filenames containing path separators */
    if (strchr(name, '/') != NULL) {
      if (debug) {
        (void)fprintf(stderr,
                      "%s: debug: skipping filename with path separator: %s\n",
                      PROJECT_NAME, name);
      }
      (void)free(namelist[i]);
      continue;
    }

    /* Reject filenames starting with path traversal */
    if (name[0] == '.' && name[1] == '.') {
      if (debug) {
        (void)fprintf(stderr,
                      "%s: debug: skipping filename with path traversal: %s\n",
                      PROJECT_NAME, name);
      }
      (void)free(namelist[i]);
      continue;
    }

    char filepath[PATH_MAX] = {0};

    /*
     * Use snprintf for safe string formatting
     * Check return value to detect truncation
     */
    int ret = snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, name);
    if (ret < 0 || (size_t)ret >= sizeof(filepath)) {
      (void)fprintf(stderr, "%s: error: path too long: %s/%s\n", PROJECT_NAME,
                    dirpath, name);
      (void)free(namelist[i]);
      continue;
    }

    if (debug) {
      (void)fprintf(stderr, "%s: debug: processing config file: %s\n",
                    PROJECT_NAME, filepath);
    }

    (void)parse_config_file(ops, filepath, config, debug);
    (void)free(namelist[i]);
  }

  (void)free(namelist);
  return 0;
}

/**
 * config_factory - Initialize configuration with hardcoded defaults
 * @config: Configuration structure to initialize
 *
 * Sets all configuration fields to hardcoded defaults from shadow-utils.
 */
void config_factory(config_t *config) {
  if (config == NULL) {
    return;
  }

  /* Initialize with zero, then set defaults */
  *config = (config_t){0};

  /* Set hardcoded defaults from shadow-utils */
  config->key_uid_min = "UID_MIN";
  config->uid_min = 1000;
  config->key_uid_max = "UID_MAX";
  config->uid_max = 60000;

  config->subuid.type = SUBUID;
  config->subuid.key_min = "SUB_UID_MIN";
  config->subuid.min_val = 100000;
  config->subuid.key_max = "SUB_UID_MAX";
  config->subuid.max_val = 600100000;
  config->subuid.key_count = "SUB_UID_COUNT";
  config->subuid.count_val = 65536;

  config->subgid.type = SUBGID;
  config->subgid.key_min = "SUB_GID_MIN";
  config->subgid.min_val = 100000;
  config->subgid.key_max = "SUB_GID_MAX";
  config->subgid.max_val = 600100000;
  config->subgid.key_count = "SUB_GID_COUNT";
  config->subgid.count_val = 65536;

  config->key_skip_if_exists = "SKIP_IF_EXISTS";
  config->skip_if_exists = true;
  config->key_allow_subid_wrap = "ALLOW_SUBID_WRAP";
  config->allow_subid_wrap = false;
}

/**
 * load_configuration - Load configuration from all sources
 * @ops: Operations structure for system call abstraction (kernel-style ops
 * pattern)
 * @config: Configuration structure to populate
 * @debug: Enable debug output
 *
 * Loads configuration in priority order (later overrides earlier):
 * 1. Hardcoded defaults (from shadow-utils)
 * 2. /etc/login.defs
 * 3. CONFIG_FILE_PATH
 * 4. CONFIG_DROPIN_DIR_PATH/\*.conf (alphasorted)
 *
 * Missing files are silently skipped. Configuration files must be
 * owned by root and not world-writable.
 *
 * Return: 0 on success, -1 on error
 */
int load_configuration(const struct syscall_ops *ops, config_t *config,
                       bool debug) {
  if (ops == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: ops is NULL\n", PROJECT_NAME);
    return -1;
  }
  if (config == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: config is NULL\n", PROJECT_NAME);
    return -1;
  }

  /* Initialize with hardcoded defaults */
  config_factory(config);

  if (debug) {
    (void)fprintf(stderr, "%s: debug: loading configuration (defaults set)\n",
                  PROJECT_NAME);
    print_configuration(config, stderr, PROJECT_NAME ": debug: ");
  }

  /* Load from login.defs */
  (void)parse_config_file(ops, LOGIN_DEFS_PATH, config, debug);

  /* Override with main config file */
  (void)parse_config_file(ops, CONFIG_FILE_PATH, config, debug);

  /* Override with drop-in configs */
  if (load_config_from_dir(ops, config, CONFIG_DROPIN_DIR_PATH, debug) != 0) {
    return -1;
  }

  return 0;
}

/**
 * print_configuration - Print parsed configuration to output stream
 * @config: Configuration to print
 * @out: FILE stream to print to (e.g. stdout or stderr)
 * @prefix: Optional string prepended to every line (e.g. "prog: debug: "),
 *          or NULL for no prefix
 *
 * Outputs all configuration values in human-readable format.
 * Used for debugging and verification (with --debug flag).
 */
void print_configuration(const config_t *config, FILE *out,
                         const char *prefix) {
  const char *p = "";

  if (config == NULL) {
    return;
  }
  if (out == NULL) {
    return;
  }

  if (prefix != NULL) {
    p = prefix;
  }

  (void)fprintf(out, "%s  %s:\t\t%u\n", p, config->key_uid_min,
                config->uid_min);
  (void)fprintf(out, "%s  %s:\t\t%u\n", p, config->key_uid_max,
                config->uid_max);
  (void)fprintf(out, "%s  %s:\t\t%u\n", p, config->subuid.key_min,
                config->subuid.min_val);
  (void)fprintf(out, "%s  %s:\t\t%u\n", p, config->subuid.key_max,
                config->subuid.max_val);
  (void)fprintf(out, "%s  %s:\t%u\n", p, config->subuid.key_count,
                config->subuid.count_val);
  (void)fprintf(out, "%s  %s:\t\t%u\n", p, config->subgid.key_min,
                config->subgid.min_val);
  (void)fprintf(out, "%s  %s:\t\t%u\n", p, config->subgid.key_max,
                config->subgid.max_val);
  (void)fprintf(out, "%s  %s:\t%u\n", p, config->subgid.key_count,
                config->subgid.count_val);
  (void)fprintf(out, "%s  %s:\t%s\n", p, config->key_skip_if_exists,
                config->skip_if_exists ? "yes" : "no");
  (void)fprintf(out, "%s  %s:\t%s\n", p, config->key_allow_subid_wrap,
                config->allow_subid_wrap ? "yes" : "no");
}
