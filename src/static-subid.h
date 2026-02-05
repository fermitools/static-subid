/**
 * static-subid.h - Static subordinate UID/GID assignment tool
 *
 * Assigns deterministic subordinate user and group ID ranges for unprivileged
 * containers based on a user's primary UID. Ensures consistent assignments
 * across multiple systems when UIDs are synchronized.
 */

#ifndef STATIC_SUBID_H
#define STATIC_SUBID_H

#include <dirent.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include "autoconf.h"
#include "syscall_ops.h"

/* Compile-time assertions to verify platform assumptions */
_Static_assert(sizeof(uint32_t) == 4, "uint32_t must be 4 bytes");
_Static_assert(sizeof(uid_t) <= sizeof(uint32_t), "uid_t must fit in uint32_t");
_Static_assert(PATH_MAX > 0, "PATH_MAX must be positive");
_Static_assert(ULLONG_MAX >= 4294967295U,
               "unsigned long long must handle uint32_t range");

/* POSIX hard limit on user/group ID size */
#define UINT32_MAX_VAL 4294967295U

/* String representation length calculations */
#define UINT32_DECIMAL_MAX_LEN 10 /* strlen("4294967295") */
#define RANGE_STR_MAX                                                          \
  ((UINT32_DECIMAL_MAX_LEN * 2) + 2) /* "start-end\0" = 10+1+10+1 = 22 */

/* Maximum config line length - prevents DoS via large lines */
#define MAX_LINE_LEN 1024

/* Compile-time validation of configuration */
_Static_assert(MAX_RANGES > 0, "MAX_RANGES must be positive");
_Static_assert(MAX_RANGES <= (UINT32_C(1) << 26),
               "MAX_RANGES too large to make sense");

/**
 * enum subid_mode_t - Operating mode for subordinate ID operations
 * @SUBUID: Operate on subordinate UIDs
 * @SUBGID: Operate on subordinate GIDs
 */
typedef enum { SUBUID, SUBGID } subid_mode_t;

/**
 * struct subid_config_t - Configuration for one type of subordinate ID
 * @type: What sort of subid does this cover
 * @key_min: Configuration key name for minimum value
 * @key_max: Configuration key name for maximum value
 * @key_count: Configuration key name for count per user
 * @min_val: Minimum subordinate ID value from configuration
 * @max_val: Maximum subordinate ID value from configuration
 * @count_val: Number of subordinate IDs per user from configuration
 */
typedef struct {
  const char *key_min;   /* Is a string literal, never freed */
  const char *key_max;   /* Is a string literal, never freed */
  const char *key_count; /* Is a string literal, never freed */
  subid_mode_t type;     /* Is our mode enum */
  uint32_t min_val;
  uint32_t max_val;
  uint32_t count_val;
} subid_config_t;

/**
 * struct config_t - Complete configuration parameters
 * @key_uid_min: Key for @uid_min
 * @key_uid_max: Key for @uid_max
 * @uid_min: Minimum UID eligible for subordinate IDs
 * @uid_max: Maximum UID eligible for subordinate IDs
 * @subuid: Subordinate UID configuration
 * @subgid: Subordinate GID configuration
 * @key_skip_if_exists: key for @skip_if_exists
 * @key_allow_subid_wrap: key for @allow_subid_wrap
 * @skip_if_exists: Skip assignment if user already has subordinate IDs
 * @allow_subid_wrap: Allow overlap in range calculation for large UIDs
 */
typedef struct {
  const char *key_uid_min; /* Is a string literal, never freed */
  const char *key_uid_max; /* Is a string literal, never freed */
  uint32_t uid_min;
  uint32_t uid_max;
  subid_config_t subuid;
  subid_config_t subgid;
  const char *key_skip_if_exists;   /* Is a string literal, never freed */
  const char *key_allow_subid_wrap; /* Is a string literal, never freed */
  bool skip_if_exists;
  bool allow_subid_wrap;
} config_t;

/**
 * struct options_t - Command-line options and runtime state
 * @do_subuid: Assign subordinate UIDs if true
 * @do_subgid: Assign subordinate GIDs if true
 * @debug: Print debug information to stderr
 * @noop: Show actions without executing them
 * @help: Display help and exit
 * @dump_config: Dump configuration after help (only valid with --help)
 * @user_arg: User argument from command line (username or UID string)
 *
 * The @user_arg pointer references argv memory and must not be freed.
 */
typedef struct {
  bool do_subuid;
  bool do_subgid;
  bool debug;
  bool noop;
  bool help;
  bool dump_config;
  const char *user_arg; /* Points into argv, never freed */
} options_t;

/*
 * Function declarations
 */

/* config.c */
void config_factory(config_t *config);
int load_configuration(const struct syscall_ops *ops, config_t *config,
                       bool debug) __attribute__((warn_unused_result));
void print_configuration(const config_t *config, FILE *out, const char *prefix)
    __attribute__((cold));

/* range.c */
int calc_subid_range(uint32_t uid, uint32_t uid_min,
                     const subid_config_t *subid_cfg, bool allow_wrap,
                     uint32_t *start_out) __attribute__((warn_unused_result));

/* subid.c */
int check_subid_exists(const struct syscall_ops *ops, const char *username,
                       subid_mode_t mode, bool debug)
    __attribute__((warn_unused_result));
int set_subid_range(const struct syscall_ops *ops, const char *username,
                    subid_mode_t mode, uint32_t start, uint32_t count,
                    bool noop, bool debug) __attribute__((warn_unused_result));

/* util.c */
int resolve_user(const struct syscall_ops *ops, const char *user_arg,
                 uint32_t *uid, char *username, size_t username_size,
                 bool debug) __attribute__((warn_unused_result));
int filter_conf_files(const struct dirent *entry)
    __attribute__((warn_unused_result));
char *normalize_config_line(char *line) __attribute__((warn_unused_result));

/* validate.c */
int validate_path(const char *path) __attribute__((warn_unused_result));
int validate_config_dir(const struct syscall_ops *ops, const char *dirpath,
                        bool debug) __attribute__((warn_unused_result));
int validate_username(const char *username) __attribute__((warn_unused_result));
bool parse_bool(const char *str, bool default_val)
    __attribute__((warn_unused_result));
int parse_uint32_strict(const char *str, uint32_t *result)
    __attribute__((warn_unused_result));
int validate_uid_range(uint32_t uid, const config_t *config)
    __attribute__((warn_unused_result));
int validate_uid_subid_overlap(uint32_t uid, const subid_config_t *subid_cfg)
    __attribute__((warn_unused_result));

#endif /* STATIC_SUBID_H */
