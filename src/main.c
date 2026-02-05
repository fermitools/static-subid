/**
 * main.c - Main program entry point and argument parsing
 *
 * Assigns static subordinate UID/GID ranges to users based on their primary
 * UID. Uses deterministic calculation to ensure consistent assignments across
 * systems.
 */

/* clang-format off */
#include "autoconf.h"
#include "static-subid.h"
#include "syscall_ops.h"
/* clang-format on */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Forward declarations for internal functions */
static void print_help(bool dump_config, bool debug) __attribute__((cold));
static int parse_arguments(int argc, char *argv[], options_t *opts)
    __attribute__((warn_unused_result));
static int process_mode(const char *username, uint32_t uid,
                        const config_t *config, subid_mode_t mode,
                        const options_t *opts)
    __attribute__((warn_unused_result));

/**
 * print_help - Display help message and exit
 * @dump_config: If true, also load and print configuration after help text
 * @debug: If true, load config in debug mode
 *
 * Prints usage information and options to stdout. If dump_config is true,
 * loads configuration and prints it after the help text.
 */
static void print_help(bool dump_config, bool debug) {
  (void)printf("Usage: %s [OPTIONS] <username|uid>\n", PROJECT_NAME);
  (void)printf("Version: %s\n", VERSION);
  (void)printf("\n");
  (void)printf(
      "Assign static deterministic subordinate UID/GID ranges to users.\n");
  (void)printf("\n");
  (void)printf("Options:\n");
  (void)printf("  --version\t\tDisplay version information and exit\n");
  (void)printf("  --subuid\t\tAssign subordinate UIDs\n");
  (void)printf("  --subgid\t\tAssign subordinate GIDs\n");
  (void)printf("  -d, --debug\t\tPrint debug information to stderr\n");
  (void)printf("  -n, --noop\t\tShow what would be done without executing\n");
  (void)printf("  -h, --help\t\tDisplay this help and exit\n");
  (void)printf("  --dump-config\t\tUse only with --help to also print "
               "loaded configuration\n");
  (void)printf("\n");
  (void)printf("Arguments:\n");
  (void)printf("  username\tUsername (must follow shadow-utils rules)\n");
  (void)printf("  uid\t\tNumeric UID\n");
  (void)printf("\n");
  (void)printf("Both --subuid and --subgid can be specified together.\n");
  (void)printf("Use getsubids (from shadow-utils) to look for existing "
               "assigned ranges.\n");
  (void)printf("\n");
  (void)printf("Configuration:\n");
  (void)printf("  Settings read from (in priority order):\n");
  (void)printf("  1. %s\n", LOGIN_DEFS_PATH);
  (void)printf("  2. %s\n", CONFIG_FILE_PATH);
  (void)printf("  3. %s/*.conf\n", CONFIG_DROPIN_DIR_PATH);
  (void)printf("\n");

  if (dump_config) {
    config_t config = {0};
    if (load_configuration(&syscall_ops_default, &config, debug) == 0) {
      (void)printf("Parsed Configuration (including defaults):\n");
      (void)print_configuration(&config, stdout, NULL);
    } else {
      (void)fprintf(stderr,
                    "%s: error: failed to load configuration, try --debug\n",
                    PROJECT_NAME);
    }
  }
}

/**
 * parse_arguments - Parse command line arguments using getopt_long
 * @argc: Argument count from main
 * @argv: Argument vector from main
 * @opts: Options structure to populate
 *
 * Parses command line options and validates basic argument requirements.
 * Sets appropriate flags in @opts structure.
 *
 * Return: 0 on success, -1 on error (invalid arguments)
 */
static int parse_arguments(int argc, char *argv[], options_t *opts) {
  if (opts == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: opts is NULL\n", PROJECT_NAME);
    return -1;
  }

  /* Initialize options structure */
  *opts = (options_t){
      .do_subuid = false,
      .do_subgid = false,
      .debug = false,
      .noop = false,
      .help = false,
      .dump_config = false,
      .user_arg = NULL,
  };

  static struct option long_options[] = {
      {"subuid", no_argument, NULL, 'u'},
      {"subgid", no_argument, NULL, 'g'},
      {"debug", no_argument, NULL, 'd'},
      {"noop", no_argument, NULL, 'n'},
      {"help", no_argument, NULL, 'h'},
      {"dump-config", no_argument, NULL, 1001},
      {"version", no_argument, NULL, 1000},
      {NULL, 0, NULL, 0}};

  int opt = 0;
  while ((opt = getopt_long(argc, argv, "ugdnh", long_options, NULL)) != -1) {
    switch (opt) {
    case 'u':
      opts->do_subuid = true;
      break;
    case 'g':
      opts->do_subgid = true;
      break;
    case 'd':
      opts->debug = true;
      break;
    case 'n':
      opts->noop = true;
      break;
    case 'h':
      opts->help = true;
      break;
    case 1001: /* --dump-config */
      opts->dump_config = true;
      break;
    case 1000: /* --version */
      (void)printf("%s: version %s\n", PROJECT_NAME, VERSION);
      exit(EXIT_SUCCESS);
    default:
      return -1;
    }
  }

  /* Validate --dump-config only valid with --help */
  if (opts->dump_config && !opts->help) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: --dump-config only valid with --help\n",
                  PROJECT_NAME);
    return -1;
  }

  /* Check for user argument (unless --help) */
  if (optind >= argc) {
    if (!opts->help) {
      errno = EINVAL;
      (void)fprintf(stderr, "%s: error: missing username or UID argument\n",
                    PROJECT_NAME);
      return -1;
    }
    return 0;
  }

  opts->user_arg = argv[optind];

  /* Verify at least one mode was specified */
  if (!opts->do_subuid && !opts->do_subgid && !opts->help) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: must specify --subuid and/or --subgid\n",
                  PROJECT_NAME);
    return -1;
  }

  return 0;
}

/**
 * process_mode - Process single mode (subuid or subgid)
 * @username: Username to process
 * @uid: User's UID
 * @config: Configuration
 * @mode: SUBUID or SUBGID
 * @opts: Runtime options
 *
 * Handles the complete workflow for assigning one type of subordinate ID:
 * 1. Validate UID doesn't overlap subordinate range
 * 2. Check if user already has subordinate IDs (if SKIP_IF_EXISTS)
 * 3. Calculate subordinate ID range
 * 4. Assign range via usermod
 *
 * Return: 0 on success, -1 on error
 */
static int process_mode(const char *username, uint32_t uid,
                        const config_t *config, subid_mode_t mode,
                        const options_t *opts) {
  if (username == NULL || config == NULL || opts == NULL) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: NULL parameter in process_mode\n",
                  PROJECT_NAME);
    return -1;
  }

  const char *mode_str = NULL;
  const subid_config_t *subid_cfg = NULL;

  switch (mode) {
  case SUBUID:
    mode_str = "subuid";
    subid_cfg = &config->subuid;
    break;
  case SUBGID:
    mode_str = "subgid";
    subid_cfg = &config->subgid;
    break;
  default:
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: invalid mode\n", PROJECT_NAME);
    return -1;
  }

  if (opts->debug) {
    (void)fprintf(stderr, "%s: debug: processing mode: %s\n", PROJECT_NAME,
                  mode_str);
  }

  /* Validate UID doesn't overlap with subordinate ID range */
  if (validate_uid_subid_overlap(uid, subid_cfg) != 0) {
    return -1;
  }

  /* Check if subordinate IDs already exist (if configured) */
  if (config->skip_if_exists) {
    int exists =
        check_subid_exists(&syscall_ops_default, username, mode, opts->debug);
    if (exists < 0) {
      (void)fprintf(stderr,
                    "%s: warning: could not check existing %ss for user "
                    "%s giving up\n",
                    PROJECT_NAME, mode_str, username);
      return -1;
    } else if (exists > 0) {
      if (opts->debug) {
        (void)fprintf(stderr, "%s: debug: user %s already has %ss assigned\n",
                      PROJECT_NAME, username, mode_str);
      }
      return 0;
    }
  }

  /* Calculate subordinate ID range start */
  if (opts->debug) {
    (void)fprintf(stderr, "%s: debug: calculating %s range for UID %u\n",
                  PROJECT_NAME, mode_str, uid);
  }

  uint32_t start = 0; /* value actually managed by calc_subid_range */
  if (calc_subid_range(uid, config->uid_min, subid_cfg,
                       config->allow_subid_wrap, &start) != 0) {
    return -1;
  }

  if (opts->debug) {
    (void)fprintf(stderr, "%s: debug: calculated range: %u:%u\n", PROJECT_NAME,
                  start, subid_cfg->count_val);
  }

  /* Assign subordinate ID range */
  if (set_subid_range(&syscall_ops_default, username, mode, start,
                      subid_cfg->count_val, opts->noop, opts->debug) != 0) {
    return -1;
  }

  return 0;
}

/**
 * main - Program entry point
 * @argc: Argument count
 * @argv: Argument vector
 *
 * Main workflow:
 * 1. Parse command line arguments
 * 2. Handle --help (with optional --dump-config)
 * 3. Resolve user argument to UID and username
 * 4. Load configuration from multiple sources
 * 5. Validate UID is in allowed range
 * 6. Process --subuid if requested
 * 7. Process --subgid if requested
 *
 * Return: 0 on success, 1 on error
 */
int main(int argc, char *argv[]) {
  options_t opts = {0};
  uint32_t uid = 0;
  config_t config = {0};
  char *username = NULL;

  long name_max = sysconf(_SC_LOGIN_NAME_MAX);
  if (name_max <= 0) {
    fprintf(stderr, "Invalid _SC_LOGIN_NAME_MAX: %ld\n", name_max);
    exit(EXIT_FAILURE);
  }

  /* +1 for NUL terminator */
  size_t username_size = (size_t)name_max + 1;
  username = calloc(username_size, sizeof *username);
  if (username == NULL) {
    (void)fprintf(stderr, "%s: error: memory allocation failed\n",
                  PROJECT_NAME);

    exit(EXIT_FAILURE);
  }

  /* Parse command line arguments */
  if (parse_arguments(argc, argv, &opts) != 0) {
    print_help(false, false);
    exit(EXIT_FAILURE);
  }

  /* Handle --help (with optional --dump-config) */
  if (opts.help) {
    print_help(opts.dump_config, opts.debug);
    exit(EXIT_SUCCESS);
  }

  if (opts.debug) {
    (void)fprintf(stderr, "%s: debug: version %s starting\n", PROJECT_NAME,
                  VERSION);
  }

  /* Resolve user argument to UID and username */
  if (resolve_user(&syscall_ops_default, opts.user_arg, &uid, username,
                   username_size, opts.debug) != 0) {
    exit(EXIT_FAILURE);
  }

  if (opts.debug) {
    (void)fprintf(stderr, "%s: debug: resolved user: %s (UID: %u)\n",
                  PROJECT_NAME, username, uid);
  }

  /* Load configuration from all sources */
  if (opts.debug) {
    (void)fprintf(stderr, "%s: debug: loading configuration\n", PROJECT_NAME);
  }

  if (load_configuration(&syscall_ops_default, &config, opts.debug) != 0) {
    (void)fprintf(stderr, "%s: error: failed to load configuration\n",
                  PROJECT_NAME);
    exit(EXIT_FAILURE);
  }

  if (opts.debug) {
    (void)fprintf(stderr, "\n");
    (void)fprintf(stderr, "Parsed Configuration (including defaults):\n");
    (void)print_configuration(&config, stderr, NULL);
    (void)fprintf(stderr, "\n");
  }

  /* Validate UID is in allowed range */
  if (validate_uid_range(uid, &config) != 0) {
    exit(EXIT_FAILURE);
  }

  /* Process subuid if requested */
  if (opts.do_subuid) {
    if (process_mode(username, uid, &config, SUBUID, &opts) != 0) {
      exit(EXIT_FAILURE);
    }
  }

  /* Process subgid if requested */
  if (opts.do_subgid) {
    if (process_mode(username, uid, &config, SUBGID, &opts) != 0) {
      exit(EXIT_FAILURE);
    }
  }

  if (opts.debug) {
    (void)fprintf(stderr, "%s: debug: completed successfully\n", PROJECT_NAME);
  }

  exit(EXIT_SUCCESS);
}
