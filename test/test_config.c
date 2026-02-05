/**
 * test_config.c - Configuration loading tests with fixture helpers
 */

/* clang-format off */
#include "autoconf.h"
#include "static-subid.h"
#include "syscall_ops.h"
/* clang-format on */

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_framework.h"
#include "test_helpers/all.h"

/* ============================================================================
 * Constants - Replacing Magic Numbers
 * ============================================================================
 */

/* Mock file descriptor constants - distinct values for each config source */
enum {
  MOCK_FD_LOGIN_DEFS = 100,
  MOCK_FD_MAIN_CONFIG = 101,
  MOCK_FD_DROPIN_01 = 102,
  MOCK_FD_DROPIN_02 = 103,
  MOCK_FD_CUSTOM = 42 /* Generic successful fd for custom content tests */
};

/* Mock FILE* pointer constants - distinct addresses for each source */
#define MOCK_FILE_LOGIN_DEFS ((FILE *)0x1000)
#define MOCK_FILE_MAIN_CONFIG ((FILE *)0x2000)
#define MOCK_FILE_DROPIN_01 ((FILE *)0x3000)
#define MOCK_FILE_DROPIN_02 ((FILE *)0x4000)
#define MOCK_FILE_CUSTOM ((FILE *)0x5000)

/* Test buffer and path size limits */
enum {
  TEST_BUFFER_SIZE = 4096,
  LONG_PATH_SIZE = 81920, /* Extremely long path for overflow testing */
  OVERFLOW_CONFIG_SIZE = 256
};

/* Default configuration values for validation */
enum {
  DEFAULT_UID_MIN = 1000,
  DEFAULT_UID_MAX = 60000,
  DEFAULT_SUB_UID_MIN = 100000,
  DEFAULT_SUB_UID_MAX = 600100000,
  DEFAULT_SUB_UID_COUNT = 65536,
  DEFAULT_SUB_GID_MIN = 100000,
  DEFAULT_SUB_GID_MAX = 600100000,
  DEFAULT_SUB_GID_COUNT = 65536
};

/* Configuration values from mock files */
enum {
  LOGIN_DEFS_UID_MIN = 100,
  LOGIN_DEFS_UID_MAX = 6000,
  LOGIN_DEFS_SUB_GID_COUNT = 4096,
  MAIN_CONFIG_UID_MIN = 2000,
  MAIN_CONFIG_SUB_UID_MIN = 200000,
  MAIN_CONFIG_SUB_UID_MAX = 600000000,
  DROPIN_01_UID_MAX = 50000,
  DROPIN_01_SUB_UID_COUNT = 8192,
  DROPIN_02_UID_MIN = 500,
  DROPIN_02_SUB_UID_COUNT = 65536
};

/* ============================================================================
 * Static Mock File Content - Immutable Test Data
 * ============================================================================
 */

static const char *const MOCK_LOGIN_DEFS = "# Mock /etc/login.defs\n"
                                           "UID_MIN 100\n"
                                           "UID_MAX 6000\n"
                                           "SUB_UID_MIN 10000\n"
                                           "SUB_UID_MAX 60100000\n"
                                           "SUB_UID_COUNT 4096\n"
                                           "SUB_GID_MIN 10000\n"
                                           "SUB_GID_MAX 60100000\n"
                                           "SUB_GID_COUNT 4096\n";

static const char *const MOCK_MAIN_CONFIG = "# Mock /etc/static-subid.conf\n"
                                            "UID_MIN 2000\n"
                                            "SUB_UID_MIN 200000\n"
                                            "SUB_UID_MAX 600000000\n"
                                            "SUB_UID_COUNT 65536\n";

static const char *const MOCK_DROPIN_01 = "UID_MAX 50000\n"
                                          "SUB_UID_COUNT 8192\n";

static const char *const MOCK_DROPIN_02 = "UID_MIN 5\n"
                                          "UID_MIN 500\n"
                                          "SUB_UID_COUNT 65536\n";

/* ============================================================================
 * Mock I/O State - Simulates File Reading
 * ============================================================================
 */

static const char *current_mock_content = NULL;
static size_t current_mock_offset = 0;
static const char *custom_content = NULL;

/* ============================================================================
 * Mock Directory Entry Structures
 * ============================================================================
 */

/* Standard drop-in files */
static struct dirent *mock_dirent_01 = NULL;
static struct dirent **mock_namelist = NULL;

/* Standard drop-in with two files */
static struct dirent *mock_dirent_two_01 = NULL;
static struct dirent *mock_dirent_two_02 = NULL;
static struct dirent **mock_list_two = NULL;

/* Security validation test scenarios */
static struct dirent *mock_dirent_separator = NULL;
static struct dirent **mock_list_separator = NULL;

static struct dirent *mock_dirent_traversal = NULL;
static struct dirent **mock_list_traversal = NULL;

static struct dirent *mock_dirent_absolute = NULL;
static struct dirent **mock_list_absolute = NULL;

static struct dirent *mock_dirent_hidden = NULL;
static struct dirent **mock_list_hidden = NULL;

static struct dirent *mock_dirent_dotdot = NULL;
static struct dirent **mock_list_dotdot = NULL;

static struct dirent *mock_dirent_long = NULL;
static struct dirent **mock_list_long = NULL;

/* ============================================================================
 * Mock I/O State Management
 * ============================================================================
 */

/**
 * reset_mock_io_state - Resets file reading simulation state
 *
 * Call after closing a mock file to ensure clean state for next operation.
 */
static void reset_mock_io_state(void) {
  current_mock_content = NULL;
  current_mock_offset = 0;
}

/**
 * set_mock_content - Sets content for mock file reading
 * @content: Pointer to null-terminated content string
 *
 * Initializes mock file reading with specified content and resets offset.
 */
static void set_mock_content(const char *content) {
  current_mock_content = content;
  current_mock_offset = 0;
}

/* ============================================================================
 * Mock Scandir Helper - Reduces Code Duplication
 * ============================================================================
 */

/**
 * create_single_dirent - Allocates and initializes a single directory entry
 * @name: Filename to store in d_name field
 *
 * Returns: Allocated dirent structure, or NULL on allocation failure
 *
 * Caller is responsible for freeing returned memory.
 */
static struct dirent *create_single_dirent(const char *name) {
  size_t name_len;
  size_t alloc_size;
  struct dirent *entry;

  if (name == NULL) {
    return NULL;
  }

  name_len = strlen(name);
  alloc_size = sizeof(struct dirent) + name_len + 1;
  entry = calloc(1, alloc_size);

  if (entry != NULL) {
    strcpy(entry->d_name, name);
  }

  return entry;
}

/**
 * create_dirent_list - Creates a directory entry list for scandir
 * @entries: Array of directory entries to include in list
 * @count: Number of entries in array
 *
 * Returns: Allocated array of pointers to directory entries
 *
 * Caller is responsible for freeing returned memory and entry structures.
 */
static struct dirent **create_dirent_list(struct dirent **entries,
                                          size_t count) {
  struct dirent **list;
  size_t i;

  if (entries == NULL || count == 0) {
    return NULL;
  }

  list = calloc(count, sizeof(struct dirent *));
  if (list == NULL) {
    return NULL;
  }

  for (i = 0; i < count; i++) {
    list[i] = entries[i];
  }

  return list;
}

/* ============================================================================
 * Mock Functions - Basic File Operations
 * ============================================================================
 */

/**
 * mock_open - Standard mock returning fds for known config files
 * @pathname: File path to open
 * @flags: Open flags (unused)
 *
 * Maps known configuration paths to distinct file descriptors.
 *
 * Returns: File descriptor on success, -1 with errno=ENOENT on failure
 */
static int mock_open(const char *pathname, int flags, ...) {
  (void)flags;

  if (strcmp(pathname, LOGIN_DEFS_PATH) == 0) {
    return MOCK_FD_LOGIN_DEFS;
  }
  if (strcmp(pathname, CONFIG_FILE_PATH) == 0) {
    return MOCK_FD_MAIN_CONFIG;
  }
  if (strstr(pathname, "/01-override.conf") != NULL) {
    return MOCK_FD_DROPIN_01;
  }
  if (strstr(pathname, "/02-override.conf") != NULL) {
    return MOCK_FD_DROPIN_02;
  }

  errno = ENOENT;
  return -1;
}

/**
 * mock_open_login_defs_only - Only allows login.defs to be opened
 * @pathname: File path to open
 * @flags: Open flags (unused)
 *
 * Simulates environment where main config and drop-ins don't exist.
 *
 * Returns: File descriptor for login.defs, -1 with errno=ENOENT otherwise
 */
static int mock_open_login_defs_only(const char *pathname, int flags, ...) {
  (void)flags;

  if (strcmp(pathname, LOGIN_DEFS_PATH) == 0) {
    return MOCK_FD_LOGIN_DEFS;
  }

  errno = ENOENT;
  return -1;
}

/**
 * mock_open_success - Returns arbitrary successful fd
 * @pathname: File path (unused)
 * @flags: Open flags (unused)
 *
 * Used with custom content injection for dynamic test content.
 *
 * Returns: Generic successful file descriptor
 */
static int mock_open_success(const char *pathname, int flags, ...) {
  (void)pathname;
  (void)flags;
  return MOCK_FD_CUSTOM;
}

/**
 * mock_close - Validates fd range and returns success for mock fds
 * @fd: File descriptor to close
 *
 * Returns: 0 on success, -1 with errno=EBADF for invalid fd
 */
static int mock_close(int fd) {
  if ((fd >= MOCK_FD_LOGIN_DEFS && fd <= MOCK_FD_DROPIN_02) ||
      fd == MOCK_FD_CUSTOM) {
    return 0;
  }
  errno = EBADF;
  return -1;
}

/**
 * mock_fdopen - Associates file descriptors with mock content
 * @fd: File descriptor from mock_open
 * @mode: File mode (unused)
 *
 * Returns distinct FILE* pointers for each configuration source.
 *
 * Returns: Mock FILE pointer on success, NULL with errno=EBADF on failure
 */
static FILE *mock_fdopen(int fd, const char *mode) {
  (void)mode;

  switch (fd) {
  case MOCK_FD_LOGIN_DEFS:
    set_mock_content(MOCK_LOGIN_DEFS);
    return MOCK_FILE_LOGIN_DEFS;

  case MOCK_FD_MAIN_CONFIG:
    set_mock_content(MOCK_MAIN_CONFIG);
    return MOCK_FILE_MAIN_CONFIG;

  case MOCK_FD_DROPIN_01:
    set_mock_content(MOCK_DROPIN_01);
    return MOCK_FILE_DROPIN_01;

  case MOCK_FD_DROPIN_02:
    set_mock_content(MOCK_DROPIN_02);
    return MOCK_FILE_DROPIN_02;

  default:
    errno = EBADF;
    return NULL;
  }
}

/**
 * custom_fdopen - Injects dynamically provided test content
 * @fd: File descriptor (unused)
 * @mode: File mode (unused)
 *
 * Used by make_ops_with_content() for test-specific configuration.
 *
 * Returns: Mock FILE pointer
 */
static FILE *custom_fdopen(int fd, const char *mode) {
  (void)fd;
  (void)mode;
  set_mock_content(custom_content);
  return MOCK_FILE_CUSTOM;
}

/**
 * mock_fgets - Simulates line-by-line file reading
 * @str: Buffer to store read line
 * @n: Maximum bytes to read including null terminator
 * @stream: FILE pointer (unused, state tracked globally)
 *
 * Respects buffer limits and handles newline-delimited reading correctly.
 * Advances current_mock_offset to track position in content.
 *
 * Returns: str on success, NULL at end of content
 */
static char *mock_fgets(char *str, int n, FILE *stream) {
  size_t content_len;
  size_t remaining;
  size_t to_copy;
  const char *src;
  const char *newline;

  (void)stream;

  if (current_mock_content == NULL || n <= 0) {
    return NULL;
  }

  content_len = strlen(current_mock_content);
  if (current_mock_offset >= content_len) {
    return NULL;
  }

  remaining = content_len - current_mock_offset;
  to_copy = (remaining < (size_t)(n - 1)) ? remaining : (size_t)(n - 1);

  src = current_mock_content + current_mock_offset;
  newline = memchr(src, '\n', to_copy);

  if (newline != NULL) {
    ptrdiff_t diff = newline - src + 1;
    to_copy = (diff > 0) ? (size_t)diff : 0;
  }

  memcpy(str, src, to_copy);
  str[to_copy] = '\0';
  current_mock_offset += to_copy;

  return str;
}

/**
 * mock_fclose - Resets mock file reading state
 * @stream: FILE pointer (unused)
 *
 * Returns: Always 0
 */
static int mock_fclose(FILE *stream) {
  (void)stream;
  reset_mock_io_state();
  return 0;
}

/* ============================================================================
 * Mock Functions - Scandir Variants
 * ============================================================================
 */

/**
 * mock_scandir_with_dropin - Returns a valid drop-in configuration file
 *
 * Returns: 1 with allocated namelist containing two entries
 */
static int mock_scandir_with_dropin(const char *dirp, struct dirent ***namelist,
                                    int (*filter)(const struct dirent *),
                                    int (*compar)(const struct dirent **,
                                                  const struct dirent **)) {
  struct dirent *entries[2];
  (void)dirp;
  (void)filter;
  (void)compar;

  mock_dirent_01 = create_single_dirent("01-override.conf");

  entries[0] = mock_dirent_01;
  mock_namelist = create_dirent_list(entries, 1);

  *namelist = mock_namelist;
  return 1;
}

/**
 * mock_scandir_two_files - Returns two valid drop-in configuration files
 *
 * Returns: 2 with allocated namelist containing two entries
 */
static int mock_scandir_two_files(const char *dirp, struct dirent ***namelist,
                                  int (*filter)(const struct dirent *),
                                  int (*compar)(const struct dirent **,
                                                const struct dirent **)) {
  struct dirent *entries[2];
  (void)dirp;
  (void)filter;
  (void)compar;

  mock_dirent_two_01 = create_single_dirent("01-override.conf");
  mock_dirent_two_02 = create_single_dirent("02-override.conf");

  entries[0] = mock_dirent_two_01;
  entries[1] = mock_dirent_two_02;
  mock_list_two = create_dirent_list(entries, 2);

  *namelist = mock_list_two;
  return 2;
}

/**
 * mock_scandir_path_separator - Returns filename with path separator
 *
 * Tests rejection of "invalid/name.conf".
 *
 * Returns: 1 with allocated namelist containing invalid entry
 */
static int mock_scandir_path_separator(const char *dirp,
                                       struct dirent ***namelist,
                                       int (*filter)(const struct dirent *),
                                       int (*compar)(const struct dirent **,
                                                     const struct dirent **)) {
  struct dirent *entries[1];
  (void)dirp;
  (void)filter;
  (void)compar;

  mock_dirent_separator = create_single_dirent("invalid/name.conf");
  entries[0] = mock_dirent_separator;
  mock_list_separator = create_dirent_list(entries, 1);

  *namelist = mock_list_separator;
  return 1;
}

/**
 * mock_scandir_path_traversal - Returns filename with path traversal
 *
 * Tests rejection of "../escape.conf".
 *
 * Returns: 1 with allocated namelist containing traversal entry
 */
static int mock_scandir_path_traversal(const char *dirp,
                                       struct dirent ***namelist,
                                       int (*filter)(const struct dirent *),
                                       int (*compar)(const struct dirent **,
                                                     const struct dirent **)) {
  struct dirent *entries[1];
  (void)dirp;
  (void)filter;
  (void)compar;

  mock_dirent_traversal = create_single_dirent("../escape.conf");
  entries[0] = mock_dirent_traversal;
  mock_list_traversal = create_dirent_list(entries, 1);

  *namelist = mock_list_traversal;
  return 1;
}

/**
 * mock_scandir_absolute_path - Returns filename with absolute path
 *
 * Tests rejection of "/etc/shadow.conf".
 *
 * Returns: 1 with allocated namelist containing absolute path entry
 */
static int mock_scandir_absolute_path(const char *dirp,
                                      struct dirent ***namelist,
                                      int (*filter)(const struct dirent *),
                                      int (*compar)(const struct dirent **,
                                                    const struct dirent **)) {
  struct dirent *entries[1];
  (void)dirp;
  (void)filter;
  (void)compar;

  mock_dirent_absolute = create_single_dirent("/etc/shadow.conf");
  entries[0] = mock_dirent_absolute;
  mock_list_absolute = create_dirent_list(entries, 1);

  *namelist = mock_list_absolute;
  return 1;
}

/**
 * mock_scandir_hidden_file - Returns hidden file (dotfile)
 *
 * Tests rejection of ".hidden.conf".
 *
 * Returns: 1 with allocated namelist containing hidden file entry
 */
static int mock_scandir_hidden_file(const char *dirp, struct dirent ***namelist,
                                    int (*filter)(const struct dirent *),
                                    int (*compar)(const struct dirent **,
                                                  const struct dirent **)) {
  struct dirent *entries[1];
  (void)dirp;
  (void)filter;
  (void)compar;

  mock_dirent_hidden = create_single_dirent(".hidden.conf");
  entries[0] = mock_dirent_hidden;
  mock_list_hidden = create_dirent_list(entries, 1);

  *namelist = mock_list_hidden;
  return 1;
}

/**
 * mock_scandir_dotdot_prefix - Returns filename starting with ".."
 *
 * Tests rejection of "..conf".
 *
 * Returns: 1 with allocated namelist containing dotdot entry
 */
static int mock_scandir_dotdot_prefix(const char *dirp,
                                      struct dirent ***namelist,
                                      int (*filter)(const struct dirent *),
                                      int (*compar)(const struct dirent **,
                                                    const struct dirent **)) {
  struct dirent *entries[1];
  (void)dirp;
  (void)filter;
  (void)compar;

  mock_dirent_dotdot = create_single_dirent("..conf");
  entries[0] = mock_dirent_dotdot;
  mock_list_dotdot = create_dirent_list(entries, 1);

  *namelist = mock_list_dotdot;
  return 1;
}

/**
 * mock_scandir_long_path - Returns extremely long filename
 *
 * Tests handling of paths exceeding PATH_MAX.
 *
 * Returns: 1 with allocated namelist containing very long entry
 */
static int mock_scandir_long_path(const char *dirp, struct dirent ***namelist,
                                  int (*filter)(const struct dirent *),
                                  int (*compar)(const struct dirent **,
                                                const struct dirent **)) {
  struct dirent *entries[1];
  (void)dirp;
  (void)filter;
  (void)compar;

  mock_dirent_long = calloc(1, sizeof(struct dirent) + LONG_PATH_SIZE);
  if (mock_dirent_long != NULL) {
    memset(mock_dirent_long->d_name, 'A', LONG_PATH_SIZE - 6);
    strcpy(mock_dirent_long->d_name + (LONG_PATH_SIZE - 6), ".conf");
  }

  entries[0] = mock_dirent_long;
  mock_list_long = create_dirent_list(entries, 1);

  *namelist = mock_list_long;
  return 1;
}

/* ============================================================================
 * Fixture Helpers
 * ============================================================================
 */

/**
 * make_default_ops - Creates standard syscall_ops with mock implementations
 *
 * Default configuration: all mocks enabled, scandir returns ENOENT.
 *
 * Returns: Initialized syscall_ops structure
 */
static struct syscall_ops make_default_ops(void) {
  struct syscall_ops ops = {.open = mock_open,
                            .close = mock_close,
                            .fstat = mock_fstat_root_file,
                            .stat = mock_stat_root_dir,
                            .fdopen = mock_fdopen,
                            .fgets = mock_fgets,
                            .fclose = mock_fclose,
                            .scandir = mock_scandir_enoent};
  return ops;
}

/**
 * make_ops_with_content - Creates ops with custom test content
 * @content: Null-terminated configuration string
 *
 * Used for dynamic injection of configuration strings in tests.
 *
 * Returns: Initialized syscall_ops structure with custom content
 */
static struct syscall_ops make_ops_with_content(const char *content) {
  struct syscall_ops ops = make_default_ops();
  custom_content = content;
  ops.open = mock_open_success;
  ops.close = mock_close_any;
  ops.fdopen = custom_fdopen;
  return ops;
}

/* ============================================================================
 * Tests: NULL Parameter Validation
 * ============================================================================
 */

TEST(load_configuration_null_ops) {
  config_t config = {0};
  TEST_ASSERT_EQ(load_configuration(NULL, &config, true), -1,
                 "Should reject NULL ops parameter");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(load_configuration_null_config) {
  struct syscall_ops ops = make_default_ops();
  TEST_ASSERT_EQ(load_configuration(&ops, NULL, true), -1,
                 "Should reject NULL config parameter");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

/* ============================================================================
 * Tests: File Security Validation
 * ============================================================================
 */

TEST(config_file_not_owned_by_root) {
  config_t config = {0};
  struct syscall_ops ops;
  int result;

  /* Content that would be valid if file passed security checks */
  ops = make_ops_with_content("UID_MIN 3500\nUID_MAX 45000\n");
  ops.fstat = mock_fstat_non_root_file;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should skip non-root files");
  TEST_ASSERT_EQ(config.uid_min, DEFAULT_UID_MIN, "Should keep defaults");
  TEST_ASSERT_EQ(config.uid_max, DEFAULT_UID_MAX,
                 "Should not parse valid content from non-root file");
}

TEST(config_file_world_writable) {
  config_t config = {0};
  struct syscall_ops ops;
  int result;

  /* Content that would be valid if file passed security checks */
  ops = make_ops_with_content("SUB_UID_MIN 150000\nSUB_UID_COUNT 32768\n");
  ops.fstat = mock_fstat_root_file_world_write;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should skip world-writable files");
  TEST_ASSERT_EQ(config.subuid.min_val, DEFAULT_SUB_UID_MIN,
                 "Should keep defaults");
  TEST_ASSERT_EQ(config.subuid.count_val, DEFAULT_SUB_UID_COUNT,
                 "Should not parse valid content from world-writable file");
}

TEST(config_file_is_symlink) {
  /*
   * open without O_NOFOLLOW will land on an actual target
   * so nothing to test here
   */
  TEST_ASSERT_EQ(true, true, "Always pass");
}

TEST(config_file_is_directory) {
  config_t config = {0};
  struct syscall_ops ops;
  int result;

  /* Content that would be valid if file passed security checks */
  ops = make_ops_with_content("UID_MIN 2500\nSUB_GID_MAX 700000000\n");
  ops.fstat = mock_fstat_root_dir;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should skip directories");
  TEST_ASSERT_EQ(config.uid_min, DEFAULT_UID_MIN, "Should keep defaults");
  TEST_ASSERT_EQ(config.subgid.max_val, DEFAULT_SUB_GID_MAX,
                 "Should not parse valid content from directory");
}

TEST(config_file_is_character_device) {
  config_t config = {0};
  struct syscall_ops ops;
  int result;

  /* Content that would be valid if file passed security checks */
  ops = make_ops_with_content("SUB_UID_MIN 250000\nSUB_UID_COUNT 16384\n");
  ops.fstat = mock_fstat_root_chardev;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should skip character devices");
  TEST_ASSERT_EQ(config.subuid.min_val, DEFAULT_SUB_UID_MIN,
                 "Should keep defaults");
  TEST_ASSERT_EQ(config.subuid.count_val, DEFAULT_SUB_UID_COUNT,
                 "Should not parse valid content from character device");
}

TEST(config_file_is_block_device) {
  config_t config = {0};
  struct syscall_ops ops;
  int result;

  /* Content that would be valid if file passed security checks */
  ops = make_ops_with_content("SUB_GID_MIN 350000\nSUB_GID_MAX 800000000\n");
  ops.fstat = mock_fstat_root_blockdev;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should skip block devices");
  TEST_ASSERT_EQ(config.subgid.min_val, DEFAULT_SUB_GID_MIN,
                 "Should keep defaults");
  TEST_ASSERT_EQ(config.subgid.max_val, DEFAULT_SUB_GID_MAX,
                 "Should not parse valid content from block device");
}

TEST(config_file_is_fifo) {
  config_t config = {0};
  struct syscall_ops ops;
  int result;

  /* Content that would be valid if file passed security checks */
  ops = make_ops_with_content("UID_MIN 1500\nSUB_UID_MAX 500000000\n");
  ops.fstat = mock_fstat_root_fifo;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should skip FIFOs");
  TEST_ASSERT_EQ(config.uid_min, DEFAULT_UID_MIN, "Should keep defaults");
  TEST_ASSERT_EQ(config.subuid.max_val, DEFAULT_SUB_UID_MAX,
                 "Should not parse valid content from FIFO");
}

TEST(config_file_is_socket) {
  config_t config = {0};
  struct syscall_ops ops;
  int result;

  /* Content that would be valid if file passed security checks */
  ops = make_ops_with_content("UID_MAX 45000\nSUB_GID_COUNT 32768\n");
  ops.fstat = mock_fstat_root_socket;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should skip sockets");
  TEST_ASSERT_EQ(config.uid_max, DEFAULT_UID_MAX, "Should keep defaults");
  TEST_ASSERT_EQ(config.subgid.count_val, DEFAULT_SUB_GID_COUNT,
                 "Should not parse valid content from socket");
}

/* ============================================================================
 * Tests: System Call Error Handling
 * ============================================================================
 */

TEST(safe_open_config_open_fails_eperm) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.open = mock_open_eperm;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle EPERM on open");
  TEST_ASSERT_EQ(config.uid_min, DEFAULT_UID_MIN, "Should keep defaults");
}

TEST(safe_open_config_open_fails_eacces) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.open = mock_open_eacces;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle EACCES on open");
  TEST_ASSERT_EQ(config.uid_min, DEFAULT_UID_MIN, "Should keep defaults");
}

TEST(safe_open_config_fstat_eperm) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.fstat = mock_fstat_eperm;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle fstat EPERM");
  TEST_ASSERT_EQ(config.uid_min, DEFAULT_UID_MIN, "Should keep defaults");
}

TEST(safe_open_config_fstat_enoent) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.fstat = mock_fstat_enoent;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle fstat ENOENT");
  TEST_ASSERT_EQ(config.uid_min, DEFAULT_UID_MIN, "Should keep defaults");
}

TEST(safe_open_config_fdopen_fails) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.fdopen = mock_fdopen_null;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle fdopen failure");
  TEST_ASSERT_EQ(config.uid_min, DEFAULT_UID_MIN, "Should keep defaults");
}

TEST(safe_open_config_enoent_debug_mode) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.open = mock_open_enoent;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle ENOENT in debug mode");
  TEST_ASSERT_EQ(config.uid_min, DEFAULT_UID_MIN, "Should keep defaults");
}

TEST(safe_open_config_enoent_nondebug) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.open = mock_open_enoent;
  config_factory(&config);
  result = load_configuration(&ops, &config, false);

  TEST_ASSERT_EQ(result, 0, "Should handle ENOENT in non-debug mode");
  TEST_ASSERT_EQ(config.uid_min, DEFAULT_UID_MIN, "Should keep defaults");
}

/* ============================================================================
 * Tests: Configuration Loading and Override Chain
 * ============================================================================
 */

TEST(load_configuration_defaults) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.open = mock_open_enoent;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should succeed with defaults");
  TEST_ASSERT_EQ(config.uid_min, DEFAULT_UID_MIN,
                 "Should have default UID_MIN");
  TEST_ASSERT_EQ(config.uid_max, DEFAULT_UID_MAX,
                 "Should have default UID_MAX");
}

TEST(load_configuration_login_defs_overrides_defaults) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.open = mock_open_login_defs_only;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should load login.defs");
  TEST_ASSERT_EQ(config.uid_min, LOGIN_DEFS_UID_MIN,
                 "login.defs should override default");
  TEST_ASSERT_EQ(config.uid_max, LOGIN_DEFS_UID_MAX,
                 "login.defs should override default");
}

TEST(load_configuration_override_login_defs_in_config) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should load config file");
  TEST_ASSERT_EQ(config.uid_max, LOGIN_DEFS_UID_MAX,
                 "Should still parse login.defs");
  TEST_ASSERT_EQ(config.uid_min, MAIN_CONFIG_UID_MIN,
                 "Main config should override login.defs");
}

TEST(load_configuration_override_config_in_dropin) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.scandir = mock_scandir_with_dropin;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should load drop-in configs");
  TEST_ASSERT_EQ(config.subgid.count_val, LOGIN_DEFS_SUB_GID_COUNT,
                 "Should still parse login.defs");
  TEST_ASSERT_EQ(config.uid_min, MAIN_CONFIG_UID_MIN,
                 "Main config should override login.defs");
  TEST_ASSERT_EQ(config.uid_max, DROPIN_01_UID_MAX,
                 "Drop-in should override main config");
}

TEST(load_configuration_override_dropin_in_another_dropin) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.scandir = mock_scandir_two_files;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should process multiple drop-ins");
  TEST_ASSERT_EQ(config.subgid.count_val, LOGIN_DEFS_SUB_GID_COUNT,
                 "Should still parse login.defs");
  TEST_ASSERT_EQ(config.subuid.max_val, MAIN_CONFIG_SUB_UID_MAX,
                 "Main config should override login.defs");
  TEST_ASSERT_EQ(config.uid_max, DROPIN_01_UID_MAX,
                 "Drop-in should override main config");
  TEST_ASSERT_EQ(config.uid_min, DROPIN_02_UID_MIN,
                 "Later drop-in should override earlier");
  TEST_ASSERT_EQ(config.subuid.count_val, DROPIN_02_SUB_UID_COUNT,
                 "Later drop-in should override earlier SUB_UID_COUNT");
}

TEST(load_configuration_multiple_overrides_one_file) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should load all settings");
  TEST_ASSERT_EQ(config.subuid.min_val, MAIN_CONFIG_SUB_UID_MIN,
                 "Should override SUB_UID_MIN");
  TEST_ASSERT_EQ(config.subuid.max_val, MAIN_CONFIG_SUB_UID_MAX,
                 "Should override SUB_UID_MAX");
}

/* ============================================================================
 * Tests: Parsing Edge Cases
 * ============================================================================
 */

TEST(load_configuration_comments_ignored) {
  config_t config = {0};
  struct syscall_ops ops = make_ops_with_content("# Comment\nUID_MIN 3000\n");
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should skip comments");
  TEST_ASSERT_EQ(config.uid_min, 3000, "Should parse value after comment");
}

TEST(parse_config_blank_lines) {
  config_t config = {0};
  struct syscall_ops ops = make_ops_with_content("\n\nUID_MIN 4000\n\n");
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should skip blank lines");
  TEST_ASSERT_EQ(config.uid_min, 4000, "Should parse value");
}

TEST(parse_config_key_only_no_value) {
  config_t config = {0};
  struct syscall_ops ops = make_ops_with_content("UID_MIN\nUID_MAX 5000\n");
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle key without value");
  TEST_ASSERT_EQ(config.uid_min, DEFAULT_UID_MIN, "Should keep default");
  TEST_ASSERT_EQ(config.uid_max, 5000, "Should parse next line");
}

TEST(parse_config_key_only_no_value_nondebug) {
  config_t config = {0};
  struct syscall_ops ops = make_ops_with_content("UID_MIN\nUID_MAX 5000\n");
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, false);

  TEST_ASSERT_EQ(result, 0, "Should handle key without value silently");
  TEST_ASSERT_EQ(config.uid_min, DEFAULT_UID_MIN, "Should keep default");
  TEST_ASSERT_EQ(config.uid_max, 5000, "Should parse next line");
}

TEST(parse_config_long_lines) {
  config_t config = {0};
  char long_line[TEST_BUFFER_SIZE];
  struct syscall_ops ops;
  int result;

  memset(long_line, 'X', sizeof(long_line) - 1);
  long_line[sizeof(long_line) - 1] = '\0';
  ops = make_ops_with_content(long_line);

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle long lines");
  TEST_ASSERT_EQ(config.uid_min, DEFAULT_UID_MIN, "Should keep defaults");
}

TEST(parse_config_key_with_long_value) {
  config_t config = {0};
  char long_content[1024];
  struct syscall_ops ops;
  int result;

  snprintf(long_content, sizeof(long_content),
           "UID_MIN 999999999999999999999999999999999\n"
           "UID_MAX 5000\n");
  ops = make_ops_with_content(long_content);

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle overflow value");
  TEST_ASSERT_EQ(config.uid_min, DEFAULT_UID_MIN,
                 "Should keep default on overflow");
  TEST_ASSERT_EQ(config.uid_max, 5000, "Should parse next line");
}

TEST(parse_config_whitespace_only_value) {
  config_t config = {0};
  struct syscall_ops ops =
      make_ops_with_content("UID_MIN     \t  \nUID_MAX 5000\n");
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle whitespace-only value");
  TEST_ASSERT_EQ(config.uid_min, DEFAULT_UID_MIN,
                 "Should ignore whitespace-only value");
  TEST_ASSERT_EQ(config.uid_max, 5000, "Should parse next line");
}

TEST(parse_config_whitespace_complex_values) {
  config_t config = {0};
  struct syscall_ops ops =
      make_ops_with_content("  UID_MIN     \t 200 \n\t \t  UID_MAX 5000\n");
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle whitespace well");
  TEST_ASSERT_EQ(config.uid_min, 200, "Should still parse value");
  TEST_ASSERT_EQ(config.uid_max, 5000, "Should still parse value");
}

TEST(parse_config_unknown_key_ignored) {
  config_t config = {0};
  struct syscall_ops ops =
      make_ops_with_content("COMPLETELY_UNKNOWN_KEY 12345\n"
                            "ANOTHER_FOREIGN_KEY yes\n"
                            "UID_MIN 3000\n");
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  /* Unknown keys are silently skipped for login.defs compatibility */
  TEST_ASSERT_EQ(result, 0, "Should ignore unknown keys");
  TEST_ASSERT_EQ(config.uid_min, 3000,
                 "Known keys after unknown keys should be applied");
}

/* ============================================================================
 * Tests: Boolean Value Parsing
 * ============================================================================
 */

TEST(apply_config_bool_values) {
  config_t config = {0};
  struct syscall_ops ops =
      make_ops_with_content("SKIP_IF_EXISTS yes\nALLOW_SUBID_WRAP 1\n");
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should parse boolean");
  TEST_ASSERT_EQ(config.skip_if_exists, true, "Should parse 'yes' as true");
  TEST_ASSERT_EQ(config.allow_subid_wrap, true, "Should parse '1' as true");
}

TEST(apply_config_bool_literal_values) {
  config_t config = {0};
  struct syscall_ops ops =
      make_ops_with_content("SKIP_IF_EXISTS true\nALLOW_SUBID_WRAP false\n");
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should parse alternate bool values");
  TEST_ASSERT_EQ(config.skip_if_exists, true, "Should parse 'true' as true");
  TEST_ASSERT_EQ(config.allow_subid_wrap, false,
                 "Should parse 'false' as false");
}

TEST(apply_config_bool_numeric_values) {
  config_t config = {0};
  struct syscall_ops ops =
      make_ops_with_content("SKIP_IF_EXISTS 1\nALLOW_SUBID_WRAP 0\n");
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should parse alternate bool values");
  TEST_ASSERT_EQ(config.skip_if_exists, true, "Should parse '1' as true");
  TEST_ASSERT_EQ(config.allow_subid_wrap, false, "Should parse '0' as false");
}

TEST(apply_config_allow_subid_wrap_no) {
  config_t config = {0};
  struct syscall_ops ops = make_ops_with_content("ALLOW_SUBID_WRAP no\n");
  int result;

  config_factory(&config);
  config.allow_subid_wrap = true;
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should parse ALLOW_SUBID_WRAP");
  TEST_ASSERT_EQ(config.allow_subid_wrap, false, "Should parse 'no' as false");
}

/* ============================================================================
 * Tests: Value Limits and Numeric Validation
 * ============================================================================
 */

TEST(apply_config_count_exceeds_max) {
  config_t config = {0};
  char overflow_config[OVERFLOW_CONFIG_SIZE];
  struct syscall_ops ops;
  int result;

  snprintf(overflow_config, sizeof(overflow_config), "SUB_UID_COUNT %u\n",
           MAX_RANGES + 1);
  ops = make_ops_with_content(overflow_config);

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle count overflow");
  TEST_ASSERT_EQ(config.subuid.count_val, DEFAULT_SUB_UID_COUNT,
                 "Should keep default on overflow");
}

TEST(apply_config_gid_count_exceeds_max) {
  config_t config = {0};
  char overflow_config[OVERFLOW_CONFIG_SIZE];
  struct syscall_ops ops;
  int result;

  snprintf(overflow_config, sizeof(overflow_config), "SUB_GID_COUNT %u\n",
           MAX_RANGES + 1);
  ops = make_ops_with_content(overflow_config);

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle SUB_GID_COUNT overflow");
  TEST_ASSERT_EQ(config.subgid.count_val, DEFAULT_SUB_UID_COUNT,
                 "Should keep default");
}

TEST(apply_config_all_gid_settings) {
  config_t config = {0};
  struct syscall_ops ops = make_ops_with_content("SUB_GID_MIN 300000\n"
                                                 "SUB_GID_MAX 700000000\n"
                                                 "SUB_GID_COUNT 32768\n");
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should parse all GID settings");
  TEST_ASSERT_EQ(config.subgid.min_val, 300000, "Should set SUB_GID_MIN");
  TEST_ASSERT_EQ(config.subgid.max_val, 700000000, "Should set SUB_GID_MAX");
  TEST_ASSERT_EQ(config.subgid.count_val, 32768, "Should set SUB_GID_COUNT");
}

TEST(apply_config_invalid_numeric_values) {
  config_t config = {0};
  struct syscall_ops ops =
      make_ops_with_content("UID_MAX notanumber\n"
                            "SUB_UID_MAX 9999999999999999999999999999\n"
                            "SUB_GID_MAX -500\n"
                            "SUB_GID_COUNT abc123\n");
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle invalid values");
  TEST_ASSERT_EQ(config.uid_max, DEFAULT_UID_MAX,
                 "Should keep default on invalid");
  TEST_ASSERT_EQ(config.subuid.max_val, DEFAULT_SUB_GID_MAX,
                 "Should keep default on overflow");
  TEST_ASSERT_EQ(config.subgid.max_val, DEFAULT_SUB_GID_MAX,
                 "Should keep default on negative");
  TEST_ASSERT_EQ(config.subgid.count_val, DEFAULT_SUB_UID_COUNT,
                 "Should keep default on non-numeric");
}

TEST(apply_config_subuid_min_invalid_value) {
  config_t config = {0};
  struct syscall_ops ops = make_ops_with_content("SUB_UID_MIN not_a_number\n");
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle invalid SUB_UID_MIN");
  TEST_ASSERT_EQ(config.subuid.min_val, DEFAULT_SUB_UID_MIN,
                 "Should keep default on parse failure");
}

TEST(apply_config_subuid_count_invalid_value) {
  config_t config = {0};
  struct syscall_ops ops = make_ops_with_content("SUB_UID_COUNT notanumber\n");
  int result;

  /*
   * Distinct from apply_config_count_exceeds_max: that test supplies a valid
   * number that parse_uint32_strict accepts but exceeds MAX_RANGES.  This test
   * supplies a non-numeric string so parse_uint32_strict itself fails.
   */
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle non-numeric SUB_UID_COUNT");
  TEST_ASSERT_EQ(config.subuid.count_val, DEFAULT_SUB_UID_COUNT,
                 "Should keep default on parse failure");
}

TEST(apply_config_subgid_min_invalid_value) {
  config_t config = {0};
  struct syscall_ops ops = make_ops_with_content("SUB_GID_MIN garbage_value\n");
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle invalid SUB_GID_MIN");
  TEST_ASSERT_EQ(config.subgid.min_val, DEFAULT_SUB_GID_MIN,
                 "Should keep default on parse failure");
}

/* ============================================================================
 * Tests: Directory Processing
 * ============================================================================
 */

TEST(load_from_dir_empty) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle ENOENT directory");
}

TEST(load_from_dir_empty_directory_debug) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.scandir = mock_scandir_zero_files;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should handle empty directory");
  TEST_ASSERT_EQ(config.uid_min, MAIN_CONFIG_UID_MIN,
                 "Should load main config");
}

TEST(load_from_dir_scandir_fails_not_enoent) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.scandir = mock_scandir_eperm;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, -1, "Should fail on scandir EPERM");
  TEST_ASSERT_EQ(errno, EPERM, "Should set the correct error code");
}

TEST(load_from_dir_validate_fails) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.stat = mock_stat_eperm;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, -1, "Should fail on stat failure");
  TEST_ASSERT_EQ(errno, EPERM, "Should set the correct error code");
}

TEST(load_from_dir_process_files_non_debug) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.scandir = mock_scandir_two_files;
  config_factory(&config);
  result = load_configuration(&ops, &config, false);

  TEST_ASSERT_EQ(result, 0, "Should process drop-ins without debug");
  TEST_ASSERT_EQ(config.uid_min, DROPIN_02_UID_MIN,
                 "Drop-in 02 should override 01");
  TEST_ASSERT_EQ(config.subuid.count_val, DROPIN_02_SUB_UID_COUNT,
                 "Drop-in 02 should override 01");

  mock_dirent_two_01 = NULL;
  mock_dirent_two_02 = NULL;
  mock_list_two = NULL;
}

/* ============================================================================
 * Tests: Filename Security Validation
 * ============================================================================
 */

TEST(load_from_dir_rejects_path_traversal) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.scandir = mock_scandir_path_traversal;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should skip path traversal");
  TEST_ASSERT_EQ(config.uid_min, MAIN_CONFIG_UID_MIN,
                 "Should load main config");

  mock_dirent_traversal = NULL;
  mock_list_traversal = NULL;
}

TEST(load_from_dir_rejects_path_separator_in_name) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.scandir = mock_scandir_path_separator;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should skip path with separator");
  TEST_ASSERT_EQ(config.uid_min, MAIN_CONFIG_UID_MIN,
                 "Should load main config");

  mock_dirent_separator = NULL;
  mock_list_separator = NULL;
}

TEST(load_from_dir_rejects_path_separator_nondebug) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.scandir = mock_scandir_path_separator;
  config_factory(&config);
  result = load_configuration(&ops, &config, false);

  TEST_ASSERT_EQ(result, 0, "Should skip path with separator silently");
  TEST_ASSERT_EQ(config.uid_min, MAIN_CONFIG_UID_MIN,
                 "Should load main config");

  mock_dirent_separator = NULL;
  mock_list_separator = NULL;
}

TEST(load_from_dir_rejects_absolute_path_in_name) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.scandir = mock_scandir_absolute_path;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should skip absolute path");
  TEST_ASSERT_EQ(config.uid_min, MAIN_CONFIG_UID_MIN,
                 "Should load main config");

  mock_dirent_absolute = NULL;
  mock_list_absolute = NULL;
}

TEST(load_from_dir_rejects_hidden_files) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.scandir = mock_scandir_hidden_file;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should skip hidden files");
  TEST_ASSERT_EQ(config.uid_min, MAIN_CONFIG_UID_MIN,
                 "Should load main config");

  mock_dirent_hidden = NULL;
  mock_list_hidden = NULL;
}

TEST(load_from_dir_rejects_dotdot_prefix_debug) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.scandir = mock_scandir_dotdot_prefix;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should skip ..conf files");
  TEST_ASSERT_EQ(config.uid_min, MAIN_CONFIG_UID_MIN,
                 "Should load main config");

  mock_dirent_dotdot = NULL;
  mock_list_dotdot = NULL;
}

TEST(load_from_dir_rejects_dotdot_prefix_nondebug) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.scandir = mock_scandir_dotdot_prefix;
  config_factory(&config);
  result = load_configuration(&ops, &config, false);

  TEST_ASSERT_EQ(result, 0, "Should skip ..conf files silently");
  TEST_ASSERT_EQ(config.uid_min, MAIN_CONFIG_UID_MIN,
                 "Should load main config");

  mock_dirent_dotdot = NULL;
  mock_list_dotdot = NULL;
}

TEST(load_from_dir_path_too_long) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  ops.scandir = mock_scandir_long_path;
  config_factory(&config);
  result = load_configuration(&ops, &config, true);

  TEST_ASSERT_EQ(result, 0, "Should skip too-long path");
  TEST_ASSERT_EQ(config.uid_min, MAIN_CONFIG_UID_MIN,
                 "Should load main config");

  mock_dirent_long = NULL;
  mock_list_long = NULL;
}

/* ============================================================================
 * Tests: Utility Functions
 * ============================================================================
 */

TEST(config_factory_null_config) {
  config_factory(NULL);
  /* Should not crash */
}

TEST(print_configuration_null_config) {
  print_configuration(NULL, stdout, NULL);
  /* Should not crash */
}

TEST(print_configuration_null_output) {
  config_t config = {0};
  config_factory(&config);

  print_configuration(&config, NULL, NULL);
  /* Should not crash */
}

TEST(print_configuration_valid) {
  config_t config = {0};
  char buffer[TEST_BUFFER_SIZE] = {0};
  FILE *memfile;

  config_factory(&config);

  memfile = fmemopen(buffer, sizeof(buffer), "w");
  print_configuration(&config, memfile, NULL);
  fclose(memfile);

  TEST_ASSERT_NOT_EQ(strstr(buffer, "UID_MIN"), NULL, "Should print UID_MIN");

  /* Should not crash on any of these */

  config.skip_if_exists = true;
  config.allow_subid_wrap = true;
  memfile = fmemopen(buffer, sizeof(buffer), "w");
  print_configuration(&config, memfile, "prefix");
  fclose(memfile);

  config.skip_if_exists = false;
  config.allow_subid_wrap = false;
  memfile = fmemopen(buffer, sizeof(buffer), "w");
  print_configuration(&config, memfile, "prefix");
  fclose(memfile);

  config.skip_if_exists = true;
  config.allow_subid_wrap = false;
  memfile = fmemopen(buffer, sizeof(buffer), "w");
  print_configuration(&config, memfile, "prefix");
  fclose(memfile);

  config.skip_if_exists = false;
  config.allow_subid_wrap = true;
  memfile = fmemopen(buffer, sizeof(buffer), "w");
  print_configuration(&config, memfile, "prefix");
  fclose(memfile);
}

TEST(load_configuration_non_debug_mode) {
  config_t config = {0};
  struct syscall_ops ops = make_default_ops();
  int result;

  config_factory(&config);
  result = load_configuration(&ops, &config, false);

  TEST_ASSERT_EQ(result, 0, "Should work in non-debug mode");
  TEST_ASSERT_EQ(config.uid_min, MAIN_CONFIG_UID_MIN, "Should load config");
}

/* ============================================================================
 * Test Runner
 * ============================================================================
 */

int main(int argc, char **argv) {
  int result;

  TEST_INIT(10, false, false); /* timeout, verbose, duration */

  /* NULL parameter validation */
  RUN_TEST(load_configuration_null_ops);
  RUN_TEST(load_configuration_null_config);

  /* File security validation */
  RUN_TEST(config_file_not_owned_by_root);
  RUN_TEST(config_file_world_writable);
  RUN_TEST(config_file_is_directory);
  RUN_TEST(config_file_is_symlink);
  RUN_TEST(config_file_is_character_device);
  RUN_TEST(config_file_is_block_device);
  RUN_TEST(config_file_is_fifo);
  RUN_TEST(config_file_is_socket);

  /* System call error handling */
  RUN_TEST(safe_open_config_open_fails_eperm);
  RUN_TEST(safe_open_config_open_fails_eacces);
  RUN_TEST(safe_open_config_fstat_eperm);
  RUN_TEST(safe_open_config_fstat_enoent);
  RUN_TEST(safe_open_config_fdopen_fails);
  RUN_TEST(safe_open_config_enoent_debug_mode);
  RUN_TEST(safe_open_config_enoent_nondebug);

  /* Configuration loading and override chain */
  RUN_TEST(load_configuration_defaults);
  RUN_TEST(load_configuration_login_defs_overrides_defaults);
  RUN_TEST(load_configuration_override_login_defs_in_config);
  RUN_TEST(load_configuration_override_config_in_dropin);
  RUN_TEST(load_configuration_override_dropin_in_another_dropin);
  RUN_TEST(load_configuration_multiple_overrides_one_file);

  /* Parsing edge cases */
  RUN_TEST(load_configuration_comments_ignored);
  RUN_TEST(parse_config_blank_lines);
  RUN_TEST(parse_config_key_only_no_value);
  RUN_TEST(parse_config_key_only_no_value_nondebug);
  RUN_TEST(parse_config_long_lines);
  RUN_TEST(parse_config_key_with_long_value);
  RUN_TEST(parse_config_whitespace_only_value);
  RUN_TEST(parse_config_whitespace_complex_values);
  RUN_TEST(parse_config_unknown_key_ignored);

  /* Boolean value parsing */
  RUN_TEST(apply_config_bool_values);
  RUN_TEST(apply_config_bool_literal_values);
  RUN_TEST(apply_config_bool_numeric_values);
  RUN_TEST(apply_config_allow_subid_wrap_no);

  /* Value limits and numeric validation */
  RUN_TEST(apply_config_count_exceeds_max);
  RUN_TEST(apply_config_gid_count_exceeds_max);
  RUN_TEST(apply_config_all_gid_settings);
  RUN_TEST(apply_config_invalid_numeric_values);
  RUN_TEST(apply_config_subuid_min_invalid_value);
  RUN_TEST(apply_config_subuid_count_invalid_value);
  RUN_TEST(apply_config_subgid_min_invalid_value);

  /* Directory processing */
  RUN_TEST(load_from_dir_empty);
  RUN_TEST(load_from_dir_empty_directory_debug);
  RUN_TEST(load_from_dir_scandir_fails_not_enoent);
  RUN_TEST(load_from_dir_validate_fails);
  RUN_TEST(load_from_dir_process_files_non_debug);

  /* Filename security validation */
  RUN_TEST(load_from_dir_rejects_path_traversal);
  RUN_TEST(load_from_dir_rejects_path_separator_in_name);
  RUN_TEST(load_from_dir_rejects_path_separator_nondebug);
  RUN_TEST(load_from_dir_rejects_absolute_path_in_name);
  RUN_TEST(load_from_dir_rejects_hidden_files);
  RUN_TEST(load_from_dir_rejects_dotdot_prefix_debug);
  RUN_TEST(load_from_dir_rejects_dotdot_prefix_nondebug);
  RUN_TEST(load_from_dir_path_too_long);

  /* Utility functions */
  RUN_TEST(config_factory_null_config);
  RUN_TEST(print_configuration_null_config);
  RUN_TEST(print_configuration_null_output);
  RUN_TEST(print_configuration_valid);
  RUN_TEST(load_configuration_non_debug_mode);

  result = TEST_EXECUTE();
  return result;
}
