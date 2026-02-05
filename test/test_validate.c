/**
 * test_validate.c - Tests for input validation functions
 */

/* clang-format off */
#include "autoconf.h"
#include "static-subid.h"
#include "syscall_ops.h"
/* clang-format on */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "test_framework.h"
#include "test_helpers/all.h"

/* ============================================================================
 * Constants - Buffer Sizes and Test Values
 * ============================================================================
 */

/* Buffer size constants */
enum {
  PATH_OVERFLOW_SIZE = PATH_MAX + 1000, /* Exceeds PATH_MAX for testing */
  USERNAME_OVERFLOW_SIZE = 8192         /* Exceeds _SC_LOGIN_NAME_MAX */
};

/* UID test values - standard user range */
enum {
  TEST_UID_BELOW_MIN = 999,   /* Below typical minimum (1000) */
  TEST_UID_MIN = 1000,        /* Typical minimum regular user UID */
  TEST_UID_MID_RANGE = 30000, /* Middle of typical user range */
  TEST_UID_MAX = 60000,       /* Default maximum regular user UID */
  TEST_UID_ABOVE_MAX = 60001, /* Just above maximum */
  TEST_UID_HIGH = 100000      /* Well above regular user range */
};

/* Subordinate ID range boundaries (default configuration) */
enum {
  SUBID_MIN = 100000,         /* Start of subordinate ID space */
  SUBID_MID = 300000,         /* Middle of subordinate range */
  SUBID_MAX = 600100000,      /* End of subordinate ID space */
  SUBID_ABOVE_MAX = 600100001 /* Just above subordinate range */
};

/* Parsing test values */
enum {
  PARSE_TEST_SMALL = 123,
  PARSE_TEST_MID = 1000,
};

/* ============================================================================
 * Helper Functions - Test Execution
 * ============================================================================
 */

/**
 * assert_parse_result - Helper to test parse_uint32_strict
 * @input: Input string to parse
 * @expected_ret: Expected return value (0 success, -1 error)
 * @expected_value: Expected parsed value (ignored if expected_ret != 0)
 * @desc: Test description
 *
 * Reduces boilerplate in parse_uint32_strict tests by combining the
 * call and assertions into a single function.
 */
static void assert_parse_result(const char *input, int expected_ret,
                                uint32_t expected_value, const char *desc) {
  uint32_t result = 0;
  int ret;
  errno = 0;

  ret = parse_uint32_strict(input, &result);

  TEST_ASSERT_EQ(ret, expected_ret, desc);
  if (expected_ret == 0) {
    TEST_ASSERT_EQ(result, expected_value, "Should have correct value");
  }
}

/**
 * assert_config_dir_validation - Helper to test validate_config_dir
 * @stat_mock: stat mock function to use (or NULL for no mock)
 * @path: Configuration directory path to validate
 * @expected: Expected validation result
 * @desc: Test description
 *
 * Centralizes config_dir validation testing by setting up syscall_ops
 * and performing the validation check.
 */
static void
assert_config_dir_validation(int (*stat_mock)(const char *, struct stat *),
                             const char *path, int expected, const char *desc) {
  struct syscall_ops test_ops = syscall_ops_default;
  int result;

  if (stat_mock != NULL) {
    test_ops.stat = stat_mock;
  }

  result = validate_config_dir(&test_ops, path, true);
  TEST_ASSERT_EQ(result, expected, desc);
}

/* ============================================================================
 * Tests - Path Validation
 * ============================================================================
 */

TEST(validate_path_null) {
  TEST_ASSERT_EQ(validate_path(NULL), -1, "Should reject NULL");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(validate_path_empty) {
  TEST_ASSERT_EQ(validate_path(""), -1, "Should reject empty");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(validate_path_too_long) {
  char long_path[PATH_OVERFLOW_SIZE];

  memset(long_path, 'a', sizeof(long_path) - 1);
  long_path[sizeof(long_path) - 1] = '\0';
  long_path[0] = '/';

  TEST_ASSERT_EQ(validate_path(long_path), -1, "Should reject large path");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(validate_path_traversal_dotdot) {
  TEST_ASSERT_EQ(validate_path("/etc/.."), -1, "Should reject '/..'");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(validate_path_traversal_dotdot_slash) {
  TEST_ASSERT_EQ(validate_path("/etc/../passwd"), -1, "Should reject '/../'");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(validate_path_relative) {
  TEST_ASSERT_EQ(validate_path("relative/path/file.txt"), -1,
                 "Should reject relative paths");
  TEST_ASSERT_EQ(validate_path("../relative/path/file.txt"), -1,
                 "Should reject relative paths");
}

TEST(validate_path_valid) {
  TEST_ASSERT_EQ(validate_path("/etc/passwd"), 0, "Should accept valid paths");
  TEST_ASSERT_EQ(validate_path("/tmp/test.conf"), 0,
                 "Should accept valid paths");
  TEST_ASSERT_EQ(validate_path("/var/lib/data/file.txt"), 0,
                 "Should accept valid paths");
}

/* ============================================================================
 * Tests - Configuration Directory Validation
 * ============================================================================
 */

TEST(validate_config_dir_null_ops) {
  TEST_ASSERT_EQ(validate_config_dir(NULL, "/etc", true), -1,
                 "Should reject NULL ops");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(validate_config_dir_null_directory) {
  struct syscall_ops test_ops = syscall_ops_default;

  TEST_ASSERT_EQ(validate_config_dir(&test_ops, NULL, true), -1,
                 "Should reject NULL directory");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(validate_config_dir_invalid_path) {
  struct syscall_ops test_ops = syscall_ops_default;

  TEST_ASSERT_EQ(validate_config_dir(&test_ops, "/etc/../root", true), -1,
                 "Should reject invalid paths");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(validate_config_dir_not_owned_by_root) {
  assert_config_dir_validation(mock_stat_non_root_dir, CONFIG_DROPIN_DIR_PATH,
                               -1, "Should reject non-root config dir");
  TEST_ASSERT_EQ(errno, EPERM, "Should set the correct error code");
}

TEST(validate_config_dir_world_writable) {
  assert_config_dir_validation(mock_stat_root_dir_world_write,
                               CONFIG_DROPIN_DIR_PATH, -1,
                               "Should reject world-writable config dir");
  TEST_ASSERT_EQ(errno, EPERM, "Should set the correct error code");
}

TEST(validate_config_dir_not_directory) {
  assert_config_dir_validation(mock_stat_root_file, CONFIG_DROPIN_DIR_PATH, -1,
                               "Should reject regular file");
  TEST_ASSERT_EQ(errno, ENOTDIR, "Should set the correct error code");
}

TEST(validate_config_dir_does_not_exist) {
  assert_config_dir_validation(mock_stat_enoent, CONFIG_DROPIN_DIR_PATH, 0,
                               "Should allow missing config dir");
}

TEST(validate_config_dir_does_not_exist_non_debug) {
  struct syscall_ops test_ops = syscall_ops_default;
  test_ops.stat = mock_stat_enoent;

  TEST_ASSERT_EQ(validate_config_dir(&test_ops, CONFIG_DROPIN_DIR_PATH, false),
                 0, "Should allow missing config dir without debug output");
}

TEST(validate_config_dir_eperm) {
  assert_config_dir_validation(mock_stat_eperm, CONFIG_DROPIN_DIR_PATH, -1,
                               "Should error on EPERM");
  TEST_ASSERT_EQ(errno, EPERM, "Should set the correct error code");
}

TEST(validate_config_dir_valid) {
  assert_config_dir_validation(mock_stat_root_dir, CONFIG_DROPIN_DIR_PATH, 0,
                               "Should accept properly secured directory");
}

/* ============================================================================
 * Tests - Configuration Directory Symlink Validation
 * ============================================================================
 */

TEST(validate_config_dir_symlink_to_non_root_dir) {
  assert_config_dir_validation(mock_stat_non_root_dir, CONFIG_DROPIN_DIR_PATH,
                               -1,
                               "Should reject symlink to non-root directory");
  TEST_ASSERT_EQ(errno, EPERM, "Should set the correct error code");
}

TEST(validate_config_dir_symlink_to_world_writable_dir) {
  assert_config_dir_validation(
      mock_stat_root_dir_world_write, CONFIG_DROPIN_DIR_PATH, -1,
      "Should reject symlink to world-writable directory");
  TEST_ASSERT_EQ(errno, EPERM, "Should set the correct error code");
}

TEST(validate_config_dir_symlink_to_file) {
  assert_config_dir_validation(mock_stat_root_file, CONFIG_DROPIN_DIR_PATH, -1,
                               "Should reject symlink to regular file");
  TEST_ASSERT_EQ(errno, ENOTDIR, "Should set the correct error code");
}

TEST(validate_config_dir_broken_symlink) {
  assert_config_dir_validation(
      mock_stat_enoent, CONFIG_DROPIN_DIR_PATH, 0,
      "Should allow broken symlink same as missing directory");
}

TEST(validate_config_dir_symlink_stat_eperm) {
  assert_config_dir_validation(mock_stat_eperm, CONFIG_DROPIN_DIR_PATH, -1,
                               "Should error on stat EPERM for symlink target");
  TEST_ASSERT_EQ(errno, EPERM, "Should set the correct error code");
}

/* ============================================================================
 * Tests - Username Validation
 * ============================================================================
 */

TEST(validate_username_null) {
  TEST_ASSERT_EQ(validate_username(NULL), -1, "Should reject NULL");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(validate_username_too_long) {
  char long_username[USERNAME_OVERFLOW_SIZE];

  memset(long_username, 'a', sizeof(long_username) - 1);
  long_username[sizeof(long_username) - 1] = '\0';

  TEST_ASSERT_EQ(validate_username(long_username), -1,
                 "Should reject very long username");
  TEST_ASSERT_EQ(errno, ENAMETOOLONG, "Should set the correct error code");
}

TEST(validate_username_invalid) {
  FOR_EACH_INVALID_USERNAME(TEST_ASSERT_EQ(validate_username(case_ptr->input),
                                           -1, case_ptr->reason););
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(validate_username_valid) {
  FOR_EACH_VALID_USERNAME(
      TEST_ASSERT_EQ(validate_username(case_ptr->input), 0, case_ptr->reason););
}

/* ============================================================================
 * Tests - Boolean Parsing
 * ============================================================================
 */

TEST(parse_bool_null) {
  TEST_ASSERT_EQ(parse_bool(NULL, false), false,
                 "Should return default for NULL");
  TEST_ASSERT_EQ(parse_bool(NULL, true), true,
                 "Should return default for NULL");
}

TEST(parse_bool_true_values) {
  TEST_ASSERT_EQ(parse_bool("true", false), true, "Should parse 'true'");
  TEST_ASSERT_EQ(parse_bool("yes", false), true, "Should parse 'yes'");
  TEST_ASSERT_EQ(parse_bool("1", false), true, "Should parse '1'");
}

TEST(parse_bool_false_values) {
  TEST_ASSERT_EQ(parse_bool("false", true), false, "Should parse 'false'");
  TEST_ASSERT_EQ(parse_bool("no", true), false, "Should parse 'no'");
  TEST_ASSERT_EQ(parse_bool("0", true), false, "Should parse '0'");
}

TEST(parse_bool_invalid_defaults_to_default) {
  TEST_ASSERT_EQ(parse_bool("invalid", false), false,
                 "Should use default for invalid");
  TEST_ASSERT_EQ(parse_bool("invalid", true), true,
                 "Should use default for invalid");
  TEST_ASSERT_EQ(parse_bool("maybe", false), false,
                 "Should use default for invalid");
}

/* ============================================================================
 * Tests - Strict Unsigned Integer Parsing: Input Validation
 * ============================================================================
 */

TEST(parse_uint32_null_input) {
  uint32_t result = 0;
  int ret;

  ret = parse_uint32_strict(NULL, &result);
  TEST_ASSERT_EQ(ret, -1, "Should reject NULL input");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(parse_uint32_null_result) {
  int ret;

  ret = parse_uint32_strict("123", NULL);
  TEST_ASSERT_EQ(ret, -1, "Should reject NULL result pointer");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(parse_uint32_empty_string) {
  assert_parse_result("", -1, 0, "Should reject empty string");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(parse_uint32_leading_sign) {
  assert_parse_result("+123", -1, 0, "Should reject plus sign");
  assert_parse_result("-123", -1, 0, "Should reject minus sign");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(parse_uint32_leading_whitespace) {
  /* Single whitespace characters */
  assert_parse_result(" 123", -1, 0, "Should reject leading space");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("\t123", -1, 0, "Should reject leading tab");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("\n123", -1, 0, "Should reject leading newline");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  /* Multiple whitespace characters */
  assert_parse_result("  123", -1, 0, "Should reject multiple leading spaces");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("\t\t123", -1, 0, "Should reject multiple leading tabs");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("\n\n123", -1, 0,
                      "Should reject multiple leading newlines");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  /* Mixed whitespace combinations */
  assert_parse_result(" \t123", -1, 0,
                      "Should reject mixed leading whitespace");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("\t 123", -1, 0,
                      "Should reject mixed leading whitespace");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result(" \n123", -1, 0,
                      "Should reject mixed leading whitespace");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("\n 123", -1, 0,
                      "Should reject mixed leading whitespace");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result(" \t\n123", -1, 0,
                      "Should reject complex leading whitespace");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("\t\n 123", -1, 0,
                      "Should reject complex leading whitespace");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  /* Trailing whitespace */
  assert_parse_result("123 ", -1, 0, "Should reject trailing space");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("123\t", -1, 0, "Should reject trailing tab");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("123\n", -1, 0, "Should reject trailing newline");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("123  ", -1, 0, "Should reject multiple trailing spaces");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("123 \t", -1, 0,
                      "Should reject mixed trailing whitespace");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("123\n\t", -1, 0,
                      "Should reject mixed trailing whitespace");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  /* Both leading and trailing */
  assert_parse_result("  123  ", -1, 0, "Should reject surrounding spaces");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("\t123\t", -1, 0, "Should reject surrounding tabs");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result(" \t 123 \t ", -1, 0,
                      "Should reject mixed surrounding whitespace");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("  123 \n ", -1, 0,
                      "Should reject complex whitespace pattern");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("\t\n123\t\n", -1, 0,
                      "Should reject complex whitespace pattern");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result(" \n\t 123 \n\t ", -1, 0,
                      "Should reject complex whitespace pattern");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  /* Asymmetric combinations */
  assert_parse_result("\t123  ", -1, 0, "Should reject asymmetric whitespace");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("  123\t", -1, 0, "Should reject asymmetric whitespace");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("\t\n123  ", -1, 0,
                      "Should reject asymmetric whitespace");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  assert_parse_result("  123\t\n", -1, 0,
                      "Should reject asymmetric whitespace");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(parse_uint32_leading_zero) {
  assert_parse_result("0123", 0, 123, "Should trim leading zeros");
  assert_parse_result("00", 0, 0, "Should trim multiple zeros");
}

TEST(parse_uint32_non_digit) {
  assert_parse_result("123abc", -1, 0, "Should reject letters");
  assert_parse_result("12.34", -1, 0, "Should reject decimal point");
  assert_parse_result("12a34", -1, 0, "Should reject embedded letters");
}

TEST(parse_uint32_overflow) {
  assert_parse_result("4294967296", -1, 0, "Should reject UINT32_MAX + 1");
  assert_parse_result("9999999999", -1, 0, "Should reject large overflow");
}

TEST(parse_uint32_strtoull_erange) {
  assert_parse_result("99999999999999999999999999999999", -1, 0,
                      "Should detect ERANGE from strtoull");
}

TEST(parse_uint32_valid) {
  assert_parse_result("0", 0, 0, "Should parse zero");
  assert_parse_result("1", 0, 1, "Should parse one");
  assert_parse_result("123", 0, PARSE_TEST_SMALL, "Should parse 123");
  assert_parse_result("1000", 0, PARSE_TEST_MID, "Should parse 1000");
  assert_parse_result("4294967295", 0, UINT32_MAX_VAL,
                      "Should parse UINT32_MAX");
}

/* ============================================================================
 * Tests - UID Range Validation
 * ============================================================================
 */

TEST(validate_uid_range_null_config) {
  TEST_ASSERT_EQ(validate_uid_range(TEST_UID_MIN, NULL), -1,
                 "Should reject NULL");
}

TEST(validate_uid_range_below_min) {
  config_t config = {0};
  config_factory(&config);

  TEST_ASSERT_EQ(validate_uid_range(TEST_UID_BELOW_MIN, &config), -1,
                 "Should reject UID below minimum");
  TEST_ASSERT_EQ(validate_uid_range(TEST_UID_ROOT, &config), -1,
                 "Should reject root UID");
}

TEST(validate_uid_range_above_max) {
  config_t config = {0};
  config_factory(&config);

  TEST_ASSERT_EQ(validate_uid_range(TEST_UID_ABOVE_MAX, &config), -1,
                 "Should reject UID above maximum");
  TEST_ASSERT_EQ(validate_uid_range(TEST_UID_HIGH, &config), -1,
                 "Should reject high UID");
}

TEST(validate_uid_range_valid) {
  config_t config = {0};
  config_factory(&config);

  TEST_ASSERT_EQ(validate_uid_range(TEST_UID_MIN, &config), 0,
                 "Should accept minimum UID");
  TEST_ASSERT_EQ(validate_uid_range(TEST_UID_MID_RANGE, &config), 0,
                 "Should accept mid-range UID");
  TEST_ASSERT_EQ(validate_uid_range(TEST_UID_MAX, &config), 0,
                 "Should accept maximum UID");
}

/* ============================================================================
 * Tests - UID/Subordinate ID Overlap
 * ============================================================================
 */

TEST(validate_uid_subid_overlap_null_config) {
  TEST_ASSERT_EQ(validate_uid_subid_overlap(TEST_UID_MIN, NULL), -1,
                 "Should reject NULL");
}

TEST(validate_uid_subid_overlap_overlaps) {
  config_t config = {0};
  config_factory(&config);

  TEST_ASSERT_EQ(validate_uid_subid_overlap(SUBID_MIN, &config.subuid), -1,
                 "Should reject UID at subordinate minimum");
  TEST_ASSERT_EQ(validate_uid_subid_overlap(SUBID_MID, &config.subuid), -1,
                 "Should reject UID in subordinate range");
  TEST_ASSERT_EQ(validate_uid_subid_overlap(SUBID_MAX, &config.subuid), -1,
                 "Should reject UID at subordinate maximum");
}

TEST(validate_uid_subid_overlap_no_overlap) {
  config_t config = {0};
  config_factory(&config);

  TEST_ASSERT_EQ(validate_uid_subid_overlap(TEST_UID_MIN, &config.subuid), 0,
                 "Should accept UID below subordinate range");
  TEST_ASSERT_EQ(validate_uid_subid_overlap(TEST_UID_MAX, &config.subuid), 0,
                 "Should accept UID below subordinate range");
  TEST_ASSERT_EQ(validate_uid_subid_overlap(TEST_UID_BELOW_MIN, &config.subuid),
                 0, "Should accept UID below subordinate range");
  TEST_ASSERT_EQ(validate_uid_subid_overlap(SUBID_ABOVE_MAX, &config.subuid), 0,
                 "Should accept UID above subordinate range");
}

/* ============================================================================
 * Test Runner
 * ============================================================================
 */

int main(int argc, char **argv) {
  int result;

  TEST_INIT(10, false, false); /* timeout, verbose, duration */

  /* Path validation */
  RUN_TEST(validate_path_null);
  RUN_TEST(validate_path_empty);
  RUN_TEST(validate_path_too_long);
  RUN_TEST(validate_path_traversal_dotdot);
  RUN_TEST(validate_path_traversal_dotdot_slash);
  RUN_TEST(validate_path_relative);
  RUN_TEST(validate_path_valid);

  /* Configuration directory validation */
  RUN_TEST(validate_config_dir_null_ops);
  RUN_TEST(validate_config_dir_null_directory);
  RUN_TEST(validate_config_dir_invalid_path);
  RUN_TEST(validate_config_dir_not_owned_by_root);
  RUN_TEST(validate_config_dir_world_writable);
  RUN_TEST(validate_config_dir_not_directory);
  RUN_TEST(validate_config_dir_does_not_exist);
  RUN_TEST(validate_config_dir_does_not_exist_non_debug);
  RUN_TEST(validate_config_dir_eperm);
  RUN_TEST(validate_config_dir_valid);

  /* Configuration directory symlink validation */
  RUN_TEST(validate_config_dir_symlink_to_non_root_dir);
  RUN_TEST(validate_config_dir_symlink_to_world_writable_dir);
  RUN_TEST(validate_config_dir_symlink_to_file);
  RUN_TEST(validate_config_dir_broken_symlink);
  RUN_TEST(validate_config_dir_symlink_stat_eperm);

  /* Username validation */
  RUN_TEST(validate_username_null);
  RUN_TEST(validate_username_too_long);
  RUN_TEST(validate_username_invalid);
  RUN_TEST(validate_username_valid);

  /* Boolean parsing */
  RUN_TEST(parse_bool_null);
  RUN_TEST(parse_bool_true_values);
  RUN_TEST(parse_bool_false_values);
  RUN_TEST(parse_bool_invalid_defaults_to_default);

  /* Strict unsigned integer parsing */
  RUN_TEST(parse_uint32_null_input);
  RUN_TEST(parse_uint32_null_result);
  RUN_TEST(parse_uint32_empty_string);
  RUN_TEST(parse_uint32_leading_sign);
  RUN_TEST(parse_uint32_leading_whitespace);
  RUN_TEST(parse_uint32_leading_zero);
  RUN_TEST(parse_uint32_non_digit);
  RUN_TEST(parse_uint32_overflow);
  RUN_TEST(parse_uint32_strtoull_erange);
  RUN_TEST(parse_uint32_valid);

  /* UID range validation */
  RUN_TEST(validate_uid_range_null_config);
  RUN_TEST(validate_uid_range_below_min);
  RUN_TEST(validate_uid_range_above_max);
  RUN_TEST(validate_uid_range_valid);

  /* UID/Subordinate ID overlap */
  RUN_TEST(validate_uid_subid_overlap_null_config);
  RUN_TEST(validate_uid_subid_overlap_overlaps);
  RUN_TEST(validate_uid_subid_overlap_no_overlap);

  result = TEST_EXECUTE();
  return result;
}
