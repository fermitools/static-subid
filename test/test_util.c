/**
 * test_util.c - Tests for utility functions
 */

/* clang-format off */
#include "autoconf.h"
#include "static-subid.h"
#include "syscall_ops.h"
/* clang-format on */

#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "test_framework.h"
#include "test_helpers/all.h"

/* ============================================================================
 * Constants - Buffer Sizes and Test Values
 * ============================================================================
 */

/* Buffer size constants */
enum {
  STANDARD_USERNAME_BUFFER = 256, /* Standard buffer for username output */
  EXACT_FIT_TESTUSER_BUFFER = 9,  /* Exact size for "testuser" + null */
  TOO_SMALL_TESTUSER_BUFFER = 8,  /* One byte too small for "testuser" */
  TINY_USERNAME_BUFFER = 10,      /* Small buffer for overflow testing */
  LONG_USERNAME_TEST_SIZE = 8192  /* Very long username for validation */
};

/* Filter function return values look weird const helps avoid confusion */
enum {
  FILTER_REJECT = 0, /* Entry should be filtered out */
  FILTER_ACCEPT = 1  /* Entry should be accepted */
};

/* ============================================================================
 * Helper Functions - Test Execution
 * ============================================================================
 */

/**
 * assert_normalize_result - Helper to test normalize_config_line
 * @input: Input line to normalize
 * @expected: Expected output after normalization
 * @desc: Test description
 *
 * Reduces boilerplate in normalization tests by combining the call
 * and assertion into a single function.
 */
static void assert_normalize_result(char *input, const char *expected,
                                    const char *desc) {
  char *result = normalize_config_line(input);
  TEST_ASSERT_STR_EQ(result, expected, desc);
}

/**
 * assert_filter_result - Helper to test filter_conf_files
 * @filename: Filename to test (or NULL)
 * @expected: Expected filter result (FILTER_ACCEPT or FILTER_REJECT)
 * @desc: Test description
 *
 * Reduces boilerplate in filter tests by combining dirent setup,
 * filter call, and assertion.
 */
static void assert_filter_result(const char *filename, int expected,
                                 const char *desc) {
  struct dirent entry = {0};
  int result;

  if (filename != NULL) {
    strncpy(entry.d_name, filename, sizeof(entry.d_name) - 1);
  }

  result = filter_conf_files(filename != NULL ? &entry : NULL);
  TEST_ASSERT_EQ(result, expected, desc);
}

/**
 * test_resolve_user - Helper to test resolve_user with various scenarios
 * @ops: Syscall operations structure with mocked functions
 * @user_arg: User argument (username or UID string)
 * @expected_ret: Expected return value (0 success, -1 error)
 * @expected_uid: Expected UID value (ignored if expected_ret != 0)
 * @expected_username: Expected username (or NULL to skip check)
 * @username_bufsize: Size of username buffer
 * @debug: Debug mode flag
 * @desc: Test description
 *
 * Centralizes resolve_user testing by handling the common pattern of:
 * call resolve_user, check return value, verify UID and username if
 * successful.
 */
static void test_resolve_user(struct syscall_ops *ops, const char *user_arg,
                              int expected_ret, uint32_t expected_uid,
                              const char *expected_username,
                              size_t username_bufsize, bool debug,
                              const char *desc) {
  uint32_t uid = 0;
  char *username = NULL;
  int result;

  if (username_bufsize > 0) {
    username = calloc(1, username_bufsize);
    TEST_ASSERT_NOT_EQ(username, NULL, "Test setup: buffer allocation failed");
  }

  result = resolve_user(ops, user_arg, &uid, username, username_bufsize, debug);

  TEST_ASSERT_EQ(result, expected_ret, desc);

  if (expected_ret == 0) {
    TEST_ASSERT_EQ(uid, expected_uid, "Should set correct UID");
    if (expected_username != NULL && username != NULL) {
      TEST_ASSERT_STR_EQ(username, expected_username,
                         "Should set correct username");
    }
  }

  free(username);
}

/* ============================================================================
 * Tests - Configuration Line Normalization
 * ============================================================================
 */

TEST(normalize_null) {
  char *result = normalize_config_line(NULL);
  TEST_ASSERT_EQ(result, NULL, "Should return NULL");
}

TEST(normalize_empty_line) {
  char input[] = "";
  assert_normalize_result(input, "", "Should return empty");
}

TEST(normalize_only_whitespace) {
  char input1[] = "   ";
  char input2[] = "\t\t";
  char input3[] = "  \t  \t  ";
  char input4[] = "  \n  \t  ";

  assert_normalize_result(input1, "", "Should return empty for spaces");
  assert_normalize_result(input2, "", "Should return empty for tabs");
  assert_normalize_result(input3, "", "Should return empty for mixed");
  assert_normalize_result(input4, "", "Should return empty for mixed");
}

TEST(normalize_comment_only) {
  char input1[] = "# This is a comment";
  char input2[] = "  # Comment with leading space";
  char input3[] = "\t# Comment with leading tab";

  assert_normalize_result(input1, "", "Should remove comment");
  assert_normalize_result(input2, "",
                          "Should remove comment with leading space");
  assert_normalize_result(input3, "", "Should remove comment with leading tab");
}

TEST(normalize_with_trailing_comment) {
  char input1[] = "KEY VALUE # comment";
  char input2[] = "KEY VALUE  #comment";
  char input3[] = "KEY VALUE\t# comment";

  assert_normalize_result(input1, "KEY VALUE",
                          "Should remove trailing comment");
  assert_normalize_result(input2, "KEY VALUE",
                          "Should remove trailing comment with spaces");
  assert_normalize_result(input3, "KEY VALUE",
                          "Should remove trailing comment with tab");
}

TEST(normalize_leading_whitespace) {
  char input1[] = "  KEY VALUE";
  char input2[] = "\tKEY VALUE";
  char input3[] = "  \t  KEY VALUE";

  assert_normalize_result(input1, "KEY VALUE", "Should remove leading spaces");
  assert_normalize_result(input2, "KEY VALUE", "Should remove leading tab");
  assert_normalize_result(input3, "KEY VALUE",
                          "Should remove mixed leading whitespace");
}

TEST(normalize_trailing_whitespace) {
  char input1[] = "KEY VALUE  ";
  char input2[] = "KEY VALUE\t";
  char input3[] = "KEY VALUE  \t  ";

  assert_normalize_result(input1, "KEY VALUE", "Should remove trailing spaces");
  assert_normalize_result(input2, "KEY VALUE", "Should remove trailing tab");
  assert_normalize_result(input3, "KEY VALUE",
                          "Should remove mixed trailing whitespace");
}

TEST(normalize_both_whitespace) {
  char input1[] = "  KEY VALUE  ";
  char input2[] = "\tKEY VALUE\t";
  char input3[] = "  \t KEY VALUE \t  ";

  assert_normalize_result(input1, "KEY VALUE", "Should remove both spaces");
  assert_normalize_result(input2, "KEY VALUE", "Should remove both tabs");
  assert_normalize_result(input3, "KEY VALUE",
                          "Should remove mixed surrounding whitespace");
}

TEST(normalize_both_whitespace_and_center) {
  char input[] = "  KEY   VALUE  ";
  assert_normalize_result(input, "KEY   VALUE",
                          "Should preserve internal whitespace");
}

TEST(normalize_complex) {
  char input1[] = "  KEY VALUE # comment  ";
  char input2[] = "\tKEY VALUE\t# comment";
  char input3[] = "  \t KEY VALUE \t # comment \t ";

  assert_normalize_result(input1, "KEY VALUE", "Should handle spaces, comment");
  assert_normalize_result(input2, "KEY VALUE", "Should handle tabs, comment");
  assert_normalize_result(input3, "KEY VALUE",
                          "Should handle mixed whitespace, comment");
}

TEST(normalize_preserves_internal_whitespace) {
  char input[] = "KEY  MULTIPLE   SPACES    VALUE";
  assert_normalize_result(input, "KEY  MULTIPLE   SPACES    VALUE",
                          "Should preserve internal whitespace");
}

/* ============================================================================
 * Tests - Directory Entry Filtering
 * ============================================================================
 */

TEST(filter_null_entry) {
  assert_filter_result(NULL, FILTER_REJECT, "Should reject NULL entry");
}

TEST(filter_dot) {
  assert_filter_result(".", FILTER_REJECT, "Should reject '.'");
}

TEST(filter_dotdot) {
  assert_filter_result("..", FILTER_REJECT, "Should reject '..'");
}

TEST(filter_slash) {
  assert_filter_result("file/path", FILTER_REJECT,
                       "Should reject path with slash");
}

TEST(filter_not_conf_extension) {
  assert_filter_result("file.txt", FILTER_REJECT, "Should reject .txt file");
  assert_filter_result("file.cfg", FILTER_REJECT, "Should reject .cfg file");
  assert_filter_result("noextension", FILTER_REJECT, "Should reject no ext");
}

TEST(filter_conf_extension_partial) {
  assert_filter_result("file.con", FILTER_REJECT,
                       "Should reject partial .conf");
  assert_filter_result("file.config", FILTER_REJECT,
                       "Should reject .config extension");
}

TEST(filter_valid_conf_files) {
  assert_filter_result("settings.conf", FILTER_ACCEPT,
                       "Should accept .conf file");
  assert_filter_result("01-settings.conf", FILTER_ACCEPT,
                       "Should accept numbered .conf");
  assert_filter_result("my_config.conf", FILTER_ACCEPT,
                       "Should accept underscored .conf");
}

TEST(filter_hidden_conf_file) {
  assert_filter_result(".hidden.conf", FILTER_REJECT,
                       "Should reject hidden .conf file");
}

TEST(filter_short_name) {
  assert_filter_result("abc", FILTER_REJECT,
                       "Should reject 3-char name (len <= 5)");
  assert_filter_result("a", FILTER_REJECT,
                       "Should reject 1-char name (len <= 5)");
  assert_filter_result("x.con", FILTER_REJECT,
                       "Should reject 5-char name (len == 5, not > 5)");
}

/* ============================================================================
 * Tests - User Resolution: Input Validation
 * ============================================================================
 */

TEST(resolve_user_null_arguments) {
  struct syscall_ops test_ops = syscall_ops_default;
  uint32_t uid = 0;
  char username[STANDARD_USERNAME_BUFFER];

  errno = 0;
  TEST_ASSERT_EQ(
      resolve_user(NULL, "testuser", &uid, username, sizeof(username), true),
      -1, "Should reject NULL ops");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  errno = 0;
  TEST_ASSERT_EQ(
      resolve_user(&test_ops, NULL, &uid, username, sizeof(username), true), -1,
      "Should reject NULL user_arg");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  errno = 0;
  TEST_ASSERT_EQ(resolve_user(&test_ops, "testuser", NULL, username,
                              sizeof(username), true),
                 -1, "Should reject NULL uid pointer");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  errno = 0;
  TEST_ASSERT_EQ(
      resolve_user(&test_ops, "testuser", &uid, NULL, sizeof(username), true),
      -1, "Should reject NULL username pointer");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");

  errno = 0;
  TEST_ASSERT_EQ(resolve_user(&test_ops, "testuser", NULL, username, 0, true),
                 -1, "Should reject size 0");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(resolve_user_by_name_buffer_too_small) {
  struct syscall_ops test_ops = syscall_ops_default;

  test_ops.getpwnam_r = mock_getpwnam_r_success;

  test_resolve_user(&test_ops, "testuser", -1, 0, NULL,
                    TOO_SMALL_TESTUSER_BUFFER, true,
                    "Should fail when buffer too small");
  TEST_ASSERT_EQ(errno, ENAMETOOLONG, "Should set the correct error code");
}

TEST(resolve_user_arg_too_long) {
  struct syscall_ops test_ops = syscall_ops_default;
  char long_arg[LONG_USERNAME_TEST_SIZE];
  uint32_t uid = 0;
  char username[STANDARD_USERNAME_BUFFER];
  int result;

  memset(long_arg, 'a', sizeof(long_arg) - 1);
  long_arg[sizeof(long_arg) - 1] = '\0';

  result =
      resolve_user(&test_ops, long_arg, &uid, username, sizeof(username), true);
  TEST_ASSERT_EQ(result, -1, "Should reject very long user argument");
  TEST_ASSERT_EQ(errno, ENAMETOOLONG, "Should set the correct error code");
}

TEST(resolve_user_uid_overflow) {
  struct syscall_ops test_ops = syscall_ops_default;
  uint32_t uid = 0;
  char username[STANDARD_USERNAME_BUFFER];
  int result;

  result = resolve_user(&test_ops, "4294967296", &uid, username,
                        sizeof(username), true);
  TEST_ASSERT_EQ(result, -1, "Should reject UID overflow");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(resolve_user_by_name_null_pwname) {
  struct syscall_ops test_ops = syscall_ops_default;

  test_ops.getpwnam_r = mock_getpwnam_r_null_pwname;

  test_resolve_user(&test_ops, "testuser", -1, 0, NULL,
                    STANDARD_USERNAME_BUFFER, true,
                    "Should reject NULL pw_name in passwd struct");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(resolve_user_username_invalid) {
  struct syscall_ops test_ops = syscall_ops_default;
  uint32_t uid = 0;
  char username[STANDARD_USERNAME_BUFFER];

  FOR_EACH_INVALID_USERNAME(
      TEST_ASSERT_EQ(resolve_user(&test_ops, case_ptr->input, &uid, username,
                                  sizeof(username), true),
                     -1, case_ptr->reason););
}

TEST(resolve_user_username_valid) {
  struct syscall_ops test_ops = syscall_ops_default;
  uint32_t uid = 0;
  char username[STANDARD_USERNAME_BUFFER];

  test_ops.getpwnam_r = mock_getpwnam_r_success;

  FOR_EACH_VALID_USERNAME(
      TEST_ASSERT_EQ(resolve_user(&test_ops, case_ptr->input, &uid, username,
                                  sizeof(username), true),
                     0, case_ptr->reason););
}

/* ============================================================================
 * Tests - User Resolution: UID to Username
 * ============================================================================
 */

TEST(resolve_user_by_uid_non_debug) {
  struct syscall_ops test_ops = syscall_ops_default;

  test_ops.getpwuid = mock_getpwuid_testuser;

  test_resolve_user(&test_ops, "1000", 0, TEST_UID_STANDARD, "testuser",
                    STANDARD_USERNAME_BUFFER, false,
                    "Should succeed in non-debug mode");
}

TEST(resolve_user_by_uid_success) {
  struct syscall_ops test_ops = syscall_ops_default;

  test_ops.getpwuid = mock_getpwuid_testuser;

  test_resolve_user(&test_ops, "1000", 0, TEST_UID_STANDARD, "testuser",
                    STANDARD_USERNAME_BUFFER, true, "Should succeed");
}

TEST(resolve_user_by_uid_not_found) {
  struct syscall_ops test_ops = syscall_ops_default;

  test_ops.getpwuid = mock_getpwuid_null;

  test_resolve_user(&test_ops, "9999", -1, 0, NULL, STANDARD_USERNAME_BUFFER,
                    true, "Should fail when user not found");
  TEST_ASSERT_EQ(errno, ENOENT, "Should set the correct error code");
}

TEST(resolve_user_by_uid_null_pwname) {
  struct syscall_ops test_ops = syscall_ops_default;

  test_ops.getpwuid = mock_getpwuid_null_pwname;

  test_resolve_user(&test_ops, "1000", -1, 0, NULL, STANDARD_USERNAME_BUFFER,
                    true, "Should reject NULL pw_name in passwd struct");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(resolve_user_by_uid_root) {
  struct syscall_ops test_ops = syscall_ops_default;

  test_ops.getpwuid = mock_getpwuid_root;

  test_resolve_user(&test_ops, "0", 0, TEST_UID_ROOT, "root",
                    STANDARD_USERNAME_BUFFER, true,
                    "Should resolve root user correctly");
}

TEST(resolve_user_uid_leading_zeros) {
  struct syscall_ops test_ops = syscall_ops_default;

  test_ops.getpwuid = mock_getpwuid_testuser;

  test_resolve_user(&test_ops, "0001000", 0, TEST_UID_STANDARD, "testuser",
                    STANDARD_USERNAME_BUFFER, true,
                    "Should parse UID with leading zeros correctly");
}

TEST(resolve_user_by_uid_username_too_long) {
  struct syscall_ops test_ops = syscall_ops_default;

  test_ops.getpwuid = mock_getpwuid_longname;

  test_resolve_user(&test_ops, "1000", -1, 0, NULL, TINY_USERNAME_BUFFER, true,
                    "Should fail when username too long");
  TEST_ASSERT_EQ(errno, ENAMETOOLONG, "Should set the correct error code");
}

/* ============================================================================
 * Tests - User Resolution: Username to UID
 * ============================================================================
 */

TEST(resolve_user_by_name_non_debug) {
  struct syscall_ops test_ops = syscall_ops_default;

  test_ops.getpwnam_r = mock_getpwnam_r_success;

  test_resolve_user(&test_ops, "testuser", 0, TEST_UID_STANDARD, "testuser",
                    STANDARD_USERNAME_BUFFER, false,
                    "Should succeed in non-debug mode");
}

TEST(resolve_user_by_name_success) {
  struct syscall_ops test_ops = syscall_ops_default;

  test_ops.getpwnam_r = mock_getpwnam_r_success;

  test_resolve_user(&test_ops, "testuser", 0, TEST_UID_STANDARD, "testuser",
                    STANDARD_USERNAME_BUFFER, true, "Should succeed");
}

TEST(resolve_user_by_name_not_found) {
  struct syscall_ops test_ops = syscall_ops_default;

  test_ops.getpwnam_r = mock_getpwnam_r_not_found;

  test_resolve_user(&test_ops, "nosuchuser", -1, 0, NULL,
                    STANDARD_USERNAME_BUFFER, true,
                    "Should fail when user not found");
  TEST_ASSERT_EQ(errno, ENOENT, "Should set the correct error code");
}

TEST(resolve_user_by_name_getpwnam_r_error) {
  struct syscall_ops test_ops = syscall_ops_default;

  test_ops.getpwnam_r = mock_getpwnam_r_error;

  test_resolve_user(&test_ops, "testuser", -1, 0, NULL,
                    STANDARD_USERNAME_BUFFER, true,
                    "Should fail on system error");
  TEST_ASSERT_EQ(errno, EIO, "Should set the correct error code");
}

TEST(resolve_user_calloc_fails) {
  struct syscall_ops test_ops = syscall_ops_default;
  uint32_t uid = 0;
  char username[STANDARD_USERNAME_BUFFER];
  int result;

  test_ops.getpwnam_r = mock_getpwnam_r_success;
  test_ops.calloc = mock_calloc_null;

  result = resolve_user(&test_ops, "testuser", &uid, username, sizeof(username),
                        true);

  TEST_ASSERT_EQ(result, -1, "Should fail on allocation failure");
  TEST_ASSERT_EQ(errno, ENOMEM, "Should set the correct error code");
}

TEST(resolve_user_max_uid) {
  struct syscall_ops test_ops = syscall_ops_default;

  test_ops.getpwuid = mock_getpwuid_testuser;

  test_resolve_user(&test_ops, "4294967295", 0, UINT32_MAX_VAL, NULL,
                    STANDARD_USERNAME_BUFFER, true,
                    "Should handle maximum UID value");
}

TEST(resolve_user_username_copy_exact_size) {
  struct syscall_ops test_ops = syscall_ops_default;

  test_ops.getpwnam_r = mock_getpwnam_r_success;

  test_resolve_user(&test_ops, "testuser", 0, TEST_UID_STANDARD, "testuser",
                    EXACT_FIT_TESTUSER_BUFFER, true,
                    "Should succeed with exact-fit buffer");
}

/* ============================================================================
 * Test Runner
 * ============================================================================
 */

int main(int argc, char **argv) {
  int result;

  TEST_INIT(10, false, false); /* timeout, verbose, duration */

  /* Configuration line normalization */
  RUN_TEST(normalize_null);
  RUN_TEST(normalize_empty_line);
  RUN_TEST(normalize_only_whitespace);
  RUN_TEST(normalize_comment_only);
  RUN_TEST(normalize_with_trailing_comment);
  RUN_TEST(normalize_leading_whitespace);
  RUN_TEST(normalize_trailing_whitespace);
  RUN_TEST(normalize_both_whitespace);
  RUN_TEST(normalize_both_whitespace_and_center);
  RUN_TEST(normalize_complex);
  RUN_TEST(normalize_preserves_internal_whitespace);

  /* Directory entry filtering */
  RUN_TEST(filter_null_entry);
  RUN_TEST(filter_dot);
  RUN_TEST(filter_dotdot);
  RUN_TEST(filter_slash);
  RUN_TEST(filter_not_conf_extension);
  RUN_TEST(filter_conf_extension_partial);
  RUN_TEST(filter_valid_conf_files);
  RUN_TEST(filter_hidden_conf_file);
  RUN_TEST(filter_short_name);

  /* User resolution: Input validation */
  RUN_TEST(resolve_user_null_arguments);
  RUN_TEST(resolve_user_by_name_buffer_too_small);
  RUN_TEST(resolve_user_arg_too_long);
  RUN_TEST(resolve_user_uid_overflow);
  RUN_TEST(resolve_user_by_name_null_pwname);
  RUN_TEST(resolve_user_username_invalid);
  RUN_TEST(resolve_user_username_valid);

  /* User resolution: UID to username */
  RUN_TEST(resolve_user_by_uid_non_debug);
  RUN_TEST(resolve_user_by_uid_success);
  RUN_TEST(resolve_user_by_uid_not_found);
  RUN_TEST(resolve_user_by_uid_null_pwname);
  RUN_TEST(resolve_user_by_uid_root);
  RUN_TEST(resolve_user_uid_leading_zeros);
  RUN_TEST(resolve_user_by_uid_username_too_long);

  /* User resolution: Username to UID */
  RUN_TEST(resolve_user_by_name_non_debug);
  RUN_TEST(resolve_user_by_name_success);
  RUN_TEST(resolve_user_by_name_not_found);
  RUN_TEST(resolve_user_by_name_getpwnam_r_error);
  RUN_TEST(resolve_user_calloc_fails);
  RUN_TEST(resolve_user_max_uid);
  RUN_TEST(resolve_user_username_copy_exact_size);

  result = TEST_EXECUTE();
  return result;
}
