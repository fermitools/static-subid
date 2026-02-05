/**
 * test_helper_username.h - Username validation test data
 *
 * Provides test cases and iteration macros for username validation testing.
 * Shared across validate_username() and resolve_user() test suites to ensure
 * consistent validation behavior.
 *
 * This header is self-contained and can be included independently, but
 * including via test_helper_all.h is recommended for proper initialization.
 *
 * Usage:
 *   #include "test_helper_all.h"
 *
 *   TEST(validate_username_invalid) {
 *     FOR_EACH_INVALID_USERNAME(
 *       TEST_ASSERT_EQ(validate(case_ptr->input), -1, case_ptr->reason);
 *     );
 *   }
 */

#ifndef TEST_HELPER_USERNAME_H
#define TEST_HELPER_USERNAME_H

#include <errno.h>
#include <stddef.h>

/* ============================================================================
 * Data Structures
 * ============================================================================
 */

/**
 * struct username_test_case - Single username validation test case
 * @input: Username string to test
 * @reason: Human-readable explanation for expected result
 */
struct username_test_case {
  const char *input;
  const char *reason;
};

/* ============================================================================
 * Test Data - Invalid Usernames
 * ============================================================================
 */

/**
 * INVALID_USERNAMES - Test cases that should fail validation
 *
 * These violate POSIX username rules and should be rejected by both
 * validate_username() and resolve_user().
 */
static const struct username_test_case INVALID_USERNAMES[] = {
    {"user;name", "Should reject ; in username"},
    {"user/name", "Should reject slash in username"},
    {"user@host", "Should reject @ in username"},
    {"1user", "Should reject digit start"},
    {".hidden", "Should reject dot start"},
    {"user-", "Should reject hyphen end"},
    {"user name", "Should reject space in username"},
    {"user\tname", "Should reject tab in username"},
    {"user$var", "Should reject $ in username"},
    {"user#1", "Should reject # in username"},
    {"User", "Should reject uppercase start"},
    {"user!", "Should reject ! in username"},
    {"user~", "Should reject ~ in username"},
    {"", "Should reject empty string"},
};

#define INVALID_USERNAME_COUNT                                                 \
  (sizeof(INVALID_USERNAMES) / sizeof(INVALID_USERNAMES[0]))

/* ============================================================================
 * Test Data - Valid Usernames
 * ============================================================================
 */

/**
 * VALID_USERNAMES - Test cases that should pass validation
 *
 * These follow POSIX username rules and should be accepted by
 * validate_username(). Note that resolve_user() may still fail if the
 * user doesn't exist in the password database.
 */
static const struct username_test_case VALID_USERNAMES[] = {
    {"t", "Single character username"},
    {"testuser", "Simple lowercase username"},
    {"testuser$", "Username with $ (shadow-utils legacy)"},
    {"test-user", "Username with hyphen"},
    {"test.user", "Username with period"},
    {"test.user..", "Username with lots of periods"},
    {"test_user", "Username with underscore"},
    {"_testuser", "Username with leading underscore"},
    {"testuser123", "Username with digits (not at start)"},
    {"t.est-us.er_123$", "Mixed valid characters"},
};

#define VALID_USERNAME_COUNT                                                   \
  (sizeof(VALID_USERNAMES) / sizeof(VALID_USERNAMES[0]))

/* ============================================================================
 * Iteration Macros
 * ============================================================================
 */

/**
 * FOR_EACH_INVALID_USERNAME - Iterate over invalid username test cases
 * @test_expr: Expression to evaluate for each case (receives case_ptr)
 *
 * Loop macro that provides each invalid username case as 'case_ptr'.
 * Use within test functions to validate rejection behavior.
 */
#define FOR_EACH_INVALID_USERNAME(test_expr)                                   \
  do {                                                                         \
    for (size_t _i = 0; _i < INVALID_USERNAME_COUNT; _i++) {                   \
      const struct username_test_case *case_ptr = &INVALID_USERNAMES[_i];      \
      test_expr;                                                               \
      TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");      \
    }                                                                          \
  } while (0)

/**
 * FOR_EACH_VALID_USERNAME - Iterate over valid username test cases
 * @test_expr: Expression to evaluate for each case (receives case_ptr)
 *
 * Loop macro that provides each valid username case as 'case_ptr'.
 * Use within test functions to validate acceptance behavior.
 */
#define FOR_EACH_VALID_USERNAME(test_expr)                                     \
  do {                                                                         \
    for (size_t _i = 0; _i < VALID_USERNAME_COUNT; _i++) {                     \
      const struct username_test_case *case_ptr = &VALID_USERNAMES[_i];        \
      test_expr;                                                               \
    }                                                                          \
  } while (0)

#endif /* TEST_HELPER_USERNAME_H */
