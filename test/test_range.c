/**
 * test_range.c - Tests for subordinate ID range calculation
 */

/* clang-format off */
#include "autoconf.h"
#include "static-subid.h"
/* clang-format on */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "test_framework.h"

/* ============================================================================
 * Constants - Test Values and Expected Results
 * ============================================================================
 */

/* Standard test user UIDs */
enum {
  TEST_UID_MIN = 1000,      /* Standard minimum UID for regular users */
  TEST_UID_FIRST = 1000,    /* First regular user */
  TEST_UID_SECOND = 1001,   /* Second regular user */
  TEST_UID_THIRD = 1002,    /* Third regular user */
  TEST_UID_TENTH = 1009,    /* Tenth regular user (boundary test) */
  TEST_UID_ELEVENTH = 1010, /* Eleventh regular user (overflow test) */
  TEST_UID_TWELFTH = 1011,  /* Twelfth user (for max_val overflow test) */
  TEST_UID_BELOW_MIN = 999  /* UID below minimum (invalid) */
};

/* Standard test configuration values */
enum {
  DEFAULT_MIN_VAL = 100000, /* Default subordinate ID range start */
  DEFAULT_COUNT_VAL = 65536 /* Default IDs per user (2^16) */
};

/* Computed expected values for standard configuration */
enum {
  FIRST_USER_START = 100000,  /* min_val + (0 * count) */
  SECOND_USER_START = 165536, /* min_val + (1 * count) = 100000 + 65536 */
  THIRD_USER_START = 231072   /* min_val + (2 * count) = 100000 + 131072 */
};

/* Small test range values for wrap testing */
enum {
  SMALL_RANGE_MIN = 100000,
  SMALL_RANGE_MAX = 109999,   /* Space = 10000 IDs */
  SMALL_RANGE_COUNT = 3000,   /* Each user gets 3000 IDs */
  WRAP_USER_0_START = 100000, /* Offset 0: min_val + (0 * 3000) */
  WRAP_USER_1_START = 103000, /* Offset 3000: min_val + (1 * 3000) */
  WRAP_USER_2_START = 106000, /* Offset 6000: min_val + (2 * 3000) */
  WRAP_USER_3_START = 109000, /* Offset 9000: min_val + (3 * 3000) */
  WRAP_USER_4_START = 102000  /* Wraps to offset 2000: (4*3000) % 10000 */
};

/* Overflow test boundaries */
enum {
  OVERFLOW_TEST_UID_1 = 66000,        /* Just below overflow threshold */
  OVERFLOW_TEST_UID_2 = 66001,        /* Still below overflow threshold */
  OVERFLOW_TEST_UID_OVERFLOW = 66536, /* Causes multiplication overflow */
  LARGE_COUNT_VAL = 900000,           /* Large allocation size */
  HIGH_RANGE_COUNT = 90000000         /* Large count for end_id overflow */
};

/* Boundary test values */
enum {
  BOUNDARY_TEST_MAX_VAL = 199999,         /* DEFAULT_MIN_VAL + 99999 */
  BOUNDARY_TEST_MAX_VAL_PLUS_ONE = 200000 /* For overflow past boundary */
};

/* Test range size constants */
enum {
  SMALL_COUNT = 1000,      /* Small allocation per user */
  MEDIUM_COUNT = 10000,    /* Medium allocation per user */
  LARGE_UID = 60000,       /* Large UID for wrap testing */
  DETERMINISTIC_UID = 1234 /* Arbitrary UID for determinism tests */
};

/* Computed expected results for wrap and boundary tests */
enum {
  TENTH_USER_BOUNDARY_START = 190000,   /* 100000 + (9 * 10000) */
  LARGE_UID_WRAP_START = 124000,        /* Result of (59000*65536) % 100000 */
  DETERMINISTIC_UID_WRAP_START = 104000 /* Result of (234*1000) % 10000 */
};

/* Edge case test values */
enum {
  EDGE_CASE_MIN_VALUES_MAX = 65535 /* UINT16_MAX for min edge test */
};

/* Large constants requiring #define (exceed INT_MAX) */
#define DEFAULT_MAX_VAL 600100000U    /* Default subordinate ID range end */
#define ERROR_SENTINEL UINT32_MAX_VAL /* Indicates calculation error */
#define NEAR_MAX_MIN_VAL                                                       \
  4294000000U                      /* Near UINT32_MAX with room for count      \
                                    */
#define HIGH_RANGE_MIN 4200000000U /* High subordinate ID start */
#define EDGE_CASE_NEAR_MAX_START                                               \
  4000000000U /* Start value near UINT32_MAX                                   \
               */

/* ============================================================================
 * Helper Functions - Configuration Setup and Test Execution
 * ============================================================================
 */

/**
 * setup_custom_config - Initialize config with custom subordinate ID settings
 * @config: Configuration structure to initialize
 * @min_val: Minimum subordinate ID value
 * @max_val: Maximum subordinate ID value (inclusive)
 * @count_val: Number of subordinate IDs per user
 *
 * Initializes configuration with specified subordinate ID range parameters.
 * Used by tests that need non-standard allocation spaces, such as overflow
 * testing or wrap-around validation.
 */
static void setup_custom_config(config_t *config, uint32_t min_val,
                                uint32_t max_val, uint32_t count_val) {
  config_factory(config);
  config->subuid.min_val = min_val;
  config->subuid.max_val = max_val;
  config->subuid.count_val = count_val;
}

/**
 * calc_and_assert - Execute calc_subid_range and validate results
 * @uid: User ID to allocate range for
 * @uid_min: Minimum valid UID for regular users
 * @range: Subordinate ID range configuration
 * @allow_wrap: Whether to allow wrap-around allocation
 * @expected_ret: Expected return value (0 for success, -1 for error)
 * @expected_start: Expected starting subordinate ID
 * @desc: Test description for assertion messages
 *
 * Helper function that executes calc_subid_range and validates both
 * return code and output value. Reduces boilerplate in individual tests.
 *
 * Returns: Actual calculated start value (for additional checks if needed)
 */
static uint32_t calc_and_assert(uint32_t uid, uint32_t uid_min,
                                const subid_config_t *range, bool allow_wrap,
                                int expected_ret, uint32_t expected_start,
                                const char *desc) {
  uint32_t start = 0;
  int ret;

  ret = calc_subid_range(uid, uid_min, range, allow_wrap, &start);

  TEST_ASSERT_EQ(ret, expected_ret, desc);
  TEST_ASSERT_EQ(start, expected_start, "Start value should match expected");

  return start;
}

/* ============================================================================
 * Tests - Input Validation
 * ============================================================================
 */

TEST(calc_subid_range_null_config) {
  uint32_t start = 0;
  int ret;

  ret = calc_subid_range(TEST_UID_FIRST, TEST_UID_MIN, NULL, false, &start);
  TEST_ASSERT_EQ(ret, -1, "Should reject NULL config");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(calc_subid_range_null_output) {
  config_t config = {0};
  int ret;

  config_factory(&config);
  ret = calc_subid_range(TEST_UID_FIRST, TEST_UID_MIN, &config.subuid, false,
                         NULL);
  TEST_ASSERT_EQ(ret, -1, "Should reject NULL output");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(calc_subid_range_uid_below_min) {
  uint32_t start = 0;
  config_t config = {0};
  int ret;

  config_factory(&config);
  ret = calc_subid_range(TEST_UID_BELOW_MIN, TEST_UID_MIN, &config.subuid,
                         false, &start);
  TEST_ASSERT_EQ(ret, -1, "Should reject UID below minimum");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(calc_subid_range_zero_count) {
  uint32_t start = 0;
  config_t config = {0};
  int ret;

  config_factory(&config);
  config.subuid.count_val = 0;
  ret = calc_subid_range(TEST_UID_FIRST, TEST_UID_MIN, &config.subuid, false,
                         &start);
  TEST_ASSERT_EQ(ret, -1, "Should reject zero count");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(calc_subid_range_count_exceeds_space) {
  uint32_t start = 0;
  config_t config = {0};
  int ret;

  /* Space = 100 IDs (min_val to min_val+99), but request 101 IDs per user */
  setup_custom_config(&config, DEFAULT_MIN_VAL, DEFAULT_MIN_VAL + 99, 101);

  ret = calc_subid_range(TEST_UID_FIRST, TEST_UID_MIN, &config.subuid, false,
                         &start);
  TEST_ASSERT_EQ(ret, -1, "Should reject count exceeding space");
  TEST_ASSERT_EQ(errno, ERANGE, "Should set the correct error code");
}

/* ============================================================================
 * Tests - Strict Mode Calculation
 * ============================================================================
 */

TEST(calc_subid_range_strict_first_user) {
  config_t config = {0};

  config_factory(&config);
  calc_and_assert(TEST_UID_FIRST, TEST_UID_MIN, &config.subuid, false, 0,
                  FIRST_USER_START, "First user should start at min_val");
}

TEST(calc_subid_range_strict_second_user) {
  config_t config = {0};

  config_factory(&config);
  calc_and_assert(TEST_UID_SECOND, TEST_UID_MIN, &config.subuid, false, 0,
                  SECOND_USER_START, "Second user should be offset by count");
}

TEST(calc_subid_range_strict_third_user) {
  config_t config = {0};

  config_factory(&config);
  calc_and_assert(TEST_UID_THIRD, TEST_UID_MIN, &config.subuid, false, 0,
                  THIRD_USER_START, "Third user should be offset by 2*count");
}

TEST(calc_subid_range_strict_overflow_multiplication) {
  config_t config = {0};

  /* Test multiplication overflow detection */
  config_factory(&config);
  config.subuid.max_val = UINT32_MAX_VAL;

  /* (66000 - 1000) * 65536 = 4259940000 < UINT32_MAX (fits) */
  calc_and_assert(OVERFLOW_TEST_UID_1, TEST_UID_MIN, &config.subuid, false, 0,
                  4259940000U, "Should succeed before overflow");

  /* (66001 - 1000) * 65536 = 4260005536 < UINT32_MAX (fits) */
  calc_and_assert(OVERFLOW_TEST_UID_2, TEST_UID_MIN, &config.subuid, false, 0,
                  4260005536U, "Should succeed before overflow");

  /* (66536 - 1000) * 65536 = 4,294,967,296 > UINT32_MAX (overflows!) */
  calc_and_assert(OVERFLOW_TEST_UID_OVERFLOW, TEST_UID_MIN, &config.subuid,
                  false, -1, ERROR_SENTINEL,
                  "Should detect multiplication overflow");
  TEST_ASSERT_EQ(errno, ERANGE, "Should set the correct error code");
}

TEST(calc_subid_range_strict_overflow_addition) {
  config_t config = {0};

  /* Test addition overflow detection */
  setup_custom_config(&config, NEAR_MAX_MIN_VAL, UINT32_MAX_VAL,
                      LARGE_COUNT_VAL);

  /* User offset=2: product = 2 * 900000 = 1800000
   * Addition: 4294000000 + 1800000 = 4295800000 which overflows uint32_t
   */
  calc_and_assert(TEST_UID_THIRD, TEST_UID_MIN, &config.subuid, false, -1,
                  ERROR_SENTINEL, "Should detect addition overflow");
  TEST_ASSERT_EQ(errno, ERANGE, "Should set the correct error code");
}

TEST(calc_subid_range_strict_overflow_end_id) {
  config_t config = {0};

  /* Test end_id overflow detection */
  setup_custom_config(&config, HIGH_RANGE_MIN, UINT32_MAX_VAL,
                      HIGH_RANGE_COUNT);

  /* First user: start_id = 4200000000, end_id = 4289999999 (fits) */
  calc_and_assert(TEST_UID_FIRST, TEST_UID_MIN, &config.subuid, false, 0,
                  HIGH_RANGE_MIN, "First user should succeed");

  /* Second user: start_id = 4290000000, end_id overflows uint32_t */
  calc_and_assert(TEST_UID_SECOND, TEST_UID_MIN, &config.subuid, false, -1,
                  ERROR_SENTINEL, "Should detect end_id overflow");
  TEST_ASSERT_EQ(errno, ERANGE, "Should set the correct error code");
}

TEST(calc_subid_range_strict_exceeds_max) {
  config_t config = {0};

  /* Test detection when range exceeds max_val */
  setup_custom_config(&config, DEFAULT_MIN_VAL, BOUNDARY_TEST_MAX_VAL_PLUS_ONE,
                      MEDIUM_COUNT);

  /* UID 1011 (12th user) needs start = 210000, exceeds max_val */
  calc_and_assert(TEST_UID_TWELFTH, TEST_UID_MIN, &config.subuid, false, -1,
                  ERROR_SENTINEL, "Should detect range exceeding max_val");
  TEST_ASSERT_EQ(errno, ERANGE, "Should set the correct error code");
}

TEST(calc_subid_range_strict_boundary_exact_fit) {
  config_t config = {0};

  /* Test exact boundary fit scenario
   * Space = 100000 IDs (100000-199999), count = 10000
   * Exactly 10 users fit: 10 * 10000 = 100000
   */
  setup_custom_config(&config, DEFAULT_MIN_VAL, BOUNDARY_TEST_MAX_VAL,
                      MEDIUM_COUNT);

  /* Tenth user: offset = 9, start = 190000, end = 199999 (fits exactly) */
  calc_and_assert(TEST_UID_TENTH, TEST_UID_MIN, &config.subuid, false, 0,
                  TENTH_USER_BOUNDARY_START, "Tenth user should fit exactly");

  /* Eleventh user: start = 200000, exceeds max_val of 199999 */
  calc_and_assert(TEST_UID_ELEVENTH, TEST_UID_MIN, &config.subuid, false, -1,
                  ERROR_SENTINEL, "Eleventh user should fail");
  TEST_ASSERT_EQ(errno, ERANGE, "Should set the correct error code");
}

/* ============================================================================
 * Tests - Wrap Mode Calculation
 * ============================================================================
 */

TEST(calc_subid_range_wrap_basic) {
  config_t config = {0};

  config_factory(&config);
  calc_and_assert(TEST_UID_FIRST, TEST_UID_MIN, &config.subuid, true, 0,
                  FIRST_USER_START, "First user should start at min_val");
}

TEST(calc_subid_range_wrap_wraps_around) {
  config_t config = {0};

  /* Test wrap-around behavior with small range
   * Space = 10000 IDs, count = 3000 IDs per user
   */
  setup_custom_config(&config, SMALL_RANGE_MIN, SMALL_RANGE_MAX,
                      SMALL_RANGE_COUNT);

  /* Users 0-3: sequential allocation */
  calc_and_assert(TEST_UID_FIRST + 0, TEST_UID_MIN, &config.subuid, true, 0,
                  WRAP_USER_0_START, "User 0 at offset 0");

  calc_and_assert(TEST_UID_FIRST + 1, TEST_UID_MIN, &config.subuid, true, 0,
                  WRAP_USER_1_START, "User 1 at offset 3000");

  calc_and_assert(TEST_UID_FIRST + 2, TEST_UID_MIN, &config.subuid, true, 0,
                  WRAP_USER_2_START, "User 2 at offset 6000");

  calc_and_assert(TEST_UID_FIRST + 3, TEST_UID_MIN, &config.subuid, true, 0,
                  WRAP_USER_3_START, "User 3 at offset 9000");

  /* User 4: wraps around to offset 2000 */
  calc_and_assert(TEST_UID_FIRST + 4, TEST_UID_MIN, &config.subuid, true, 0,
                  WRAP_USER_4_START, "User 4 wraps to offset 2000");
}

TEST(calc_subid_range_wrap_large_uid) {
  config_t config = {0};

  /* Test wrap behavior with large UID causing overflow in multiplication */
  setup_custom_config(&config, DEFAULT_MIN_VAL, BOUNDARY_TEST_MAX_VAL,
                      DEFAULT_COUNT_VAL);

  /* UID 60000: offset = 59000, modulo arithmetic produces start = 124000 */
  calc_and_assert(LARGE_UID, TEST_UID_MIN, &config.subuid, true, 0,
                  LARGE_UID_WRAP_START,
                  "Wrapped calculation should use modulo arithmetic");
}

TEST(calc_subid_range_wrap_deterministic) {
  config_t config = {0};
  uint32_t start1;
  uint32_t start2;

  /* Test that wrap mode produces deterministic results */
  setup_custom_config(&config, DEFAULT_MIN_VAL, SMALL_RANGE_MAX, SMALL_COUNT);

  /* UID 1234: should always produce same result */
  start1 = calc_and_assert(DETERMINISTIC_UID, TEST_UID_MIN, &config.subuid,
                           true, 0, DETERMINISTIC_UID_WRAP_START,
                           "First call should succeed");

  start2 = calc_and_assert(DETERMINISTIC_UID, TEST_UID_MIN, &config.subuid,
                           true, 0, DETERMINISTIC_UID_WRAP_START,
                           "Second call should succeed");

  TEST_ASSERT_EQ(start1, start2, "Results should be deterministic");
}

TEST(calc_subid_range_wrap_count_exceeds_space) {
  config_t config = {0};

  /* Even in wrap mode, count cannot exceed space */
  setup_custom_config(&config, DEFAULT_MIN_VAL, DEFAULT_MIN_VAL + 99, 101);

  calc_and_assert(TEST_UID_FIRST, TEST_UID_MIN, &config.subuid, true, -1,
                  ERROR_SENTINEL,
                  "Should reject count exceeding space even in wrap mode");
  TEST_ASSERT_EQ(errno, ERANGE, "Should set the correct error code");
}

/* ============================================================================
 * Tests - Edge Cases
 * ============================================================================
 */

TEST(calc_subid_range_min_values) {
  config_t config = {0};

  /* Test minimum possible values across the board */
  setup_custom_config(&config, 0, EDGE_CASE_MIN_VALUES_MAX, 1);

  calc_and_assert(0, 0, &config.subuid, false, 0, 0,
                  "Should handle minimum possible values");
}

TEST(calc_subid_range_max_values) {
  config_t config = {0};

  /* Test values near the upper limit of uint32_t */
  setup_custom_config(&config, EDGE_CASE_NEAR_MAX_START, UINT32_MAX_VAL, 1);

  calc_and_assert(TEST_UID_FIRST, TEST_UID_MIN, &config.subuid, false, 0,
                  EDGE_CASE_NEAR_MAX_START,
                  "Should handle values near UINT32_MAX");
}

TEST(calc_subid_range_single_id_range) {
  config_t config = {0};

  /* Test minimal allocation space (space = 1 ID) */
  setup_custom_config(&config, DEFAULT_MIN_VAL, DEFAULT_MIN_VAL, 1);

  /* First user takes the only available ID */
  calc_and_assert(TEST_UID_FIRST, TEST_UID_MIN, &config.subuid, false, 0,
                  DEFAULT_MIN_VAL, "First user should fit in single-ID range");

  /* Second user has nowhere to go */
  calc_and_assert(TEST_UID_SECOND, TEST_UID_MIN, &config.subuid, false, -1,
                  ERROR_SENTINEL, "Second user should fail in single-ID range");
  TEST_ASSERT_EQ(errno, ERANGE, "Should set the correct error code");
}

/* ============================================================================
 * Test Runner
 * ============================================================================
 */

int main(int argc, char **argv) {
  int result;

  TEST_INIT(10, false, false); /* timeout, verbose, duration */

  /* Input validation */
  RUN_TEST(calc_subid_range_null_config);
  RUN_TEST(calc_subid_range_null_output);
  RUN_TEST(calc_subid_range_uid_below_min);
  RUN_TEST(calc_subid_range_zero_count);
  RUN_TEST(calc_subid_range_count_exceeds_space);

  /* Strict mode calculation */
  RUN_TEST(calc_subid_range_strict_first_user);
  RUN_TEST(calc_subid_range_strict_second_user);
  RUN_TEST(calc_subid_range_strict_third_user);
  RUN_TEST(calc_subid_range_strict_overflow_multiplication);
  RUN_TEST(calc_subid_range_strict_overflow_addition);
  RUN_TEST(calc_subid_range_strict_overflow_end_id);
  RUN_TEST(calc_subid_range_strict_exceeds_max);
  RUN_TEST(calc_subid_range_strict_boundary_exact_fit);

  /* Wrap mode calculation */
  RUN_TEST(calc_subid_range_wrap_basic);
  RUN_TEST(calc_subid_range_wrap_wraps_around);
  RUN_TEST(calc_subid_range_wrap_large_uid);
  RUN_TEST(calc_subid_range_wrap_deterministic);
  RUN_TEST(calc_subid_range_wrap_count_exceeds_space);

  /* Edge cases */
  RUN_TEST(calc_subid_range_min_values);
  RUN_TEST(calc_subid_range_max_values);
  RUN_TEST(calc_subid_range_single_id_range);

  result = TEST_EXECUTE();
  return result;
}
