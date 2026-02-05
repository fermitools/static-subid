/**
 * test_helper_all.h - Umbrella header for all test helpers
 *
 * This is the recommended single include for test files. It handles critical
 * initialization ordering (autoconf.h and static-subid.h must precede system
 * headers) and provides access to all test helper facilities:
 *
 * - Username validation test data (test_helper_username.h)
 * - File stat mocks for path validation (test_helper_mock_stat.h)
 * - Memory allocation mocks for OOM testing (test_helper_mock_alloc.h)
 * - File operation mocks for error handling (test_helper_mock_file.h)
 * - Password database mocks for user resolution (test_helper_passwd.h)
 *
 * Individual helper headers CAN be included directly if needed, but this
 * umbrella header is preferred for correct initialization.
 *
 * Design rationale:
 * - autoconf.h defines feature macros that affect system header behavior
 * - static-subid.h may set constants used by libc headers
 * - Umbrella pattern provides sensible defaults with drop-in override semantics
 */

#ifndef TEST_HELPER_ALL_H
#define TEST_HELPER_ALL_H

/* ============================================================================
 * CRITICAL: Include order matters
 * 1. autoconf.h - Feature test macros
 * 2. static-subid.h - Project constants
 * 3. System headers - Now see correct feature flags
 * 4. Helper headers - Build on initialized system state
 * ============================================================================
 */

/* clang-format off */
#include "autoconf.h"
#include "static-subid.h"
/* clang-format on */

/* Include all helper modules */
#include "test_helper_mock_alloc.h"
#include "test_helper_mock_file.h"
#include "test_helper_mock_stat.h"
#include "test_helper_passwd.h"
#include "test_helper_username.h"

#endif /* TEST_HELPER_ALL_H */
