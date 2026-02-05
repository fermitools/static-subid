/**
 * test_helper_passwd.h - Password database mock functions
 *
 * Provides mock implementations of getpwuid() and getpwnam_r() for testing
 * user resolution without requiring actual system users.
 *
 * Mock variants available:
 * - mock_getpwuid_null: User not found (returns NULL)
 * - mock_getpwuid_testuser: Standard test user (testuser, UID 1000, GID 1000)
 * - mock_getpwuid_root: Root user (root, UID 0, GID 0)
 * - mock_getpwuid_longname: Very long username (255 chars, for buffer overflow
 * testing)
 * - mock_getpwuid_null_pwname: Malformed entry with NULL pw_name
 * - mock_getpwnam_r_success: Successful lookup
 * - mock_getpwnam_r_not_found: User not found (sets *result = NULL)
 * - mock_getpwnam_r_error: System error (returns EIO)
 * - mock_getpwnam_r_null_pwname: Malformed entry with NULL pw_name
 *
 * This header is self-contained and can be included independently, but
 * including via test_helper_all.h is recommended for proper initialization.
 *
 * Usage:
 *   #include "test_helper_all.h"
 *
 *   struct syscall_ops ops = syscall_ops_default;
 *   ops.getpwuid = mock_getpwuid_testuser;
 *   ops.getpwnam_r = mock_getpwnam_r_not_found;
 *
 *   result = resolve_user(&ops, "testuser", &uid, username, bufsize, true);
 */

#ifndef TEST_HELPER_PASSWD_H
#define TEST_HELPER_PASSWD_H

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

/* ============================================================================
 * Constants
 * ============================================================================
 */

#define MOCK_USERNAME_BUFFER_SIZE 256 /* Storage for mock username strings */
#define TEST_UID_ROOT 0               /* Root user UID */
#define TEST_UID_STANDARD 1000        /* Standard test user UID */
#define TEST_GID_ROOT 0               /* Root user GID */
#define TEST_GID_STANDARD 1000        /* Standard test user GID */

/* ============================================================================
 * Global Mock Storage - Password Database Simulation
 * ============================================================================
 */

/*
 * Static storage for mock passwd structures.
 * These are reused across different mock functions to avoid repeated
 * allocations. They are safe because tests run sequentially.
 */
static struct passwd mock_pwd_storage = {0};
static char mock_pw_name_storage[MOCK_USERNAME_BUFFER_SIZE] = {0};

/* ============================================================================
 * Helper Functions
 * ============================================================================
 */

/**
 * setup_mock_user - Helper to configure mock passwd structure
 * @username: Username to set
 * @uid: User ID to set
 * @gid: Group ID to set
 *
 * Centralizes mock passwd setup to reduce code duplication across
 * different getpwuid mock variants.
 *
 * Return: Pointer to static passwd structure
 */
static struct passwd *setup_mock_user(const char *username, uid_t uid,
                                      gid_t gid) {
  snprintf(mock_pw_name_storage, sizeof(mock_pw_name_storage), "%s", username);
  mock_pwd_storage.pw_name = mock_pw_name_storage;
  mock_pwd_storage.pw_uid = uid;
  mock_pwd_storage.pw_gid = gid;

  return &mock_pwd_storage;
}

/* ============================================================================
 * getpwuid() Mock Implementations
 * ============================================================================
 */

/**
 * mock_getpwuid_null - Mock getpwuid that returns NULL (user not found)
 * @uid: User ID to look up (ignored)
 *
 * Simulates user not found in password database.
 *
 * Return: NULL
 */
static struct passwd *mock_getpwuid_null(uid_t uid) {
  (void)uid;
  return NULL;
}

/**
 * mock_getpwuid_testuser - Mock getpwuid that returns a standard test user
 * @uid: User ID to look up (ignored)
 *
 * Returns a test user with:
 * - Username: "testuser"
 * - UID: 1000
 * - GID: 1000
 *
 * Return: Pointer to static passwd structure
 */
static struct passwd *mock_getpwuid_testuser(uid_t uid) {
  (void)uid;
  return setup_mock_user("testuser", TEST_UID_STANDARD, TEST_GID_STANDARD);
}

/**
 * mock_getpwuid_root - Mock getpwuid that returns root user
 * @uid: User ID to look up (ignored)
 *
 * Returns root user information for testing privileged user handling.
 *
 * Return: Pointer to static passwd structure with root user
 */
static struct passwd *mock_getpwuid_root(uid_t uid) {
  (void)uid;
  return setup_mock_user("root", TEST_UID_ROOT, TEST_GID_ROOT);
}

/**
 * mock_getpwuid_longname - Mock getpwuid that returns a very long username
 * @uid: User ID to look up (ignored)
 *
 * Returns a user with username that fills the entire buffer (255 chars +
 * null). Used to test buffer overflow handling.
 *
 * Return: Pointer to static passwd structure with max-length username
 */
static struct passwd *mock_getpwuid_longname(uid_t uid) {
  (void)uid;

  /* Create a username that's too long to fit in most buffers */
  memset(mock_pw_name_storage, 'a', sizeof(mock_pw_name_storage) - 1);
  mock_pw_name_storage[sizeof(mock_pw_name_storage) - 1] = '\0';

  mock_pwd_storage.pw_name = mock_pw_name_storage;
  mock_pwd_storage.pw_uid = TEST_UID_STANDARD;
  mock_pwd_storage.pw_gid = TEST_GID_STANDARD;

  return &mock_pwd_storage;
}

/**
 * mock_getpwuid_null_pwname - Mock getpwuid with NULL pw_name (malformed)
 * @uid: User ID to look up (ignored)
 *
 * Simulates corrupted password database or NSS module bug that returns
 * a passwd struct but with NULL pw_name field. This tests defensive handling
 * of malformed system responses in the UID-to-username resolution path.
 *
 * Critical for long-lived systems where data corruption or NSS bugs may
 * occur. Code must handle gracefully rather than dereferencing NULL.
 *
 * Return: Pointer to passwd structure with NULL pw_name
 */
static struct passwd *mock_getpwuid_null_pwname(uid_t uid) {
  (void)uid;

  /* Set valid UID but NULL pw_name to simulate corruption */
  mock_pwd_storage.pw_name = NULL;
  mock_pwd_storage.pw_uid = TEST_UID_STANDARD;
  mock_pwd_storage.pw_gid = TEST_GID_STANDARD;

  return &mock_pwd_storage;
}

/* ============================================================================
 * getpwnam_r() Mock Implementations
 * ============================================================================
 */

/**
 * mock_getpwnam_r_success - Mock getpwnam_r that succeeds
 * @name: Username to look up
 * @pwd: Output passwd structure
 * @buf: Buffer for string storage
 * @buflen: Size of buffer
 * @result: Output pointer to passwd structure
 *
 * Simulates successful username lookup with standard test user.
 *
 * Return: 0 on success
 */
static int mock_getpwnam_r_success(const char *name, struct passwd *pwd,
                                   char *buf, size_t buflen,
                                   struct passwd **result) {
  /* Copy username into buffer */
  snprintf(buf, buflen, "%s", name);

  pwd->pw_name = buf;
  pwd->pw_uid = TEST_UID_STANDARD;
  pwd->pw_gid = TEST_GID_STANDARD;

  *result = pwd;
  return 0;
}

/**
 * mock_getpwnam_r_not_found - Mock getpwnam_r that doesn't find user
 * @name: Username to look up (ignored)
 * @pwd: Output passwd structure (ignored)
 * @buf: Buffer for string storage (ignored)
 * @buflen: Size of buffer (ignored)
 * @result: Output pointer to passwd structure
 *
 * Simulates user not found in password database.
 *
 * Return: 0 with *result set to NULL
 */
static int mock_getpwnam_r_not_found(const char *name, struct passwd *pwd,
                                     char *buf, size_t buflen,
                                     struct passwd **result) {
  (void)name;
  (void)pwd;
  (void)buf;
  (void)buflen;

  *result = NULL;
  return 0;
}

/**
 * mock_getpwnam_r_error - Mock getpwnam_r that returns system error
 * @name: Username to look up (ignored)
 * @pwd: Output passwd structure (ignored)
 * @buf: Buffer for string storage (ignored)
 * @buflen: Size of buffer (ignored)
 * @result: Output pointer to passwd structure
 *
 * Simulates system error during user lookup (e.g., I/O error).
 *
 * Return: EIO error code
 */
static int mock_getpwnam_r_error(const char *name, struct passwd *pwd,
                                 char *buf, size_t buflen,
                                 struct passwd **result) {
  (void)name;
  (void)pwd;
  (void)buf;
  (void)buflen;

  *result = NULL;
  return EIO; /* I/O error */
}

/**
 * mock_getpwnam_r_null_pwname - Mock getpwnam_r with NULL pw_name (malformed)
 * @name: Username to look up (ignored)
 * @pwd: Output passwd structure
 * @buf: Buffer for string storage (ignored)
 * @buflen: Size of buffer (ignored)
 * @result: Output pointer to passwd structure
 *
 * Simulates corrupted password database or NSS module bug that returns
 * success but with NULL pw_name field. This tests defensive handling of
 * malformed system responses.
 *
 * Critical for long-lived systems where data corruption or NSS bugs may
 * occur. Code must handle gracefully rather than dereferencing NULL.
 *
 * Return: 0 (success) with pwd->pw_name = NULL
 */
static int mock_getpwnam_r_null_pwname(const char *name, struct passwd *pwd,
                                       char *buf, size_t buflen,
                                       struct passwd **result) {
  (void)name;
  (void)buf;
  (void)buflen;

  /* Set valid UID but NULL pw_name to simulate corruption */
  pwd->pw_name = NULL;
  pwd->pw_uid = TEST_UID_STANDARD;
  pwd->pw_gid = TEST_GID_STANDARD;

  *result = pwd;
  return 0;
}

#pragma GCC diagnostic pop
#endif /* TEST_HELPER_PASSWD_H */
