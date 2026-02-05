/**
 * test_subid.c - Tests for subordinate ID operations
 */

/* clang-format off */
#include "autoconf.h"
#include "static-subid.h"
#include "syscall_ops.h"
/* clang-format on */

#include <errno.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>

#include "test_framework.h"
#include "test_helpers/all.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/* Default mock PID assigned to spawned child processes */
enum { DEFAULT_MOCK_PID = 12345 };

/* getsubids exit code semantics */
enum {
  GETSUBIDS_EXIT_EXISTS = 0,    /* User has subordinate ID ranges */
  GETSUBIDS_EXIT_NOT_FOUND = 1, /* User has no subordinate ID ranges */
  GETSUBIDS_EXIT_ERROR = 2      /* Error occurred during query */
};

/* usermod exit code semantics */
enum {
  USERMOD_EXIT_SUCCESS = 0, /* Range assignment succeeded */
  USERMOD_EXIT_ERROR = 1    /* Range assignment failed */
};

/* Expected argument counts for command invocations.
 * Counts include program name but exclude NULL terminator. */
enum {
  GETSUBIDS_SUBUID_ARGC = 2, /* getsubids <username> */
  GETSUBIDS_SUBGID_ARGC = 3, /* getsubids -g <username> */
  USERMOD_ARGC = 4           /* usermod <flag> <range> <username> */
};

/* File action control constants */
enum {
  ADDOPEN_FIRST_CALL = 1,  /* First file_actions_addopen call */
  ADDOPEN_SECOND_CALL = 2, /* Second file_actions_addopen call */
  ADDOPEN_THIRD_CALL = 3   /* Third file_actions_addopen call */
};

/* WEXITSTATUS macro equivalent - extract exit code from status */
enum { EXIT_CODE_SHIFT = 8 };

/* ============================================================================
 * Fixture Type
 *
 * Centralized state for posix_spawn mock behavior.  One instance,
 * current_fixture, is set by a fixture builder before each test that
 * exercises the spawn path, then read by the mock functions below.
 * ============================================================================
 */

/**
 * spawn_fixture_t - Controls all aspects of the spawn->wait->exit flow
 *
 * @spawn_errno:     If non-zero, posix_spawn() returns this errno
 * @spawn_pid:       PID assigned to *pid by posix_spawn() on success
 * @waitpid_status:  Status returned via *wstatus by waitpid();
 *                   use WEXITSTATUS(), WTERMSIG(), etc. to construct
 * @waitpid_fails:   If true, waitpid() returns -1 with errno=ECHILD
 * @init_errno:      If non-zero, file_actions_init() returns this errno
 * @addopen_errno:   errno returned by the failing addopen() call
 * @addopen_fail_at: Which addopen() call fails (1=first, 2=second, 0=none)
 * @addopen_count:   Incremented on each addopen() call; read by tests
 */
typedef struct {
  int spawn_errno;
  pid_t spawn_pid;
  int waitpid_status;
  bool waitpid_fails;
  int init_errno;
  int addopen_errno;
  int addopen_fail_at;
  int addopen_count;
} spawn_fixture_t;

/* ============================================================================
 * Global State
 *
 * All mutable test state lives here so its lifetime and coupling are visible.
 * current_fixture drives mock behavior; the captured_* variables are written
 * by mocks and read by test assertions.
 * ============================================================================
 */

/* Active fixture; set by a fixture builder before each spawn-path test */
static spawn_fixture_t current_fixture;

/* Captured path and argv from the most recent posix_spawn call.
 * Written by mock_posix_spawn via capture_spawn_args().
 * Tests assert on these after calling the function under test. */
static char *captured_path = NULL;
static char **captured_argv = NULL;
static int captured_argv_count = 0;

/* Shallow copy of the envp array from the most recent posix_spawn call.
 * Written by mock_posix_spawn_capture_env(); used to verify that
 * build_safe_environ() produced the correct set of variables.
 * Strings point into the original safe_env array and must not be freed. */
static char **captured_envp = NULL;
static int captured_envp_count = 0;

/* ============================================================================
 * Capture Helpers
 *
 * Low-level memory management for the captured_* globals.  Called by the
 * mock spawn functions and by the cleanup path in main().
 * ============================================================================
 */

/**
 * free_single_argv - Release a deep-copied argv array and its strings
 * @argv:  Argument vector to free
 * @count: Number of populated elements
 */
static void free_single_argv(char **argv, int count) {
  int i;

  if (argv == NULL)
    return;

  for (i = 0; i < count; i++)
    free(argv[i]);
  free(argv);
}

/**
 * duplicate_argv - Deep-copy a NULL-terminated argument vector
 * @argv:      Source vector
 * @out_count: Set to the number of elements copied (excluding NULL)
 *
 * Return: Allocated argv array, or NULL on allocation failure
 */
static char **duplicate_argv(char *const argv[], int *out_count) {
  char **new_argv;
  int count;
  int i;

  if (argv == NULL || out_count == NULL)
    return NULL;

  count = 0;
  while (argv[count] != NULL)
    count++;

  new_argv = calloc((size_t)(count + 1), sizeof(char *));
  if (new_argv == NULL)
    return NULL;

  for (i = 0; i < count; i++) {
    new_argv[i] = strdup(argv[i]);
    if (new_argv[i] == NULL) {
      free_single_argv(new_argv, i);
      return NULL;
    }
  }
  new_argv[count] = NULL;

  *out_count = count;
  return new_argv;
}

/**
 * free_captured_args - Release captured path and argv; reset globals to NULL
 *
 * Safe to call when nothing is captured.
 */
static void free_captured_args(void) {
  if (captured_path != NULL) {
    free(captured_path);
    captured_path = NULL;
  }

  free_single_argv(captured_argv, captured_argv_count);
  captured_argv = NULL;
  captured_argv_count = 0;
}

/**
 * free_captured_env - Release captured envp array; reset globals to NULL
 *
 * Only the array itself is freed; strings are shallow pointers into the
 * original safe_env allocation in the function under test.
 */
static void free_captured_env(void) {
  free(captured_envp);
  captured_envp = NULL;
  captured_envp_count = 0;
}

/**
 * capture_spawn_args - Record path and argv from a posix_spawn call
 * @path: Executable path
 * @argv: Argument vector (NULL-terminated)
 *
 * Frees any previous capture before storing the new one.
 */
static void capture_spawn_args(const char *path, char *const argv[]) {
  free_captured_args();

  if (path != NULL)
    captured_path = strdup(path);

  if (argv != NULL)
    captured_argv = duplicate_argv(argv, &captured_argv_count);
}

/**
 * capture_spawn_env - Record envp from a posix_spawn call (shallow copy)
 * @envp: Environment vector (NULL-terminated)
 *
 * The array is a shallow copy; individual strings point into the caller's
 * allocation and must not be freed via this array.  Frees any previous
 * capture before storing the new one.
 */
static void capture_spawn_env(char *const envp[]) {
  int count;
  int i;

  free_captured_env();

  if (envp == NULL)
    return;

  count = 0;
  while (envp[count] != NULL)
    count++;

  captured_envp = calloc((size_t)(count + 1), sizeof(char *));
  if (captured_envp == NULL)
    return;

  for (i = 0; i < count; i++)
    captured_envp[i] = envp[i];
  captured_envp[count] = NULL;
  captured_envp_count = count;
}

/* ============================================================================
 * Mock Functions - posix_spawn Family
 *
 * Installed into a syscall_ops struct by the fixture builders and called in
 * place of the real system calls.  All read from / write to current_fixture
 * and the captured_* globals.
 * ============================================================================
 */

/**
 * mock_posix_spawn - Simulates posix_spawn, capturing path and argv
 *
 * Drives behavior from current_fixture: returns spawn_errno if set,
 * otherwise sets *pid = spawn_pid and returns 0.
 */
static int mock_posix_spawn(pid_t *restrict pid, const char *restrict path,
                            const posix_spawn_file_actions_t *file_actions,
                            const posix_spawnattr_t *restrict attrp,
                            char *const argv[restrict],
                            char *const envp[restrict]) {
  (void)file_actions;
  (void)attrp;
  (void)envp;

  capture_spawn_args(path, argv);

  if (current_fixture.spawn_errno != 0) {
    errno = current_fixture.spawn_errno;
    return current_fixture.spawn_errno;
  }

  if (pid != NULL)
    *pid = current_fixture.spawn_pid;

  errno = 0;
  return 0;
}

/**
 * mock_posix_spawn_capture_env - posix_spawn variant that also captures envp
 *
 * Delegates to mock_posix_spawn for path/argv capture and fixture-driven
 * behavior, then additionally records the envp array so tests can verify
 * the sanitized environment produced by build_safe_environ().
 */
static int
mock_posix_spawn_capture_env(pid_t *restrict pid, const char *restrict path,
                             const posix_spawn_file_actions_t *file_actions,
                             const posix_spawnattr_t *restrict attrp,
                             char *const argv[restrict],
                             char *const envp[restrict]) {
  int ret = mock_posix_spawn(pid, path, file_actions, attrp, argv, envp);
  capture_spawn_env(envp);
  return ret;
}

/**
 * mock_posix_spawn_file_actions_init - Simulates file_actions initialization
 *
 * Returns init_errno from the current fixture (0 = success).
 */
static int
mock_posix_spawn_file_actions_init(posix_spawn_file_actions_t *file_actions) {
  (void)file_actions;
  errno = current_fixture.init_errno;
  return current_fixture.init_errno;
}

/**
 * mock_posix_spawn_file_actions_destroy - Simulates file_actions cleanup
 *
 * Always succeeds; no real resources to release in the mock.
 */
static int mock_posix_spawn_file_actions_destroy(
    posix_spawn_file_actions_t *file_actions) {
  (void)file_actions;
  errno = 0;
  return 0;
}

/**
 * mock_posix_spawn_file_actions_addopen - Simulates fd redirection setup
 *
 * Increments addopen_count on each call.  Returns addopen_errno if this
 * call number matches addopen_fail_at, otherwise returns 0.
 */
static int mock_posix_spawn_file_actions_addopen(
    posix_spawn_file_actions_t *restrict file_actions, int fd,
    const char *restrict path, int oflag, mode_t mode) {
  (void)file_actions;
  (void)fd;
  (void)path;
  (void)oflag;
  (void)mode;

  current_fixture.addopen_count++;

  if (current_fixture.addopen_fail_at > 0 &&
      current_fixture.addopen_count == current_fixture.addopen_fail_at) {
    errno = current_fixture.addopen_errno;
    return current_fixture.addopen_errno;
  }

  errno = 0;
  return 0;
}

/**
 * mock_waitpid - Simulates waiting for child process completion
 *
 * Returns -1 with errno=ECHILD if waitpid_fails is set; otherwise sets
 * *wstatus from the fixture and returns pid.
 */
static pid_t mock_waitpid(pid_t pid, int *wstatus, int options) {
  (void)options;

  if (current_fixture.waitpid_fails) {
    errno = ECHILD;
    return -1;
  }

  if (wstatus != NULL)
    *wstatus = current_fixture.waitpid_status;

  return pid;
}

/* ============================================================================
 * Fixture Builders
 *
 * Pure functions that return a fully configured spawn_fixture_t or
 * syscall_ops.  Tests assign the result to current_fixture and call the
 * matching make_*_spawn_ops() to get an ops struct wired to those mocks.
 * ============================================================================
 */

/**
 * make_default_fixture - Base fixture: successful spawn with DEFAULT_MOCK_PID
 */
static spawn_fixture_t make_default_fixture(void) {
  spawn_fixture_t fixture = {0};
  fixture.spawn_pid = DEFAULT_MOCK_PID;
  return fixture;
}

/**
 * make_fixture_process_exits - Child exits normally with the given exit code
 *
 * Encodes exit_code into the waitpid status word (exit_code << 8) so that
 * WIFEXITED() and WEXITSTATUS() behave correctly on the mock status.
 */
static spawn_fixture_t make_fixture_process_exits(int exit_code) {
  spawn_fixture_t fixture = make_default_fixture();
  fixture.waitpid_status = exit_code << EXIT_CODE_SHIFT;
  return fixture;
}

/**
 * make_fixture_process_killed_by_signal - Child terminated by signal
 *
 * Encodes the signal number directly into the status word so that
 * WIFSIGNALED() and WTERMSIG() behave correctly on the mock status.
 */
static spawn_fixture_t make_fixture_process_killed_by_signal(int signal) {
  spawn_fixture_t fixture = make_default_fixture();
  fixture.waitpid_status = signal;
  return fixture;
}

/**
 * make_fixture_file_actions_init_fails - file_actions_init returns error
 * @error: errno value to return
 */
static spawn_fixture_t make_fixture_file_actions_init_fails(int error) {
  spawn_fixture_t fixture = make_default_fixture();
  fixture.init_errno = error;
  return fixture;
}

/**
 * make_fixture_addopen_fails - A specific addopen() call returns error
 * @call_num: Which call fails (ADDOPEN_FIRST_CALL / _SECOND / _THIRD)
 * @error:    errno value to return from that call
 */
static spawn_fixture_t make_fixture_addopen_fails(int call_num, int error) {
  spawn_fixture_t fixture = make_default_fixture();
  fixture.addopen_fail_at = call_num;
  fixture.addopen_errno = error;
  return fixture;
}

/**
 * make_fixture_spawn_fails - posix_spawn itself returns an error
 * @error: errno value to return
 */
static spawn_fixture_t make_fixture_spawn_fails(int error) {
  spawn_fixture_t fixture = make_default_fixture();
  fixture.spawn_errno = error;
  return fixture;
}

/**
 * make_fixture_waitpid_fails - waitpid returns -1 with errno=ECHILD
 */
static spawn_fixture_t make_fixture_waitpid_fails(void) {
  spawn_fixture_t fixture = make_default_fixture();
  fixture.waitpid_fails = true;
  return fixture;
}

/**
 * make_default_spawn_ops - Base ops struct with all spawn mocks installed
 *
 * Clears captured_path/argv from any previous test as a side effect of
 * installing mock_posix_spawn, which calls capture_spawn_args() on entry.
 */
static struct syscall_ops make_default_spawn_ops(void) {
  struct syscall_ops ops = syscall_ops_default;

  ops.posix_spawn = mock_posix_spawn;
  ops.posix_spawn_file_actions_init = mock_posix_spawn_file_actions_init;
  ops.posix_spawn_file_actions_destroy = mock_posix_spawn_file_actions_destroy;
  ops.posix_spawn_file_actions_addopen = mock_posix_spawn_file_actions_addopen;
  ops.waitpid = mock_waitpid;

  return ops;
}

/**
 * make_env_capture_spawn_ops - Ops that also capture the envp array
 *
 * Use when a test needs to inspect the sanitized environment that
 * build_safe_environ() produced.  Replaces posix_spawn with the
 * env-capturing variant on top of make_default_spawn_ops().
 */
static struct syscall_ops make_env_capture_spawn_ops(void) {
  struct syscall_ops ops = make_default_spawn_ops();
  ops.posix_spawn = mock_posix_spawn_capture_env;
  return ops;
}

/**
 * make_oom_spawn_ops - Ops that fail calloc to simulate OOM in
 * build_safe_environ
 *
 * mock_calloc_null is provided by test_helper_mock_alloc.h (via all.h); it
 * always returns NULL without attempting allocation.  Combined with the full
 * spawn mock set so the test reaches build_safe_environ() before the failure.
 */
static struct syscall_ops make_oom_spawn_ops(void) {
  struct syscall_ops ops = make_default_spawn_ops();
  ops.calloc = mock_calloc_null;
  return ops;
}

/* ============================================================================
 * Test Helpers
 * ============================================================================
 */

/**
 * env_contains_key - Check whether the captured env has a KEY=... entry
 * @key: Variable name without the trailing '='
 *
 * Return: true if any captured_envp entry begins with "key=", false otherwise
 */
static bool env_contains_key(const char *key) {
  size_t klen;
  int i;

  if (captured_envp == NULL)
    return false;

  klen = strlen(key);
  for (i = 0; i < captured_envp_count; i++) {
    if (strncmp(captured_envp[i], key, klen) == 0 &&
        captured_envp[i][klen] == '=')
      return true;
  }
  return false;
}

/* ============================================================================
 * Tests - check_subid_exists: Input Validation
 * ============================================================================
 */

TEST(check_subid_exists_null_ops) {
  int result = check_subid_exists(NULL, "testuser", SUBUID, true);
  TEST_ASSERT_EQ(result, -1, "Should reject NULL ops");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(check_subid_exists_null_username) {
  struct syscall_ops ops = syscall_ops_default;
  int result = check_subid_exists(&ops, NULL, SUBUID, true);
  TEST_ASSERT_EQ(result, -1, "Should reject NULL username");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(check_subid_exists_invalid_mode) {
  struct syscall_ops ops = syscall_ops_default;
  int result = check_subid_exists(&ops, "testuser", (subid_mode_t)999, true);
  TEST_ASSERT_EQ(result, -1, "Should reject invalid mode");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

/* ============================================================================
 * Tests - check_subid_exists: Normal Operation
 * ============================================================================
 */

TEST(check_subid_exists_subuid_exists) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_process_exits(GETSUBIDS_EXIT_EXISTS);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, true);

  TEST_ASSERT_EQ(result, 1, "Exit 0 from getsubids means ranges exist");
  TEST_ASSERT_STR_EQ(captured_path, GETSUBIDS_PATH,
                     "Should invoke getsubids at correct path");
}

TEST(check_subid_exists_subuid_not_exists) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_process_exits(GETSUBIDS_EXIT_NOT_FOUND);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, true);

  TEST_ASSERT_EQ(result, 0, "Exit 1 from getsubids means no ranges");
}

TEST(check_subid_exists_subgid_exists) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_process_exits(GETSUBIDS_EXIT_EXISTS);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBGID, true);

  TEST_ASSERT_EQ(result, 1, "Exit 0 from getsubids means ranges exist");
  TEST_ASSERT_STR_EQ(captured_path, GETSUBIDS_PATH,
                     "Should invoke getsubids at correct path");
}

TEST(check_subid_exists_no_debug) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_process_exits(GETSUBIDS_EXIT_EXISTS);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, false);

  TEST_ASSERT_EQ(result, 1, "Should work without debug output");

  current_fixture = make_fixture_process_exits(GETSUBIDS_EXIT_EXISTS);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBGID, false);

  TEST_ASSERT_EQ(result, 1, "Should work without debug output");
}

TEST(check_subid_exists_subuid_not_exists_no_debug) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_process_exits(GETSUBIDS_EXIT_NOT_FOUND);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, false);

  TEST_ASSERT_EQ(result, 0, "Exit 1 from getsubids means no ranges (no debug)");
}

/* ============================================================================
 * Tests - check_subid_exists: Argument Verification
 * ============================================================================
 */

TEST(check_subid_exists_subuid_args_correct) {
  struct syscall_ops ops;
  int result;

  const char *expected_basename = strrchr(GETSUBIDS_PATH, '/');
  expected_basename =
      expected_basename ? expected_basename + 1 : GETSUBIDS_PATH;

  current_fixture = make_fixture_process_exits(GETSUBIDS_EXIT_EXISTS);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "alice", SUBUID, true);

  TEST_ASSERT_EQ(result, 1, "Should succeed");
  TEST_ASSERT_EQ(captured_argv_count, GETSUBIDS_SUBUID_ARGC,
                 "Should have 2 args (program, username)");
  TEST_ASSERT_STR_EQ(captured_argv[0], expected_basename,
                     "argv[0] should be program name");
  TEST_ASSERT_STR_EQ(captured_argv[1], "alice", "argv[1] should be username");
}

TEST(check_subid_exists_subgid_args_correct) {
  struct syscall_ops ops;
  int result;

  const char *expected_basename = strrchr(GETSUBIDS_PATH, '/');
  expected_basename =
      expected_basename ? expected_basename + 1 : GETSUBIDS_PATH;

  current_fixture = make_fixture_process_exits(GETSUBIDS_EXIT_EXISTS);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "bob", SUBGID, true);

  TEST_ASSERT_EQ(result, 1, "Should succeed");
  TEST_ASSERT_EQ(captured_argv_count, GETSUBIDS_SUBGID_ARGC,
                 "Should have 3 args (program, -g, username)");
  TEST_ASSERT_STR_EQ(captured_argv[0], expected_basename,
                     "argv[0] should be program name");
  TEST_ASSERT_STR_EQ(captured_argv[1], "-g", "argv[1] should be -g flag");
  TEST_ASSERT_STR_EQ(captured_argv[2], "bob", "argv[2] should be username");
}

/* ============================================================================
 * Tests - check_subid_exists: System Call Failures
 * ============================================================================
 */

TEST(check_subid_exists_debug_suppresses_only_stdin) {
  struct syscall_ops ops;
  int result;

  /*
   * In debug mode only stdin is redirected to /dev/null so that getsubids
   * stdout/stderr remain visible.  Exactly one addopen call must be made.
   */
  current_fixture = make_fixture_process_exits(GETSUBIDS_EXIT_EXISTS);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, true);

  TEST_ASSERT_EQ(result, 1, "Should succeed in debug mode");
  TEST_ASSERT_EQ(current_fixture.addopen_count, ADDOPEN_FIRST_CALL,
                 "Debug mode should redirect only stdin (one addopen call)");
}

TEST(check_subid_exists_no_debug_suppresses_stdin_stdout_stderr) {
  struct syscall_ops ops;
  int result;

  /*
   * In non-debug mode stdin, stdout, and stderr are all redirected to
   * /dev/null.  Exactly three addopen calls must be made.
   */
  current_fixture = make_fixture_process_exits(GETSUBIDS_EXIT_EXISTS);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, false);

  TEST_ASSERT_EQ(result, 1, "Should succeed in non-debug mode");
  TEST_ASSERT_EQ(current_fixture.addopen_count, ADDOPEN_THIRD_CALL,
                 "Non-debug mode should redirect stdin+stdout+stderr (three "
                 "addopen calls)");
}

TEST(check_subid_exists_init_fails) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_file_actions_init_fails(ENOMEM);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, true);

  TEST_ASSERT_EQ(result, -1,
                 "Should fail when posix_spawn_file_actions_init fails");
}

TEST(check_subid_exists_first_addopen_fails) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_addopen_fails(ADDOPEN_FIRST_CALL, ENOMEM);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, true);

  TEST_ASSERT_EQ(result, -1, "Should fail when stdin redirect fails");
  TEST_ASSERT_EQ(current_fixture.addopen_count, ADDOPEN_FIRST_CALL,
                 "Should stop at first addopen failure");
}

TEST(check_subid_exists_second_addopen_fails) {
  struct syscall_ops ops;
  int result;

  /*
   * stdout suppression only happens in non-debug mode; the second addopen
   * call is not reachable with debug=true.
   */
  current_fixture = make_fixture_addopen_fails(ADDOPEN_SECOND_CALL, ENOMEM);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, false);

  TEST_ASSERT_EQ(result, -1, "Should fail when stdout redirect fails");
  TEST_ASSERT_EQ(current_fixture.addopen_count, ADDOPEN_SECOND_CALL,
                 "Should reach second addopen before failing");
}

TEST(check_subid_exists_third_addopen_fails) {
  struct syscall_ops ops;
  int result;

  /*
   * stderr suppression only happens in non-debug mode; the third addopen
   * call is not reachable with debug=true.
   */
  current_fixture = make_fixture_addopen_fails(ADDOPEN_THIRD_CALL, ENOMEM);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, false);

  TEST_ASSERT_EQ(result, -1, "Should fail when stderr redirect fails");
  TEST_ASSERT_EQ(current_fixture.addopen_count, ADDOPEN_THIRD_CALL,
                 "Should reach third addopen before failing");
}

TEST(check_subid_exists_spawn_fails) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_spawn_fails(ENOENT);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, true);

  TEST_ASSERT_EQ(result, -1, "Should fail when posix_spawn returns error");
}

TEST(check_subid_exists_waitpid_fails) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_waitpid_fails();
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, true);

  TEST_ASSERT_EQ(result, -1, "Should fail when waitpid returns error");
}

TEST(check_subid_exists_abnormal_exit) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_process_killed_by_signal(SIGKILL);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, true);

  TEST_ASSERT_EQ(result, -1, "Should fail when process terminated abnormally");
}

TEST(check_subid_exists_unexpected_exit_code) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_process_exits(GETSUBIDS_EXIT_ERROR);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, true);

  TEST_ASSERT_EQ(result, -1, "Should fail on unexpected exit code");
}

/* ============================================================================
 * Tests - set_subid_range: Input Validation
 * ============================================================================
 */

TEST(set_subid_range_null_ops) {
  int result =
      set_subid_range(NULL, "testuser", SUBUID, 100000, 65536, false, true);
  TEST_ASSERT_EQ(result, -1, "Should reject NULL ops");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(set_subid_range_null_username) {
  struct syscall_ops ops = syscall_ops_default;
  int result = set_subid_range(&ops, NULL, SUBUID, 100000, 65536, false, true);
  TEST_ASSERT_EQ(result, -1, "Should reject NULL username");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(set_subid_range_zero_count) {
  struct syscall_ops ops = syscall_ops_default;
  int result =
      set_subid_range(&ops, "testuser", SUBUID, 100000, 0, false, true);
  TEST_ASSERT_EQ(result, -1, "Should reject zero count (empty range)");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(set_subid_range_invalid_mode) {
  struct syscall_ops ops = syscall_ops_default;
  int result = set_subid_range(&ops, "testuser", (subid_mode_t)999, 100000,
                               65536, false, true);
  TEST_ASSERT_EQ(result, -1, "Should reject invalid mode");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(set_subid_range_overflow) {
  struct syscall_ops ops = syscall_ops_default;
  int result;

  /*
   * start=UINT32_MAX, count=10: (uint64_t)UINT32_MAX + 10 - 1 > UINT32_MAX.
   * The overflow check uses uint64_t arithmetic so there is no wrapping.
   */
  result =
      set_subid_range(&ops, "testuser", SUBUID, UINT32_MAX, 10, false, true);

  TEST_ASSERT_EQ(result, -1, "Should detect integer overflow in range");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
}

TEST(set_subid_range_overflow_boundary) {
  struct syscall_ops ops;
  int result;

  /*
   * Exact boundary: start=UINT32_MAX-1, count=2 → end_id=UINT32_MAX.
   * (uint64_t)(UINT32_MAX-1) + 2 - 1 == UINT32_MAX, which is not >, so valid.
   */
  current_fixture = make_fixture_process_exits(USERMOD_EXIT_SUCCESS);
  ops = make_default_spawn_ops();
  result = set_subid_range(&ops, "u", SUBUID, UINT32_MAX - 1, 2, false, false);
  TEST_ASSERT_EQ(result, 0, "start + count - 1 == UINT32_MAX should be valid");

  /*
   * One past the boundary: start=UINT32_MAX-1, count=3 → end_id would be
   * UINT32_MAX+1.  (uint64_t)(UINT32_MAX-1) + 3 - 1 > UINT32_MAX, invalid.
   */
  result = set_subid_range(&ops, "u", SUBUID, UINT32_MAX - 1, 3, false, false);
  TEST_ASSERT_EQ(result, -1,
                 "start + count - 1 overflows uint32_t, must reject");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set EINVAL on overflow");

  /*
   * count=0 is caught by the zero-count guard before the overflow check.
   * This case represents a caller who passed UINT32_MAX+1 as a uint32_t,
   * which wraps to 0 at the call site.
   */
  ops = syscall_ops_default;
  result = set_subid_range(&ops, "u", SUBUID, 0, 0, false, false);
  TEST_ASSERT_EQ(result, -1, "count=0 (UINT32_MAX+1 wrapped) must reject");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set EINVAL for zero count");
}

/* ============================================================================
 * Tests - set_subid_range: Normal Operation
 * ============================================================================
 */

TEST(set_subid_range_subuid_success) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_process_exits(USERMOD_EXIT_SUCCESS);
  ops = make_default_spawn_ops();
  result =
      set_subid_range(&ops, "testuser", SUBUID, 100000, 65536, false, true);

  TEST_ASSERT_EQ(result, 0, "Should succeed for SUBUID assignment");
  TEST_ASSERT_STR_EQ(captured_path, USERMOD_PATH,
                     "Should invoke usermod at correct path");
}

TEST(set_subid_range_subgid_success) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_process_exits(USERMOD_EXIT_SUCCESS);
  ops = make_default_spawn_ops();
  result =
      set_subid_range(&ops, "testuser", SUBGID, 100000, 65536, false, true);

  TEST_ASSERT_EQ(result, 0, "Should succeed for SUBGID assignment");
  TEST_ASSERT_STR_EQ(captured_path, USERMOD_PATH,
                     "Should invoke usermod at correct path");
}

TEST(set_subid_range_count_one) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_process_exits(USERMOD_EXIT_SUCCESS);
  ops = make_default_spawn_ops();
  result = set_subid_range(&ops, "testuser", SUBUID, 100000, 1, false, true);

  TEST_ASSERT_EQ(result, 0, "Should succeed with count=1 (single ID)");
}

TEST(set_subid_range_large_count) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_process_exits(USERMOD_EXIT_SUCCESS);
  ops = make_default_spawn_ops();
  result = set_subid_range(&ops, "testuser", SUBUID, 1000, UINT32_MAX - 1001,
                           false, true);

  TEST_ASSERT_EQ(result, 0, "Should succeed with maximum valid range");
}

TEST(set_subid_range_noop) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_default_fixture();
  ops = make_default_spawn_ops();
  result = set_subid_range(&ops, "testuser", SUBUID, 100000, 65536, true, true);

  TEST_ASSERT_EQ(result, 0, "Should succeed in noop mode");
  TEST_ASSERT_EQ(captured_path == NULL, true,
                 "Should not spawn process in noop mode");
}

TEST(set_subid_range_no_debug) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_process_exits(USERMOD_EXIT_SUCCESS);
  ops = make_default_spawn_ops();
  result =
      set_subid_range(&ops, "testuser", SUBUID, 100000, 65536, false, false);

  TEST_ASSERT_EQ(result, 0, "Should work without debug output");
}

/* ============================================================================
 * Tests - set_subid_range: Argument Verification
 * ============================================================================
 */

TEST(set_subid_range_subuid_args_correct) {
  struct syscall_ops ops;
  int result;

  const char *expected_basename = strrchr(USERMOD_PATH, '/');
  expected_basename = expected_basename ? expected_basename + 1 : USERMOD_PATH;

  current_fixture = make_fixture_process_exits(USERMOD_EXIT_SUCCESS);
  ops = make_default_spawn_ops();
  result = set_subid_range(&ops, "alice", SUBUID, 100000, 65536, false, true);

  TEST_ASSERT_EQ(result, 0, "Should succeed");
  TEST_ASSERT_EQ(captured_argv_count, USERMOD_ARGC,
                 "Should have 4 args (program, flag, range, username)");
  TEST_ASSERT_STR_EQ(captured_argv[0], expected_basename,
                     "argv[0] should be program name");
  TEST_ASSERT_STR_EQ(captured_argv[1], "--add-subuids",
                     "argv[1] should be --add-subuids for SUBUID");
  TEST_ASSERT_STR_EQ(captured_argv[2], "100000-165535",
                     "argv[2] should be range string (start-end)");
  TEST_ASSERT_STR_EQ(captured_argv[3], "alice", "argv[3] should be username");
}

TEST(set_subid_range_subgid_args_correct) {
  struct syscall_ops ops;
  int result;

  const char *expected_basename = strrchr(USERMOD_PATH, '/');
  expected_basename = expected_basename ? expected_basename + 1 : USERMOD_PATH;

  current_fixture = make_fixture_process_exits(USERMOD_EXIT_SUCCESS);
  ops = make_default_spawn_ops();
  result = set_subid_range(&ops, "bob", SUBGID, 200000, 4096, false, true);

  TEST_ASSERT_EQ(result, 0, "Should succeed");
  TEST_ASSERT_EQ(captured_argv_count, USERMOD_ARGC,
                 "Should have 4 args (program, flag, range, username)");
  TEST_ASSERT_STR_EQ(captured_argv[0], expected_basename,
                     "argv[0] should be program name");
  TEST_ASSERT_STR_EQ(captured_argv[1], "--add-subgids",
                     "argv[1] should be --add-subgids for SUBGID");
  TEST_ASSERT_STR_EQ(captured_argv[2], "200000-204095",
                     "argv[2] should be range string (start-end)");
  TEST_ASSERT_STR_EQ(captured_argv[3], "bob", "argv[3] should be username");
}

TEST(set_subid_range_range_formatting) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_process_exits(USERMOD_EXIT_SUCCESS);
  ops = make_default_spawn_ops();

  /* count=1 should format as "start-start" (single ID, not a span) */
  result = set_subid_range(&ops, "user1", SUBUID, 50000, 1, false, true);
  TEST_ASSERT_EQ(result, 0, "Should succeed");
  TEST_ASSERT_STR_EQ(captured_argv[2], "50000-50000",
                     "count=1 should format as 'start-start' (single ID)");

  result = set_subid_range(&ops, "user2", SUBUID, 1000000, 100000, false, true);
  TEST_ASSERT_EQ(result, 0, "Should succeed");
  TEST_ASSERT_STR_EQ(captured_argv[2], "1000000-1099999",
                     "Large range should format correctly");
}

/* ============================================================================
 * Tests - set_subid_range: System Call Failures
 * ============================================================================
 */

TEST(set_subid_range_init_fails) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_file_actions_init_fails(ENOMEM);
  ops = make_default_spawn_ops();
  result =
      set_subid_range(&ops, "testuser", SUBUID, 100000, 65536, false, true);

  TEST_ASSERT_EQ(result, -1,
                 "Should fail when posix_spawn_file_actions_init fails");
}

TEST(set_subid_range_addopen_fails) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_addopen_fails(ADDOPEN_FIRST_CALL, ENOMEM);
  ops = make_default_spawn_ops();
  result =
      set_subid_range(&ops, "testuser", SUBUID, 100000, 65536, false, true);

  TEST_ASSERT_EQ(result, -1, "Should fail when stdin redirect fails");
  TEST_ASSERT_EQ(current_fixture.addopen_count, ADDOPEN_FIRST_CALL,
                 "Should attempt one addopen call");
}

TEST(set_subid_range_spawn_fails) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_spawn_fails(ENOENT);
  ops = make_default_spawn_ops();
  result =
      set_subid_range(&ops, "testuser", SUBUID, 100000, 65536, false, true);

  TEST_ASSERT_EQ(result, -1, "Should fail when posix_spawn returns error");
}

TEST(set_subid_range_waitpid_fails) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_waitpid_fails();
  ops = make_default_spawn_ops();
  result =
      set_subid_range(&ops, "testuser", SUBUID, 100000, 65536, false, true);

  TEST_ASSERT_EQ(result, -1, "Should fail when waitpid returns error");
}

TEST(set_subid_range_terminated_by_signal) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_process_killed_by_signal(SIGTERM);
  ops = make_default_spawn_ops();
  result =
      set_subid_range(&ops, "testuser", SUBUID, 100000, 65536, false, true);

  TEST_ASSERT_EQ(result, -1, "Should fail when usermod terminated by signal");
}

TEST(set_subid_range_usermod_fails) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_process_exits(USERMOD_EXIT_ERROR);
  ops = make_default_spawn_ops();
  result =
      set_subid_range(&ops, "testuser", SUBUID, 100000, 65536, false, true);

  TEST_ASSERT_EQ(result, -1, "Should fail when usermod returns non-zero");
}

/* ============================================================================
 * Tests - build_safe_environ
 *
 * build_safe_environ() is static, so it is exercised indirectly through
 * check_subid_exists and set_subid_range.  The cases below cover:
 *   - calloc failure: both callers must return -1 before reaching posix_spawn
 *   - allowlisted variable present: must appear in the env seen by posix_spawn
 *   - non-allowlisted variable present: must be absent from that env
 *   - NULL termination: the last slot in the array must be NULL
 * ============================================================================
 */

TEST(check_subid_exists_safe_env_calloc_fails) {
  struct syscall_ops ops;
  int result;

  /*
   * OOM during build_safe_environ must propagate as -1 before posix_spawn
   * is reached.  Verify posix_spawn was never called (captured_path == NULL).
   */
  current_fixture = make_fixture_process_exits(GETSUBIDS_EXIT_EXISTS);
  ops = make_oom_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, false);

  TEST_ASSERT_EQ(result, -1,
                 "Should fail when calloc fails in build_safe_environ");
  TEST_ASSERT_EQ(captured_path == NULL, true,
                 "Should not reach posix_spawn on OOM");
}

TEST(set_subid_range_safe_env_calloc_fails) {
  struct syscall_ops ops;
  int result;

  current_fixture = make_fixture_process_exits(USERMOD_EXIT_SUCCESS);
  ops = make_oom_spawn_ops();
  result =
      set_subid_range(&ops, "testuser", SUBUID, 100000, 65536, false, false);

  TEST_ASSERT_EQ(result, -1,
                 "Should fail when calloc fails in build_safe_environ");
  TEST_ASSERT_EQ(captured_path == NULL, true,
                 "Should not reach posix_spawn on OOM");
}

TEST(check_subid_exists_safe_env_excludes_ld_preload) {
  struct syscall_ops ops;
  int result;

  /*
   * LD_PRELOAD is a primary privilege-escalation vector when subid tools run
   * with elevated permissions.  It must never be forwarded to child processes
   * regardless of what is set in the caller's environment.
   */
  setenv("LD_PRELOAD", "/tmp/evil.so", 1);

  current_fixture = make_fixture_process_exits(GETSUBIDS_EXIT_EXISTS);
  ops = make_env_capture_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, false);

  unsetenv("LD_PRELOAD");

  TEST_ASSERT_EQ(result, 1, "Should succeed");
  TEST_ASSERT_EQ(env_contains_key("LD_PRELOAD"), false,
                 "LD_PRELOAD must not be passed to child process");

  free_captured_env();
}

TEST(check_subid_exists_safe_env_passes_lang) {
  struct syscall_ops ops;
  int result;

  /*
   * LANG is allowlisted so child processes can produce locale-consistent
   * output.  Verify it is present in the sanitized env.
   */
  setenv("LANG", "en_US.UTF-8", 1);

  current_fixture = make_fixture_process_exits(GETSUBIDS_EXIT_EXISTS);
  ops = make_env_capture_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, false);

  TEST_ASSERT_EQ(result, 1, "Should succeed");
  TEST_ASSERT_EQ(env_contains_key("LANG"), true,
                 "LANG should be forwarded to child process");

  free_captured_env();
}

TEST(set_subid_range_safe_env_excludes_ld_library_path) {
  struct syscall_ops ops;
  int result;

  setenv("LD_LIBRARY_PATH", "/tmp/evil/lib", 1);

  current_fixture = make_fixture_process_exits(USERMOD_EXIT_SUCCESS);
  ops = make_env_capture_spawn_ops();
  result =
      set_subid_range(&ops, "testuser", SUBUID, 100000, 65536, false, false);

  unsetenv("LD_LIBRARY_PATH");

  TEST_ASSERT_EQ(result, 0, "Should succeed");
  TEST_ASSERT_EQ(env_contains_key("LD_LIBRARY_PATH"), false,
                 "LD_LIBRARY_PATH must not be passed to child process");

  free_captured_env();
}

TEST(check_subid_exists_safe_env_null_terminated) {
  struct syscall_ops ops;
  int result;

  /*
   * posix_spawn requires the envp array to be NULL-terminated.  Check that
   * captured_envp[count] == NULL to catch off-by-one errors in the array
   * construction loop in build_safe_environ.
   */
  current_fixture = make_fixture_process_exits(GETSUBIDS_EXIT_EXISTS);
  ops = make_env_capture_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, false);

  TEST_ASSERT_EQ(result, 1, "Should succeed");
  TEST_ASSERT_EQ(captured_envp != NULL &&
                     captured_envp[captured_envp_count] == NULL,
                 true, "Sanitized env array must be NULL-terminated");

  free_captured_env();
}

/* ============================================================================
 * Test Runner
 * ============================================================================
 */

int main(int argc, char **argv) {
  int result;

  TEST_INIT(10, false, false); /* timeout, verbose, duration */

  /* check_subid_exists: Input validation */
  RUN_TEST(check_subid_exists_null_ops);
  RUN_TEST(check_subid_exists_null_username);
  RUN_TEST(check_subid_exists_invalid_mode);

  /* check_subid_exists: Normal operation */
  RUN_TEST(check_subid_exists_subuid_exists);
  RUN_TEST(check_subid_exists_subuid_not_exists);
  RUN_TEST(check_subid_exists_subgid_exists);
  RUN_TEST(check_subid_exists_no_debug);
  RUN_TEST(check_subid_exists_subuid_not_exists_no_debug);

  /* check_subid_exists: Argument verification */
  RUN_TEST(check_subid_exists_subuid_args_correct);
  RUN_TEST(check_subid_exists_subgid_args_correct);

  /* check_subid_exists: System call failures */
  RUN_TEST(check_subid_exists_debug_suppresses_only_stdin);
  RUN_TEST(check_subid_exists_no_debug_suppresses_stdin_stdout_stderr);
  RUN_TEST(check_subid_exists_init_fails);
  RUN_TEST(check_subid_exists_first_addopen_fails);
  RUN_TEST(check_subid_exists_second_addopen_fails);
  RUN_TEST(check_subid_exists_third_addopen_fails);
  RUN_TEST(check_subid_exists_spawn_fails);
  RUN_TEST(check_subid_exists_waitpid_fails);
  RUN_TEST(check_subid_exists_abnormal_exit);
  RUN_TEST(check_subid_exists_unexpected_exit_code);

  /* set_subid_range: Input validation */
  RUN_TEST(set_subid_range_null_ops);
  RUN_TEST(set_subid_range_null_username);
  RUN_TEST(set_subid_range_zero_count);
  RUN_TEST(set_subid_range_invalid_mode);
  RUN_TEST(set_subid_range_overflow);
  RUN_TEST(set_subid_range_overflow_boundary);

  /* set_subid_range: Normal operation */
  RUN_TEST(set_subid_range_subuid_success);
  RUN_TEST(set_subid_range_subgid_success);
  RUN_TEST(set_subid_range_count_one);
  RUN_TEST(set_subid_range_large_count);
  RUN_TEST(set_subid_range_noop);
  RUN_TEST(set_subid_range_no_debug);

  /* set_subid_range: Argument verification */
  RUN_TEST(set_subid_range_subuid_args_correct);
  RUN_TEST(set_subid_range_subgid_args_correct);
  RUN_TEST(set_subid_range_range_formatting);

  /* set_subid_range: System call failures */
  RUN_TEST(set_subid_range_init_fails);
  RUN_TEST(set_subid_range_addopen_fails);
  RUN_TEST(set_subid_range_spawn_fails);
  RUN_TEST(set_subid_range_waitpid_fails);
  RUN_TEST(set_subid_range_terminated_by_signal);
  RUN_TEST(set_subid_range_usermod_fails);

  /* build_safe_environ: OOM propagation */
  RUN_TEST(check_subid_exists_safe_env_calloc_fails);
  RUN_TEST(set_subid_range_safe_env_calloc_fails);

  /* build_safe_environ: Allowlist enforcement */
  RUN_TEST(check_subid_exists_safe_env_excludes_ld_preload);
  RUN_TEST(check_subid_exists_safe_env_passes_lang);
  RUN_TEST(set_subid_range_safe_env_excludes_ld_library_path);
  RUN_TEST(check_subid_exists_safe_env_null_terminated);

  result = TEST_EXECUTE();

  free_captured_args();
  free_captured_env();

  return result;
}
