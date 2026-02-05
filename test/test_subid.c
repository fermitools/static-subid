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
 * Constants - Exit Codes and Process Behavior
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

/* Expected argument counts for command invocations
 * Note: Counts include program name but exclude NULL terminator */
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
 * Global State - Spawn Arguments Capture
 * ============================================================================
 */

/* Captured arguments from most recent posix_spawn call */
static char *captured_path = NULL;
static char **captured_argv = NULL;
static int captured_argv_count = 0;

/* ============================================================================
 * Mock Fixture - Spawn Behavior Control
 * ============================================================================
 */

/**
 * spawn_fixture_t - Centralized state for posix_spawn mock behavior
 *
 * Controls all aspects of the spawn->wait->exit flow for testing:
 *
 * @spawn_errno: If non-zero, posix_spawn() returns this errno
 * @spawn_pid: PID assigned to *pid by posix_spawn() on success
 * @waitpid_status: Status returned via *wstatus by waitpid()
 *                  Use WEXITSTATUS(), WTERMSIG(), etc. macros to construct
 * @waitpid_fails: If true, waitpid() returns -1 with errno=ECHILD
 * @init_errno: If non-zero, file_actions_init() returns this errno
 * @addopen_errno: errno returned by failing addopen() call
 * @addopen_fail_at: Which addopen() call fails (1=first, 2=second, 0=none)
 * @addopen_count: Increments on each addopen() call (for verification)
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

static spawn_fixture_t current_fixture;

/* ============================================================================
 * Spawn Arguments Capture - Memory Management Helpers
 * ============================================================================
 */

/**
 * free_single_argv - Release a single argv array and its strings
 * @argv: Argument vector to free
 * @count: Number of elements in argv
 *
 * Helper function to centralize argv cleanup logic.
 */
static void free_single_argv(char **argv, int count) {
  int i;

  if (argv == NULL) {
    return;
  }

  for (i = 0; i < count; i++) {
    free(argv[i]);
  }
  free(argv);
}

/**
 * duplicate_argv - Create deep copy of argument vector
 * @argv: Source argument vector (NULL-terminated)
 * @out_count: Output parameter for argument count
 *
 * Creates a complete copy of argv including all strings.
 *
 * Returns: Allocated argv array, or NULL on allocation failure
 */
static char **duplicate_argv(char *const argv[], int *out_count) {
  char **new_argv;
  int count;
  int i;

  if (argv == NULL || out_count == NULL) {
    return NULL;
  }

  /* Count arguments */
  count = 0;
  while (argv[count] != NULL) {
    count++;
  }

  /* Allocate array */
  new_argv = calloc((size_t)(count + 1), sizeof(char *));
  if (new_argv == NULL) {
    return NULL;
  }

  /* Duplicate each string */
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

/* ============================================================================
 * Spawn Arguments Capture - Public Interface
 * ============================================================================
 */

/**
 * free_captured_args - Release captured spawn arguments
 *
 * Should be called after test completion to prevent memory leaks.
 * Safe to call multiple times or when no args captured.
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
 * capture_spawn_args - Record posix_spawn arguments for verification
 * @path: Executable path from posix_spawn
 * @argv: Argument vector from posix_spawn
 *
 * Duplicates path and argv so tests can verify the correct program
 * was invoked with correct arguments. Frees any previously captured
 * arguments before capturing new ones.
 *
 * Safe to call multiple times; handles cleanup automatically.
 */
static void capture_spawn_args(const char *path, char *const argv[]) {
  /* Free previous captures */
  free_captured_args();

  /* Capture new values */
  if (path != NULL) {
    captured_path = strdup(path);
  }

  if (argv != NULL) {
    captured_argv = duplicate_argv(argv, &captured_argv_count);
  }
}

/* ============================================================================
 * Fixture Management
 * ============================================================================
 */

/**
 * make_default_fixture - Create fixture for successful spawn
 *
 * Returns: Fixture configured for successful spawn with default PID
 */
static spawn_fixture_t make_default_fixture(void) {
  spawn_fixture_t fixture = {0};
  fixture.spawn_pid = DEFAULT_MOCK_PID;
  return fixture;
}

/* ============================================================================
 * Mock Functions - posix_spawn Family
 * ============================================================================
 */

/**
 * mock_posix_spawn - Simulates posix_spawn system call
 * @pid: Output parameter for child process ID
 * @path: Path to executable
 * @file_actions: File descriptor redirections (unused in mock)
 * @attrp: Process attributes (unused in mock)
 * @argv: Argument vector
 * @envp: Environment vector (unused in mock)
 *
 * Captures arguments for test verification and simulates spawn behavior
 * based on current fixture state.
 *
 * Returns: spawn_errno if set, otherwise 0 with *pid set to spawn_pid
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

  if (pid != NULL) {
    *pid = current_fixture.spawn_pid;
  }

  errno = 0;
  return 0;
}

/**
 * mock_posix_spawn_file_actions_init - Simulates file_actions initialization
 * @file_actions: File actions object to initialize (unused)
 *
 * Returns: init_errno from fixture (0 for success)
 */
static int
mock_posix_spawn_file_actions_init(posix_spawn_file_actions_t *file_actions) {
  (void)file_actions;
  errno = current_fixture.init_errno;
  return current_fixture.init_errno;
}

/**
 * mock_posix_spawn_file_actions_destroy - Simulates file_actions cleanup
 * @file_actions: File actions object to destroy (unused)
 *
 * Always succeeds in mock environment.
 *
 * Returns: Always 0
 */
static int mock_posix_spawn_file_actions_destroy(
    posix_spawn_file_actions_t *file_actions) {
  (void)file_actions;
  errno = 0;
  return 0;
}

/**
 * mock_posix_spawn_file_actions_addopen - Simulates file descriptor
 * redirection
 * @file_actions: File actions object (unused)
 * @fd: File descriptor to redirect (unused)
 * @path: Path to open for redirection (unused)
 * @oflag: Open flags (unused)
 * @mode: File mode (unused)
 *
 * Tracks addopen call count and simulates failure if configured in fixture.
 * This allows testing of setup phase failures in specific redirection steps.
 *
 * Returns: addopen_errno if this call matches addopen_fail_at, otherwise 0
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
 * @pid: Process ID to wait for
 * @wstatus: Pointer to store exit status
 * @options: Wait options (unused)
 *
 * Returns status from fixture or simulates failure based on fixture state.
 * Allows testing of both successful completion and waitpid failures.
 *
 * Returns: pid on success, -1 with errno=ECHILD if waitpid_fails is true
 */
static pid_t mock_waitpid(pid_t pid, int *wstatus, int options) {
  (void)options;

  if (current_fixture.waitpid_fails) {
    errno = ECHILD;
    return -1;
  }

  if (wstatus != NULL) {
    *wstatus = current_fixture.waitpid_status;
  }

  return pid;
}

/* ============================================================================
 * Fixture Builders - Pure Functions for Test Setup
 * ============================================================================
 */

/**
 * make_default_spawn_ops - Creates base syscall_ops with all spawn mocks
 *
 * Installs mock implementations for entire posix_spawn family while
 * leaving other operations at their defaults. Automatically cleans up
 * any captured arguments from previous test invocations.
 *
 * Returns: syscall_ops with spawn family mocked, other ops from default
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
 * make_fixture_process_exits - Child exits normally with given exit code
 * @exit_code: Exit code to return from child process
 *
 * Constructs waitpid status using standard encoding (exit_code << 8).
 * This simulates a normal process exit that can be checked with WEXITSTATUS().
 *
 * Returns: Fixture configured for normal exit with specified code
 */
static spawn_fixture_t make_fixture_process_exits(int exit_code) {
  spawn_fixture_t fixture = make_default_fixture();

  fixture.waitpid_status = exit_code << EXIT_CODE_SHIFT;
  errno = fixture.waitpid_status;
  return fixture;
}

/**
 * make_fixture_process_killed_by_signal - Child terminated by signal
 * @signal: Signal number that killed the process
 *
 * Constructs waitpid status to indicate signal termination without core dump.
 * This allows testing of abnormal process termination handling.
 *
 * Returns: Fixture configured for signal termination
 */
static spawn_fixture_t make_fixture_process_killed_by_signal(int signal) {
  spawn_fixture_t fixture = make_default_fixture();

  fixture.waitpid_status = signal;
  return fixture;
}

/**
 * make_fixture_file_actions_init_fails - posix_spawn_file_actions_init fails
 * @error: errno value to return from init call
 *
 * Simulates failure during file actions initialization, preventing any
 * file descriptor redirections from being set up.
 *
 * Returns: Fixture where file_actions_init returns error
 */
static spawn_fixture_t make_fixture_file_actions_init_fails(int error) {
  spawn_fixture_t fixture = make_default_fixture();

  fixture.init_errno = error;
  errno = fixture.init_errno;
  return fixture;
}

/**
 * make_fixture_addopen_fails - posix_spawn_file_actions_addopen fails at call
 * N
 * @call_num: Which addopen call to fail (1=first, 2=second, 3=third)
 * @error: errno value to return from failing call
 *
 * Allows testing of failures at specific points in file descriptor setup.
 * Useful for distinguishing between stdin and stdout redirection failures.
 *
 * Returns: Fixture where specified addopen call returns error
 */
static spawn_fixture_t make_fixture_addopen_fails(int call_num, int error) {
  spawn_fixture_t fixture = make_default_fixture();

  fixture.addopen_fail_at = call_num;
  fixture.addopen_errno = error;
  errno = fixture.addopen_fail_at;
  return fixture;
}

/**
 * make_fixture_spawn_fails - posix_spawn fails with errno
 * @error: errno value to return from spawn call
 *
 * Simulates failure during process spawn, such as executable not found
 * or insufficient permissions.
 *
 * Returns: Fixture where posix_spawn returns error
 */
static spawn_fixture_t make_fixture_spawn_fails(int error) {
  spawn_fixture_t fixture = make_default_fixture();

  fixture.spawn_errno = error;
  errno = fixture.spawn_errno;
  return fixture;
}

/**
 * make_fixture_waitpid_fails - waitpid fails with ECHILD
 *
 * Simulates waitpid failure, such as process already reaped or invalid PID.
 * This is distinct from abnormal exit (signal termination).
 *
 * Returns: Fixture where waitpid returns -1 with errno=ECHILD
 */
static spawn_fixture_t make_fixture_waitpid_fails(void) {
  spawn_fixture_t fixture = make_default_fixture();

  fixture.waitpid_fails = true;
  return fixture;
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
   * stdout suppression only happens in non-debug mode.
   * debug=true skips stdout/stderr redirects entirely (only stdin is
   * redirected), so the second addopen call is only reachable with
   * debug=false.
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
   * stderr suppression only happens in non-debug mode.
   * debug=true skips stdout/stderr redirects entirely (only stdin is
   * redirected), so the third addopen call is only reachable with debug=false.
   */
  current_fixture = make_fixture_addopen_fails(ADDOPEN_THIRD_CALL, ENOMEM);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, false);

  TEST_ASSERT_EQ(result, -1, "Should fail when stderr redirect fails");
  TEST_ASSERT_EQ(current_fixture.addopen_count, ADDOPEN_THIRD_CALL,
                 "Should reach third addopen before failing");
}

TEST(check_subid_exists_debug_suppresses_only_stdin) {
  struct syscall_ops ops;
  int result;

  /*
   * In debug mode, only stdin is redirected to /dev/null so that
   * getsubids stdout/stderr remain visible. Exactly one addopen call
   * must be made regardless of the exit path.
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
   * In non-debug mode, stdin, stdout, and stderr are all redirected to
   * /dev/null. Exactly three addopen calls must be made.
   */
  current_fixture = make_fixture_process_exits(GETSUBIDS_EXIT_EXISTS);
  ops = make_default_spawn_ops();
  result = check_subid_exists(&ops, "testuser", SUBUID, false);

  TEST_ASSERT_EQ(result, 1, "Should succeed in non-debug mode");
  TEST_ASSERT_EQ(current_fixture.addopen_count, ADDOPEN_THIRD_CALL,
                 "Non-debug mode should redirect stdin+stdout+stderr (three "
                 "addopen calls)");
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

  result =
      set_subid_range(&ops, "testuser", SUBUID, UINT32_MAX, 10, false, true);

  TEST_ASSERT_EQ(result, -1, "Should detect integer overflow in range");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set the correct error code");
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

  /* Edge case: count=1 should format as "start-start" */
  result = set_subid_range(&ops, "user1", SUBUID, 50000, 1, false, true);
  TEST_ASSERT_EQ(result, 0, "Should succeed");
  TEST_ASSERT_STR_EQ(captured_argv[2], "50000-50000",
                     "count=1 should format as 'start-start' (single ID)");

  /* Large range formatting */
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

  result = TEST_EXECUTE();

  free_captured_args(); /* free to avoid "mem leak" */

  return result;
}
