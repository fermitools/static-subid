/**
 * test_helper_mock_file.h - File operation mock functions
 *
 * Provides mock implementations of file management functions for testing
 * error handling paths. These mocks simulate actions and failures without
 * requiring actual files.
 *
 * This header is self-contained and can be included independently, but
 * including via test_helper_all.h is recommended for proper initialization.
 */

#ifndef TEST_HELPER_MOCK_FILE_H
#define TEST_HELPER_MOCK_FILE_H

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

/* ============================================================================
 * open() Mock Implementations
 * ============================================================================
 */

/**
 * mock_open_enoent - Mock open that fails with ENOENT
 * @pathname: Path to open (ignored)
 * @flags: Open flags (ignored)
 *
 * Simulates file not found condition.
 *
 * Return: -1 with errno set to ENOENT
 */
static int mock_open_enoent(const char *pathname, int flags, ...)
{
	(void)pathname;
	(void)flags;
	errno = ENOENT;
	return -1;
}

/**
 * mock_open_eperm - Mock open that fails with EPERM
 * @pathname: Path to open (ignored)
 * @flags: Open flags (ignored)
 *
 * Simulates operation not permitted condition.
 *
 * Return: -1 with errno set to EPERM
 */
static int mock_open_eperm(const char *pathname, int flags, ...)
{
	(void)pathname;
	(void)flags;
	errno = EPERM;
	return -1;
}

/**
 * mock_open_eacces - Mock open that fails with EACCES
 * @pathname: Path to open (ignored)
 * @flags: Open flags (ignored)
 *
 * Simulates permission denied condition.
 *
 * Return: -1 with errno set to EACCES
 */
static int mock_open_eacces(const char *pathname, int flags, ...)
{
	(void)pathname;
	(void)flags;
	errno = EACCES;
	return -1;
}

/* ============================================================================
 * fdopen() Mock Implementations
 * ============================================================================
 */

/**
 * mock_fdopen_null - Mock fdopen that always fails
 * @fd: File descriptor (ignored)
 * @mode: Open mode (ignored)
 *
 * Simulates fdopen() failure by returning NULL.
 *
 * Return: NULL with errno set to ENOMEM
 */
static FILE *mock_fdopen_null(int fd, const char *mode)
{
	(void)fd;
	(void)mode;
	errno = ENOMEM;
	return NULL;
}

/* ============================================================================
 * close() Mock Implementations
 * ============================================================================
 */

/**
 * mock_close_any - Mock close that accepts any fd
 * @fd: File descriptor (ignored)
 *
 * Accepts any file descriptor for custom content scenarios.
 *
 * Return: Always 0
 */
static int mock_close_any(int fd)
{
	(void)fd;
	return 0;
}

/* ============================================================================
 * scandir() Mock Implementations
 * ============================================================================
 */

/**
 * mock_scandir_enoent - Mock scandir that fails with ENOENT
 * @dirp: Directory path (ignored)
 * @namelist: Output name list (ignored)
 * @filter: Filter function (ignored)
 * @compar: Comparison function (ignored)
 *
 * Simulates directory not found condition.
 *
 * Return: -1 with errno set to ENOENT
 */
static int mock_scandir_enoent(const char *dirp, struct dirent ***namelist,
				int (*filter)(const struct dirent *),
				int (*compar)(const struct dirent **,
					      const struct dirent **))
{
	(void)dirp;
	(void)namelist;
	(void)filter;
	(void)compar;
	errno = ENOENT;
	return -1;
}

/**
 * mock_scandir_eperm - Mock scandir that fails with EPERM
 * @dirp: Directory path (ignored)
 * @namelist: Output name list (ignored)
 * @filter: Filter function (ignored)
 * @compar: Comparison function (ignored)
 *
 * Simulates permission denied condition.
 *
 * Return: -1 with errno set to EPERM
 */
static int mock_scandir_eperm(const char *dirp, struct dirent ***namelist,
			       int (*filter)(const struct dirent *),
			       int (*compar)(const struct dirent **,
					     const struct dirent **))
{
	(void)dirp;
	(void)namelist;
	(void)filter;
	(void)compar;
	errno = EPERM;
	return -1;
}

/**
 * mock_scandir_zero_files - Mock scandir for empty directory
 * @dirp: Directory path (ignored)
 * @namelist: Output name list (set to NULL)
 * @filter: Filter function (ignored)
 * @compar: Comparison function (ignored)
 *
 * Simulates empty directory (no entries).
 *
 * Return: 0 with namelist set to NULL
 */
static int mock_scandir_zero_files(const char *dirp, struct dirent ***namelist,
				    int (*filter)(const struct dirent *),
				    int (*compar)(const struct dirent **,
						  const struct dirent **))
{
	(void)dirp;
	(void)filter;
	(void)compar;
	*namelist = NULL;
	return 0;
}

#pragma GCC diagnostic pop
#endif /* TEST_HELPER_MOCK_FILE_H */
