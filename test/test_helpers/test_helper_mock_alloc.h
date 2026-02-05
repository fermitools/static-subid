/**
 * test_helper_mock_alloc.h - Memory allocation mock functions
 *
 * Provides mock implementations of memory allocation functions for testing
 * error handling paths. These mocks simulate allocation failures without
 * requiring actual memory exhaustion.
 *
 * This header is self-contained and can be included independently, but
 * including via test_helper_all.h is recommended for proper initialization.
 */

#ifndef TEST_HELPER_MOCK_ALLOC_H
#define TEST_HELPER_MOCK_ALLOC_H

#include <stddef.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

/* ============================================================================
 * Mock Implementations
 * ============================================================================
 */

/**
 * mock_calloc_null - Mock calloc that always fails
 * @nmemb: Number of elements (ignored)
 * @size: Size of each element (ignored)
 *
 * Simulates calloc() failure by returning NULL without attempting allocation.
 * Useful for testing OOM handling without exhausting system memory.
 *
 * Return: Always NULL
 */
static void *mock_calloc_null(size_t nmemb, size_t size) {
  (void)nmemb;
  (void)size;
  return NULL;
}

#pragma GCC diagnostic pop
#endif /* TEST_HELPER_MOCK_ALLOC_H */
