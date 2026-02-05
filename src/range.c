/**
 * range.c - Subordinate ID range calculation
 */

/* clang-format off */
#include "autoconf.h"
#include "static-subid.h"
#include "syscall_ops.h"
/* clang-format on */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/*
 * calc_subid_range - Calculate subordinate ID range for a user
 * @uid: User ID
 * @uid_min: Minimum UID from configuration
 * @subid_cfg: Subordinate ID configuration (min, max, count)
 * @allow_wrap: Allow range calculation to wrap around using modulo
 * @start_out: Output start of range
 *
 * Calculates deterministic subordinate ID ranges based on user UID.
 *
 * BASE FORMULA:
 *   logical_offset = (uid - uid_min) * count
 *   start_id       = min_val + logical_offset
 *   end_id         = start_id + count - 1
 *
 * The assigned range is always a single contiguous block of size `count`.
 *
 * Two operating modes exist:
 *
 * 1. STRICT MODE (allow_wrap = false)
 *    - Any arithmetic overflow is a hard error
 *    - Ranges must fit entirely within [min_val, max_val]
 *    - Guarantees non-overlapping, monotonic allocation
 *    - Suitable for production standard environments
 *
 * 2. WRAP MODE (allow_wrap = true)
 *
 *    WARNING: SECURITY RISK!
 *    WARNING: MAY CAUSE RANGE OVERLAPS!
 *    WARNING: MAY CAUSE CONTAINER ESCAPES!
 *
 *    - The subordinate ID space is treated as a ring:
 *        [min_val, max_val]
 *    - Any overflow or excess is handled via modulo arithmetic
 *    - Logical overflow is *intentional* and not an error
 *    - Intended ONLY for development, testing, or constrained labs
 *
 * In wrap mode, arithmetic overflow is not detected — it is embraced
 * and normalized using modulo over the configured ID space.
 */

int calc_subid_range(uint32_t uid, uint32_t uid_min,
                     const subid_config_t *subid_cfg, bool allow_wrap,
                     uint32_t *start_out) {
  if (!subid_cfg) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: subid_cfg is NULL\n", PROJECT_NAME);
    return -1;
  }
  if (!start_out) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: start_out is NULL\n", PROJECT_NAME);
    return -1;
  }

  /* Set a nonsense value in start_out should things go wrong we have a value
   * that will get rejected later on */
  *start_out = UINT32_MAX_VAL;

  /* Basic sanity checks */
  if (uid < uid_min) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: UID %u less than uid_min %u\n",
                  PROJECT_NAME, uid, uid_min);
    return -1;
  }

  uint32_t count = subid_cfg->count_val;

  /* Don't allocate a range of 0 entries, that makes no sense */
  if (count == 0) {
    errno = EINVAL;
    (void)fprintf(stderr, "%s: error: count_val is zero\n", PROJECT_NAME);
    return -1;
  }

  uint32_t min_val = subid_cfg->min_val;
  uint32_t max_val = subid_cfg->max_val;
  uint32_t start_id = subid_cfg->min_val;
  uint32_t uid_offset = uid - uid_min;

  /*
   * Total available subordinate ID space.
   * Linear in strict mode, circular in wrap mode.
   */
  uint32_t space = max_val - min_val + 1;

  /*
   * POLICY CHECK:
   * If a contiguous range of size `count` cannot fit anywhere
   * in the configured ID space, the only deterministic choice
   * is to give up since we are misconfigured.
   */
  if (count > space) {
    errno = ERANGE;
    (void)fprintf(stderr,
                  "%s: error: calculating range for UID %u %s=%u %s=%u %s=%u "
                  "not enough space for any subid in range\n",
                  PROJECT_NAME, uid, subid_cfg->key_min, subid_cfg->min_val,
                  subid_cfg->key_max, subid_cfg->max_val, subid_cfg->key_count,
                  subid_cfg->count_val);

    return -1;
  }

  /*
   * STRICT MODE
   *
   * All arithmetic must fit cleanly in uint32_t and
   * the resulting range must be fully contained.
   */
  if (!allow_wrap) {
    uint32_t product = 0;
    uint32_t end_id = 0;

    if (__builtin_mul_overflow(uid_offset, count, &product)) {
      errno = ERANGE;
      (void)fprintf(stderr,
                    "%s: error: overflow calculating range for UID %u\n",
                    PROJECT_NAME, uid);
      return -1;
    }

    if (__builtin_add_overflow(min_val, product, &start_id)) {
      errno = ERANGE;
      (void)fprintf(stderr,
                    "%s: error: overflow calculating range for UID %u\n",
                    PROJECT_NAME, uid);
      return -1;
    }

    if (__builtin_add_overflow(start_id, count - 1, &end_id)) {
      errno = ERANGE;
      (void)fprintf(stderr,
                    "%s: error: overflow calculating range for UID %u\n",
                    PROJECT_NAME, uid);
      return -1;
    }

    if (end_id > max_val) {
      errno = ERANGE;
      (void)fprintf(stderr, "%s: error: range for UID %u exceeds max_val %u\n",
                    PROJECT_NAME, uid, max_val);
      return -1;
    }

    *start_out = start_id;
    return 0;
  }

  /*
   * WRAP MODE
   *
   * Treat the ID space as a ring and normalize the logical
   * offset using modulo arithmetic.
   *
   * Overflow is not detected — it is expected and desired.
   */
  uint64_t logical_offset = (uint64_t)uid_offset * (uint64_t)count;

  start_id = min_val + (uint32_t)(logical_offset % space);

  *start_out = start_id;
  return 0;
}
