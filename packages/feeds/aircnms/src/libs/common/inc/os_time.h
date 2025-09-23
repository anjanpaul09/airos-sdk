#ifndef OS_TIME_H_INCLUDED
#define OS_TIME_H_INCLUDED

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#include <float.h>

/**
 * Ticks are arbitrary units of time, monotonically increasing since an undefined
 * point in time. There are TICKS_HZ ticks in one second.
 */

// shift: 1 << 10 = 1024
#define TICKS_SHIFT 10

#ifdef TICKS_SHIFT
/** Define how many ticks there are in 1 second */
#define TICKS_HZ           ((int64_t)1 << TICKS_SHIFT)
/** ticks multiply */
#define TICKS_X(X)         ((int64_t)(X) << TICKS_SHIFT)
/** ticks divide */
#define TICKS_DIV(X)       ((int64_t)(X) >> TICKS_SHIFT)
/** ticks modulo */
#define TICKS_MOD(X)       ((int64_t)(X) & (TICKS_HZ - 1))
#else
#define TICKS_HZ           ((int64_t)1000)
#define TICKS_X(X)         ((int64_t)(X) * TICKS_HZ)
#define TICKS_DIV(X)       ((int64_t)(X) / TICKS_HZ)
#define TICKS_MOD(X)       ((int64_t)(X) % TICKS_HZ)
#endif

/** Convert seconds to ticks */
#define TICKS_S(sec)       TICKS_X(sec)
/** Convert milliseconds to ticks */
#define TICKS_MS(ms)       (TICKS_X(ms) / 1000LL)
/** Convert microseconds to ticks */
#define TICKS_US(us)       (TICKS_X(us) / 1000000LL)
/** Convert nanoseconds to ticks */
#define TICKS_NS(ns)       (TICKS_X(ns) / 1000000000LL)

/** Convert ticks to seconds */
#define TICKS_TO_S(ticks)  TICKS_DIV(ticks)
/** Convert ticks to milliseconds */
#define TICKS_TO_MS(ticks) TICKS_DIV((ticks) * 1000LL)
/** Convert ticks to microseconds */
#define TICKS_TO_US(ticks) TICKS_DIV((ticks) * 1000000LL)
/** Convert ticks to nanoseconds */
#define TICKS_TO_NS(ticks) TICKS_DIV((ticks) * 1000000000LL)

/** The format used for converting to/from ISO 8601 date format */
#define TIME_ISO8601_STRFMT  "%FT%TZ"

/** Maximum size of string that can be returned by acla_time_to_str() (ex. 2015-03-11T09:52:05+1000) */
#define TIME_STR_SZ        25

typedef int64_t     ticks_t;

/*
 *  Functions related to ticks
 */
extern int64_t      clock_ticks(clockid_t clk);
extern int64_t      ticks(void);
extern void         ticks_to_timespec(int64_t t, struct timespec *ts);
extern int64_t      timespec_to_ticks(struct timespec *ts);
extern void         ticks_to_timeval(int64_t t, struct timeval *tv);
extern int64_t      timeval_to_ticks(struct timeval *ts);

/*
 *  general time related definitions
 */
extern time_t       time_monotonic(void);
extern time_t       time_real(void);
extern bool         time_to_str(time_t from, char *strz, size_t strsz);
extern bool         time_from_str(time_t *to, char *str);
extern int64_t      clock_real_ms();
extern int64_t      clock_mono_ms();
extern int64_t      clock_mono_usec();
extern double       clock_mono_double();

// monotonic clock in ev_tstamp (double) format
extern double       ev_clock(void);

// Sleep for tts amount of seconds, tts can be fractional
extern double       clock_sleep(double tts);

/**
 * Return true once the timeout @p to has expired. After expiration, subsequent
 * calls to this functions will return false until Val is reset and the timer expires
 * again.
 *
 * Val can be initialized by calling clock_tonce() with a to value of 0.0 or setting it to 0.0.
 *
 * The timer starts ticking when to is >0.0.
 *
 * Usage: Report something after 30 seconds.
 *
 * double val;
 *
 * while (true)
 * {
 *      if (clock_tonce(&val, 30.0))
 *      {
 *          printf("Something has happened. This will be reported once.\n");
 *      }
 *      sleep(1);
 * }
 */
static inline bool clock_tonce(double *val, double to)
{
    if (to <= 0.0)
    {
        *val = 0.0;
        return false;
    }

    if (*val <= 0.0) *val = clock_mono_double() + to;

    if (clock_mono_double() < *val) return false;

    *val = DBL_MAX;

    return true;
}

/**
 * Return true once after the timeout @p to has expired. After expiration, the
 * Val is reset and the timer starts ticking again.
 *
 * Val can be initialized by calling clock_trepeat() with a to value
 * of 0.0, or setting it to 0.0.
 *
 * The timer starts ticking when to is >0.0.
 *
 * Usage: Report something every 30 seconds.
 *
 * double val;
 *
 * while (true)
 * {
 *      if (clock_trepeat(&val, 30.0))
 *      {
 *          printf("Something!\n");
 *      }
 *
 *      sleep(1);
 * }
 *
 */
static inline bool  clock_trepeat(double *val, double to)
{
    double cur = clock_mono_double();

    if (to <= 0.0)
    {
        *val = 0.0;
        return false;
    }

    if (*val <= 0.0) *val = cur + to;

    if (cur < *val) return false;

    *val = cur + to;

    return true;
}

#endif /* OS_TIME_H_INCLUDED */
