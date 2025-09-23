#ifndef OSA_ASSERT_H_INCLUDED
#define OSA_ASSERT_H_INCLUDED

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>

#define ASSERT(cond, fmt...)                                            \
if (!(cond))                                                            \
{                                                                       \
   osa_assert_dump(#cond, __FUNCTION__, __FILE__, __LINE__, fmt);       \
}

extern _Noreturn void osa_assert_dump(
        const char *cond,
        const char *func,
        const char *file,
        const int line,
        const char *fmt,
        ...);

#endif /* OSA_ASSERT_H_INCLUDED */
