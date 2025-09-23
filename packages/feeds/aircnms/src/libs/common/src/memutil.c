#include <stddef.h>
#include <stdlib.h>

#include "memutil.h"

size_t mem_optimized_size(size_t req_size)
{
    size_t nsz = 16;
    size_t m = 16;

    /*
     * Grow buffer using a Fibonacci sequence where nsz and m are the starting
     * parameters. This creates a growth ratio of Phi (golden ratio), which,
     * according to some quick investigation, seems to be a better factor than 2.
     * For reference, it seems that Java and .NET use 1.5 for resizing their
     * arrays.
     */
    while (nsz < req_size)
    {
        nsz += m;
        m = nsz - m;
    }

    return nsz;
}

void* mem_append(void **base, void **cur, size_t sz)
{
    size_t nsz;
    size_t csz;

    if (*cur == NULL) *cur = *base;

    csz = *cur - *base;
    nsz = mem_optimized_size(csz);

    /* Resize the region if needed */
    if (nsz < (csz + sz) || csz == 0)
    {
        nsz = mem_optimized_size(csz + sz);

        /* Reallocate the buffer, adjust the 'base' and 'end' pointers */
        *base = realloc(*base, nsz);
        *cur = *base + csz;
    }

    *cur += sz;
    return *cur - sz;
}
