#include <stdlib.h>
#include <string.h>

static inline void* memutil_inline_malloc(
        size_t sz,
        const char *func,
        const char *file,
        const int line)
{
    void *ptr = malloc(sz);
    if (ptr == NULL)
    {
        osa_assert_dump("malloc() returned NULL", func, file, line, "Out of memory.");
    }

    return ptr;
}

static inline void* memutil_inline_calloc(
        size_t n,
        size_t sz,
        const char *func,
        const char *file,
        const int line)
{
    void *ptr = calloc(n, sz);
    if (ptr == NULL)
    {
        osa_assert_dump("calloc() returned NULL", func, file, line, "Out of memory.");
    }

    return ptr;
}

static inline void* memutil_inline_realloc(
        void *cptr,
        size_t sz,
        const char *func,
        const char *file,
        const int line)
{
    void *ptr = realloc(cptr, sz);
    if (ptr == NULL && sz > 0)
    {
        osa_assert_dump("realloc() returned NULL", func, file, line, "Out of memory.");
    }

    return ptr;
}

static inline void* memutil_inline_strdup(
        const char *str,
        const char *func,
        const char *file,
        const int line)
{
    char *ptr;

    if (str == NULL)
    {
        osa_assert_dump("strdup() ", func, file, line, "NULL parameter");
        return NULL;
    }

    ptr = strdup(str);
    if (ptr == NULL)
    {
        osa_assert_dump("strdup() returned NULL", func, file, line, "Out of memory.");
    }

    return ptr;
}

static inline void* memutil_inline_strndup(
        const char *str,
        size_t n,
        const char *func,
        const char *file,
        const int line)
{
    char *ptr;

    if (str == NULL)
    {
        osa_assert_dump("strndup() ", func, file, line, "NULL parameter");
        return NULL;
    }

    ptr = strndup(str, n);
    if (ptr == NULL)
    {
        osa_assert_dump("strndup() returned NULL", func, file, line, "Out of memory.");
    }
    return ptr;
}

static inline void* memutil_inline_memndup(
        const void *data,
        size_t n,
        const char *func,
        const char *file,
        const int line)
{
    char *ptr;

    if (data == NULL)
    {
        osa_assert_dump("memndup() ", func, file, line, "NULL parameter");
        return NULL;
    }

    ptr = malloc(n);
    if (ptr == NULL)
    {
        osa_assert_dump("memndup() returned NULL", func, file, line, "Out of memory.");
        return NULL;
    }

    return memcpy(ptr, data, n);
}
