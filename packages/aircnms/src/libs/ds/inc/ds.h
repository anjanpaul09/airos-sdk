#ifndef DS_H_INCLUDED
#define DS_H_INCLUDED

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define DS_ITER_ERROR ((void *)0x1)

/**
 * Similar to the container_of() macro used in the Linux kernel.
 *
 * Given the member address, this function returns the pointer to the base structure.
 *
 * For example:
 *
 *  struct foo
 *  {
 *      int a;
 *      int x;
 *      int b;
 *  };
 *
 * If a function is passed the pointer to variable @p x, it can return the pointer
 * to the containing @p foo structure by using CONTAINER_OF(x_ptr, struct foo, x);
 */
#define TYPE_CHECK(a, type, member) \
    (true ? a : &((type *)NULL)->member)

#ifndef CONTAINER_OF
#define CONTAINER_OF(ptr, type, member) \
    ((type *)((uintptr_t)TYPE_CHECK(ptr, type, member) - offsetof(type, member)))
#endif 

/** Calculate container address from node */
#define NODE_TO_CONT(node, offset)    ( (node) == NULL ? NULL : (void *)((char *)(node) - (offset)) )
/** Calculate node address from container */
#define CONT_TO_NODE(cont, offset)    ( (void *)((char *)(cont) + (offset)) )

/**
 * Key compare function; this function should return a negative number
 * if a < b; 0 if a == b or a positive number if a > b
 */
typedef int ds_key_cmp_t(const void *a, const void *b);

/** Integer comparator */
extern ds_key_cmp_t ds_int_cmp;
/** String comparator */
extern ds_key_cmp_t ds_str_cmp;
/** Pointer comparison (the key value is stored directly) */
extern ds_key_cmp_t ds_void_cmp;
/** Unsigned 32-bit integer comparator */
extern ds_key_cmp_t ds_u32_cmp;

#endif /* DS_H_INCLUDED */
