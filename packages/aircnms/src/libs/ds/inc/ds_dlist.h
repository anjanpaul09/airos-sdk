#ifndef DS_DLIST_H_INCLUDED
#define DS_DLIST_H_INCLUDED

#include <stddef.h>
#include "ds.h"

/*
 * ============================================================
 *  Macros
 * ============================================================
 */

/** Static initialization */
#define DS_DLIST_INIT(type, elem)       \
{                                       \
    .od_cof  = offsetof(type, elem),    \
    .od_head = NULL,                    \
    .od_tail = NULL,                    \
    .od_ndel = 0,                       \
}

/** Run-time initialization */
#define ds_dlist_init(list, type, elem) __ds_dlist_init(list, offsetof(type, elem))

#define ds_dlist_foreach(list, p)       \
    for (p = ds_dlist_head(list); p != NULL; p = ds_dlist_next(list, p))

#define ds_dlist_foreach_reverse(list, p)       \
    for (p = ds_dlist_tail(list); p != NULL; p = ds_dlist_prev(list, p))

#define ds_dlist_iforeach ds_dlist_foreach_iter

#define ds_dlist_foreach_iter(list, p, iter) \
    for (p = ds_dlist_ifirst(&iter, list); p != NULL; p = ds_dlist_inext(&iter))

#define ds_dlist_foreach_iter_err(list, p, iter) \
    for (p = ds_dlist_ifirst(&iter, list); p != NULL; p = ds_dlist_inext_err(&iter))

/*
 * Same as ds_list_foreach() except it is safe to remove the _current_ element
 * from the list. This foreach statement requires an additional parameter for
 * temporary storage.
 *
 * Note: Use with care, this macro will not detect any iteration errors
 * (for example, if the next element is removed somewhere inside the foreach
 * loop)
 */
#define ds_dlist_foreach_safe(list, elem, tmp) \
    for ((elem) = ds_dlist_head(list),  (tmp) = ((elem) != NULL) ? ds_dlist_next((list), (elem)) : NULL; \
                (elem) != NULL; \
                (elem) = (tmp), (tmp) = ((elem) != NULL) ? ds_dlist_next((list), (elem)) : NULL)

/*
 * ============================================================
 *  Typedefs
 * ============================================================
 */
typedef struct ds_dlist             ds_dlist_t;
typedef struct ds_dlist_node        ds_dlist_node_t;
typedef struct ds_dlist_iter        ds_dlist_iter_t;

/*
 * ============================================================
 *  Structs
 * ============================================================
 */
struct ds_dlist
{
    size_t                          od_cof;
    ds_dlist_node_t*                od_head;
    ds_dlist_node_t*                od_tail;
    uint32_t                        od_ndel;
};

struct ds_dlist_node
{
    ds_dlist_node_t*                odn_prev;
    ds_dlist_node_t*                odn_next;
};

struct ds_dlist_iter
{
    ds_dlist_t                      *odi_list;
    ds_dlist_node_t                 *odi_curr;
    ds_dlist_node_t                 *odi_next;
    uint32_t                        odi_ndel;
};

/*
 * ===========================================================================
 *  Public API
 * ===========================================================================
 */

static inline bool   ds_dlist_is_empty(ds_dlist_t *list);
static inline void  *ds_dlist_next(ds_dlist_t *list, void *data);
static inline void  *ds_dlist_prev(ds_dlist_t *list, void *data);
static inline void  *ds_dlist_head(ds_dlist_t *list);
static inline void  *ds_dlist_tail(ds_dlist_t *list);
static inline void   ds_dlist_insert_head(ds_dlist_t* list, void *data);
static inline void   ds_dlist_insert_tail(ds_dlist_t* list, void *data);
static inline void   ds_dlist_insert_after(ds_dlist_t *list, void *after, void *data);
static inline void   ds_dlist_insert_before(ds_dlist_t *list, void *before, void *data);
static inline void   ds_dlist_remove(ds_dlist_t* list, void *data);
static inline void  *ds_dlist_remove_head(ds_dlist_t* list);
static inline void  *ds_dlist_remove_tail(ds_dlist_t* list);
static inline void  *ds_dlist_remove_after(ds_dlist_t *list, void *after);
static inline void  *ds_dlist_remove_before(ds_dlist_t *list, void *before);

/*
 * ===========================================================================
 *  Iterator API
 * ===========================================================================
 */
static inline void  *ds_dlist_ifirst(ds_dlist_iter_t* iter, ds_dlist_t* list);
static inline void  *ds_dlist_iinsert_err(ds_dlist_iter_t *iter, void *data);
static inline void  *ds_dlist_inext_err(ds_dlist_iter_t *iter);
static inline void  *ds_dlist_iremove_err(ds_dlist_iter_t *iter);
static inline void  *ds_dlist_iinsert(ds_dlist_iter_t *iter, void *data);
static inline void  *ds_dlist_inext(ds_dlist_iter_t *iter);
static inline void  *ds_dlist_iremove(ds_dlist_iter_t* iter);

#include "../src/ds_dlist.c.h"

extern int ds_dlist_check(ds_dlist_t* list);

#endif /* DS_DLIST_H_INCLUDED */
