
#define    TAILQ_ENTRY(type)                                           \
struct {                                                               \
    struct type *tqe_next;    /* next element */                       \
    struct type **tqe_prev;    /* address of previous next element */  \
}

#define TAILQ_FIRST(head)   ((head)->tqh_first)

#define TAILQ_LAST(head, headname)                    \
        (*(((struct headname *)((head)->tqh_last))->tqh_last))

#define    TAILQ_FOREACH(var, head, field)                     \
        for ((var) = TAILQ_FIRST((head));                      \
                        (var);                                 \
                        (var) = TAILQ_NEXT((var), field))

#define    TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)

#define    TAILQ_INIT(head) do {                               \
            TAILQ_FIRST((head)) = NULL;                        \
            (head)->tqh_last = &TAILQ_FIRST((head));           \
} while (0)

#define    TAILQ_HEAD(name, type)                              \
struct name {                                                  \
    struct type *tqh_first;    /* first element */             \
    struct type **tqh_last;    /* addr of last next element */ \
}


#define    TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)

#define TAILQ_INSERT_HEAD(head, elm, field) do {                         \
        if ((TAILQ_NEXT((elm), field) = TAILQ_FIRST((head))) != NULL)    \
            TAILQ_FIRST((head))->field.tqe_prev =                        \
                                           &TAILQ_NEXT((elm), field);    \
        else                                                             \
            (head)->tqh_last = &TAILQ_NEXT((elm), field);                \
            TAILQ_FIRST((head)) = (elm);                                 \
            (elm)->field.tqe_prev = &TAILQ_FIRST((head));                \
} while (0)


#define TAILQ_INSERT_TAIL(head, elm, field) do {               \
    TAILQ_NEXT((elm), field) = NULL;                           \
    (elm)->field.tqe_prev = (head)->tqh_last;                  \
    *(head)->tqh_last = (elm);                                 \
    (head)->tqh_last = &TAILQ_NEXT((elm), field);              \
} while (0)

#define TAILQ_REMOVE(head, elm, field) do {                    \
    if ((TAILQ_NEXT((elm), field)) != NULL)                    \
        TAILQ_NEXT((elm), field)->field.tqe_prev =             \
                                  (elm)->field.tqe_prev;       \
    else {                                                     \
        (head)->tqh_last = (elm)->field.tqe_prev;              \
    }                                \
        *(elm)->field.tqe_prev = TAILQ_NEXT((elm), field);     \
} while (0)


#define    TAILQ_EMPTY(head)    ((head)->tqh_first == NULL)

#define TAILQ_CONCAT(head1, head2, field)  do {                  \
    if (!TAILQ_EMPTY(head2)) {\
        *(head1)->tqh_last = (head2)->tqh_first;                 \
        (head2)->tqh_first->field.tqe_prev = (head1)->tqh_last;  \
        (head1)->tqh_last  = (head2)->tqh_last;                  \
        TAILQ_INIT((head2));                                     \
    }                                                            \
} while (0)

#define    TAILQ_FOREACH_SAFE(var, head, field, tvar)            \
    for ((var) = TAILQ_FIRST((head));                            \
        (var) && ((tvar) = TAILQ_NEXT((var), field), 1);         \
        (var) = (tvar))

/*
 * List declarations.
 */
#define    ATH_LIST_HEAD(name, type)                    \
struct name {                                \
    struct type *lh_first;    /* first element */            \
}

#ifndef LIST_HEAD
#define LIST_HEAD ATH_LIST_HEAD
#endif

#define    LIST_HEAD_INITIALIZER(head)                    \
    { NULL }

#define    LIST_ENTRY(type)                        \
struct {                                \
    struct type *le_next;    /* next element */            \
    struct type **le_prev;    /* address of previous next element */    \
}

/*
 * List functions.
 */

#define    LIST_EMPTY(head)    ((head)->lh_first == NULL)

#define    LIST_FIRST(head)    ((head)->lh_first)

#define    LIST_FOREACH(var, head, field)                    \
    for ((var) = LIST_FIRST((head));                \
        (var);                            \
        (var) = LIST_NEXT((var), field))

#define    LIST_FOREACH_SAFE(var, head, field, tvar)            \
    for ((var) = LIST_FIRST((head));                \
        (var) && ((tvar) = LIST_NEXT((var), field), 1);        \
        (var) = (tvar))

#define    LIST_INIT(head) do {                        \
    LIST_FIRST((head)) = NULL;                    \
} while (0)

#define    LIST_INSERT_AFTER(listelm, elm, field) do {            \
    if ((LIST_NEXT((elm), field) = LIST_NEXT((listelm), field)) != NULL)\
        LIST_NEXT((listelm), field)->field.le_prev =        \
            &LIST_NEXT((elm), field);                \
    LIST_NEXT((listelm), field) = (elm);                \
    (elm)->field.le_prev = &LIST_NEXT((listelm), field);        \
} while (0)

#define    LIST_INSERT_BEFORE(listelm, elm, field) do {            \
    (elm)->field.le_prev = (listelm)->field.le_prev;        \
    LIST_NEXT((elm), field) = (listelm);                \
    *(listelm)->field.le_prev = (elm);                \
    (listelm)->field.le_prev = &LIST_NEXT((elm), field);        \
} while (0)

#define    LIST_INSERT_HEAD(head, elm, field) do {                \
    if ((LIST_NEXT((elm), field) = LIST_FIRST((head))) != NULL)    \
        LIST_FIRST((head))->field.le_prev = &LIST_NEXT((elm), field);\
    LIST_FIRST((head)) = (elm);                    \
    (elm)->field.le_prev = &LIST_FIRST((head));            \
} while (0)

#define    LIST_NEXT(elm, field)    ((elm)->field.le_next)

#define    LIST_REMOVE(elm, field) do {                    \
    if (LIST_NEXT((elm), field) != NULL)                \
        LIST_NEXT((elm), field)->field.le_prev =         \
            (elm)->field.le_prev;                \
    *(elm)->field.le_prev = LIST_NEXT((elm), field);        \
} while (0)









