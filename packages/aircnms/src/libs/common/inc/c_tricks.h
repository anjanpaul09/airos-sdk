
#ifndef C_TRICKS_H_INCLUDED
#define C_TRICKS_H_INCLUDED

/*
 * ===========================================================================
 *  Macros for counting __VA_ARGS__ arguments and returning the last argument
 *  of a list
 *
 *  VA_LAST(a, b, c, d, e, f) expands to f
 *  VA_COUNT(a, b, c, d, e, f) expands to 6
 *
 *  At most 16 arguments are supported. If you wish to increase this number
 *  you must extend the list in the VA_COUNT and __VA_COUNT macros and implement
 *  the corresponding VA_IDX_NN functions.
 *
 * ===========================================================================
 */
#define __VA_COUNT(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, N, ...) N
#define VA_COUNT(...) __VA_COUNT(dummy, ##__VA_ARGS__, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define CONCAT(a, b)   a ## b

#define VA_IDX(N, ...)  CONCAT(VA_IDX_, N)(__VA_ARGS__)

#define VA_IDX_0(x)
#define VA_IDX_1(_1, ...)   _1
#define VA_IDX_2(_1, ...)   VA_IDX_1(__VA_ARGS__)
#define VA_IDX_3(_1, ...)   VA_IDX_2(__VA_ARGS__)
#define VA_IDX_4(_1, ...)   VA_IDX_3(__VA_ARGS__)
#define VA_IDX_5(_1, ...)   VA_IDX_4(__VA_ARGS__)
#define VA_IDX_6(_1, ...)   VA_IDX_5(__VA_ARGS__)
#define VA_IDX_7(_1, ...)   VA_IDX_6(__VA_ARGS__)
#define VA_IDX_8(_1, ...)   VA_IDX_7(__VA_ARGS__)
#define VA_IDX_9(_1, ...)   VA_IDX_8(__VA_ARGS__)
#define VA_IDX_10(_1, ...)  VA_IDX_9(__VA_ARGS__)
#define VA_IDX_11(_1, ...)  VA_IDX_10(__VA_ARGS__)
#define VA_IDX_12(_1, ...)  VA_IDX_11(__VA_ARGS__)
#define VA_IDX_13(_1, ...)  VA_IDX_12(__VA_ARGS__)
#define VA_IDX_14(_1, ...)  VA_IDX_13(__VA_ARGS__)
#define VA_IDX_15(_1, ...)  VA_IDX_14(__VA_ARGS__)
#define VA_IDX_16(_1, ...)  VA_IDX_15(__VA_ARGS__)

#define VA_LAST(...) VA_IDX(VA_COUNT(__VA_ARGS__), __VA_ARGS__)

#endif /* C_TRICKS_H_INCLUDED */
