#define LL_STR_SZ   32

/*
 * JSON parsing functions
 */
#define PJS_CONFIG_FMT                          \
    PJS(config  ,                               \
        PJS_STRING_Q(loglevel, LL_STR_SZ)       \
        PJS_STRING_QA(managers, 64, 16)         \
        PJS_STRING_Q(controller, LL_STR_SZ)     \
        PJS_STRING_Q(port, LL_STR_SZ)           \
        PJS_STRING_Q(rlog_host, 128)            \
        PJS_INT_Q(rlog_port)                    \
        PJS_STRING_Q(rlog_topic, 128)           \
    )

#define PJS_GEN_TABLE PJS_CONFIG_FMT
