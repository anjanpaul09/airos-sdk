
// Return number of elements in array
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)       (sizeof(x) / sizeof(x[0]))
#endif /* ARRAY_SIZE */

typedef struct {
    const char *band;        // "2g", "5g" (OpenWrt band notation)
    const char *htmode;      // HT20, HT40, VHT80, HE80, etc.
    int bandwidth_mhz;       // Channel width in MHz
    const int *channels;     // List of supported PRIMARY channels
    int channel_count;       // Number of channels
} wifi_htmode_map_t;

// 2.4 GHz - 20 MHz channels
static const int channels_2g_20mhz[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};

// 2.4 GHz - 40 MHz channels (practical subset to avoid severe overlap)
static const int channels_2g_40mhz[] = {3, 11};

// 5 GHz - 20 MHz channels
static const int channels_5g_20mhz[] = {
    36, 40, 44, 48,                                      // U-NII-1
    52, 56, 60, 64,                                      // U-NII-2A (DFS)
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, // U-NII-2C (DFS)
    149, 153, 157, 161, 165                              // U-NII-3
};

// 5 GHz - 40 MHz primary channels
static const int channels_5g_40mhz[] = {
    36, 44,                     // U-NII-1
    52, 60,                     // U-NII-2A (DFS)
    100, 108, 116, 124, 132, 140, // U-NII-2C (DFS)
    149, 157                    // U-NII-3
};

// 5 GHz - 80 MHz primary channels
static const int channels_5g_80mhz[] = {
    36,                         // Covers 36-48
    52,                         // Covers 52-64 (DFS)
    100, 116, 132,              // Covers 100-112, 116-128, 132-144 (DFS)
    149                         // Covers 149-161
};

static const wifi_htmode_map_t wifi_htmode_table[] = {
    // 2.4 GHz Band
    {"2g", "HT20",  20, channels_2g_20mhz, ARRAY_SIZE(channels_2g_20mhz)},
    {"2g", "HT40",  40, channels_2g_40mhz, ARRAY_SIZE(channels_2g_40mhz)},
    {"2g", "HE20",  20, channels_2g_20mhz, ARRAY_SIZE(channels_2g_20mhz)},
    {"2g", "HE40",  40, channels_2g_40mhz, ARRAY_SIZE(channels_2g_40mhz)},

    // 5 GHz Band
    {"5g", "HT20",  20, channels_5g_20mhz, ARRAY_SIZE(channels_5g_20mhz)},
    {"5g", "HT40",  40, channels_5g_40mhz, ARRAY_SIZE(channels_5g_40mhz)},
    {"5g", "VHT20", 20, channels_5g_20mhz, ARRAY_SIZE(channels_5g_20mhz)},
    {"5g", "VHT40", 40, channels_5g_40mhz, ARRAY_SIZE(channels_5g_40mhz)},
    {"5g", "VHT80", 80, channels_5g_80mhz, ARRAY_SIZE(channels_5g_80mhz)},
    {"5g", "HE20",  20, channels_5g_20mhz, ARRAY_SIZE(channels_5g_20mhz)},
    {"5g", "HE40",  40, channels_5g_40mhz, ARRAY_SIZE(channels_5g_40mhz)},
    {"5g", "HE80",  80, channels_5g_80mhz, ARRAY_SIZE(channels_5g_80mhz)},
};
