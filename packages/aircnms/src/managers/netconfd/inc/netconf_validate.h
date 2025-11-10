
// Return number of elements in array
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)       (sizeof(x) / sizeof(x[0]))
#endif /* ARRAY_SIZE */

typedef struct {
    const char *band;        // "2.4GHz" or "5GHz"
    const char *htmode;      // "HT20", "HT40", "VHT80", "VHT160", "HE20", "HE40", etc.
    int bandwidth_mhz;       // Channel width in MHz
    const int *channels;     // List of supported channels
    int channel_count;       // Number of channels
} wifi_htmode_map_t;

// 2.4 GHz channels
static const int channels_24g[]  = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};

// 5 GHz channels
static const int channels_5g_20mhz[]  = {
    36, 40, 44, 48,             // U-NII-1
    52, 56, 60, 64,             // U-NII-2A (DFS)
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, // U-NII-2C (DFS)
    149, 153, 157, 161, 165     // U-NII-3
};

// 5 GHz 40 MHz (2-channel blocks)
static const int channels_5g_40mhz[] = {
    38, 46, 54, 62, 102, 110, 118, 126, 134, 151, 159
};

// 5 GHz 80 MHz (4-channel blocks)
static const int channels_5g_80mhz[] = {
    42, 58, 106, 122, 138, 155
};

// 5 GHz 160 MHz (8-channel blocks)
static const int channels_5g_160mhz[] = {
    50, 114
};

static const wifi_htmode_map_t wifi_htmode_table[] = {
    // 2.4 GHz Band
    {"2.4GHz", "HT20", 20, channels_24g,  ARRAY_SIZE(channels_24g)},
    {"2.4GHz", "HT40", 40, channels_24g,  ARRAY_SIZE(channels_24g)},
    {"2.4GHz", "HE20", 20, channels_24g,  ARRAY_SIZE(channels_24g)},
    {"2.4GHz", "HE40", 40, channels_24g,  ARRAY_SIZE(channels_24g)},

    // 5 GHz Band
    {"5GHz", "HT20", 20, channels_5g_20mhz, ARRAY_SIZE(channels_5g_20mhz)},
    {"5GHz", "HT40", 40, channels_5g_40mhz, ARRAY_SIZE(channels_5g_40mhz)},
    {"5GHz", "VHT80", 80, channels_5g_80mhz, ARRAY_SIZE(channels_5g_80mhz)},
    {"5GHz", "VHT160", 160, channels_5g_160mhz, ARRAY_SIZE(channels_5g_160mhz)},
    {"5GHz", "HE20", 20, channels_5g_20mhz, ARRAY_SIZE(channels_5g_20mhz)},
    {"5GHz", "HE40", 40, channels_5g_40mhz, ARRAY_SIZE(channels_5g_40mhz)},
    {"5GHz", "HE80", 80, channels_5g_80mhz, ARRAY_SIZE(channels_5g_80mhz)},
    {"5GHz", "HE160", 160, channels_5g_160mhz, ARRAY_SIZE(channels_5g_160mhz)},
};

