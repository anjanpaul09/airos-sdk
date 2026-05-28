#include "stamonitord_history_internal.h"
#include "stamonitord_history_service.h"
#include "log.h"

/* ------------------------------------------------------------------------- */
/* nDPI compatibility + lightweight service helpers                          */
/* ------------------------------------------------------------------------- */

bool init_ndpi(app_t *app)
{
    (void)app;

    LOG(INFO, "nDPI disabled");

    return true;
}

void cleanup_ndpi(app_t *app)
{
    (void)app;
}

void ndpi_process_flow_packet(flow_t *flow,
                              const uint8_t *payload,
                              size_t payload_len,
                              uint64_t ts_ms)
{
    (void)flow;
    (void)payload;
    (void)payload_len;
    (void)ts_ms;
}

const char *service_from_flow_and_domain(flow_t *flow, const char *domain)
{
    (void)flow;

    return service_from_domain(domain);
}

typedef struct {
    const char *service;
    const char *domain;
} service_domain_t;

static const service_domain_t SERVICE_DOMAINS[] = {
    {"DNS", "dns"},
    {"YouTube", "youtube.com"},
    {"Netflix", "netflix.com"},
    {"PrimeVideo", "amazonvideo.com"},
    {"DisneyPlusHotstar", "hotstar.com"},
    {"DisneyPlus", "disneyplus.com"},
    {"Spotify", "spotify.com"},
    {"JioHotstar", "jiohotstar.com"},
    {"SonyLIV", "sonyliv.com"},
    {"ZEE5", "zee5.com"},
    {"JioCinema", "jiocinema.com"},
    {"MXPlayer", "mxplayer.in"},
    {"WhatsApp", "whatsapp.com"},
    {"Facebook", "facebook.com"},
    {"Instagram", "instagram.com"},
    {"TikTok", "tiktok.com"},
    {"LinkedIn", "linkedin.com"},
    {"Twitter", "x.com"},
    {"Snapchat", "snapchat.com"},
    {"Reddit", "reddit.com"},
    {"Discord", "discord.com"},
    {"Telegram", "telegram.org"},
    {"Pinterest", "pinterest.com"},
    {"Quora", "quora.com"},
    {"Zoom", "zoom.us"},
    {"MicrosoftTeams", "teams.microsoft.com"},
    {"Skype", "skype.com"},
    {"Slack", "slack.com"},
    {"Notion", "notion.so"},
    {"Dropbox", "dropbox.com"},
    {"Box", "box.com"},
    {"Microsoft", "microsoft.com"},
    {"Google", "google.com"},
    {"Firebase", "firebase.google.com"},
    {"Apple", "apple.com"},
    {"AmazonAWS", "aws.amazon.com"},
    {"AmazonCloudFront", "cloudfront.net"},
    {"Cloudflare", "cloudflare.com"},
    {"Akamai", "akamai.com"},
    {"Fastly", "fastly.com"},
    {"GitHub", "github.com"},
    {"GitLab", "gitlab.com"},
    {"Bitbucket", "bitbucket.org"},
    {"Amazon", "amazon.com"},
    {"Flipkart", "flipkart.com"},
    {"Myntra", "myntra.com"},
    {"Meesho", "meesho.com"},
    {"AJIO", "ajio.com"},
    {"Nykaa", "nykaa.com"},
    {"BookMyShow", "bookmyshow.com"},
    {"Swiggy", "swiggy.com"},
    {"Zomato", "zomato.com"},
    {"Blinkit", "blinkit.com"},
    {"BigBasket", "bigbasket.com"},
    {"Uber", "uber.com"},
    {"Ola", "olacabs.com"},
    {"MakeMyTrip", "makemytrip.com"},
    {"Goibibo", "goibibo.com"},
    {"IRCTC", "irctc.co.in"},
    {"PhonePe", "phonepe.com"},
    {"Paytm", "paytm.com"},
    {"Razorpay", "razorpay.com"},
    {"Cashfree", "cashfree.com"},
    {"Stripe", "stripe.com"},
    {"PayPal", "paypal.com"},
    {"BillDesk", "billdesk.com"},
    {"HDFCBank", "hdfcbank.com"},
    {"ICICIBank", "icicibank.com"},
    {"AxisBank", "axisbank.com"},
    {"SBI", "sbi.co.in"},
    {"PUBG", "pubg.com"},
    {"Krafton", "krafton.com"},
    {"Roblox", "roblox.com"},
    {"Minecraft", "minecraft.net"},
    {"EpicGames", "epicgames.com"},
    {"Steam", "steampowered.com"},
    {"RiotGames", "riotgames.com"},
    {"EA", "ea.com"},
    {"PlayStation", "playstation.com"},
    {"Xbox", "xbox.com"},
    {"Vivo", "vivoglobal.com"},
    {"HeyTap", "heytapmobile.com"},
    {"OPPO", "oppo.com"},
    {"OnePlus", "oneplus.com"},
    {"Xiaomi", "mi.com"},
    {"Samsung", "samsung.com"},
    {"Huawei", "huawei.com"},
    {"Lenovo", "lenovo.com"},
    {"Motorola", "motorola.com"},
    {"GoogleAds", "ads.google.com"},
    {"Criteo", "criteo.com"},
    {"NewRelic", "newrelic.com"},
    {"Sentry", "sentry.io"},
    {"GoogleAnalytics", "analytics.google.com"},
    {"AppsFlyer", "appsflyer.com"},
    {"Branch", "branch.io"},
    {"MoEngage", "moengage.com"},
    {"CleverTap", "clevertap.com"},
    {"SponsorBlock", "sponsor.ajay.app"},
};

static const char *canonical_domain_for_service(const char *service)
{
    if (!service || !service[0])
        return NULL;

    for (size_t i = 0; i < sizeof(SERVICE_DOMAINS) / sizeof(SERVICE_DOMAINS[0]); i++) {
        if (!strcmp(service, SERVICE_DOMAINS[i].service))
            return SERVICE_DOMAINS[i].domain;
    }

    return NULL;
}

const char *domain_from_service_if_unknown(const char *domain,
                                           const char *service)
{
    if (domain && strcmp(domain, "unknown"))
        return domain;

    if (!service || !service[0] || !strcmp(service, "Unknown"))
        return domain ? domain : "unknown";

    const char *canonical_domain = canonical_domain_for_service(service);
    if (canonical_domain)
        return canonical_domain;

    return domain ? domain : "unknown";
}

bool str_contains_ci(const char *haystack, const char *needle)
{
    return haystack && needle && strcasestr(haystack, needle);
}

const char *strip_service_prefix(const char *s)
{
    static const char *prefixes[] = {"TLS.", "QUIC.", "HTTP.", "HTTPS."};

    if (!s)
        return NULL;

    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        size_t len = strlen(prefixes[i]);
        if (!strncasecmp(s, prefixes[i], len))
            return s + len;
    }

    return s;
}

bool ndpi_label_is_generic(const char *label)
{
    if (!label || !label[0])
        return true;

    if (!strcmp(label, "Unknown"))
        return true;

    if (!strcmp(label, "disabled"))
        return true;

    return false;
}

const char *normalized_history_service(const char *service,
                                       const char *ndpi_protocol,
                                       const char *domain)
{
    const char *domain_service = service_from_domain(domain);

    if (str_contains_ci(service, "dns") ||
        str_contains_ci(ndpi_protocol, "dns") ||
        (domain && !strcmp(domain, "dns"))) {
        return "DNS";
    }

    if (domain_service && strcmp(domain_service, "Unknown"))
        return domain_service;

    if (service && service[0] && !ndpi_label_is_generic(service))
        return strip_service_prefix(service);

    if (domain && domain[0] &&
        strcmp(domain, "unknown") &&
        strcmp(domain, "dns")) {
        return domain;
    }

    return "Unknown";
}

const char *history_domain_for_service(const char *service,
                                       const char *fallback_domain)
{
    if (!service || !service[0])
        return fallback_domain ? fallback_domain : "unknown";

    const char *canonical_domain = canonical_domain_for_service(service);
    if (canonical_domain)
        return canonical_domain;

    if (fallback_domain && fallback_domain[0] && strcmp(fallback_domain, "unknown"))
        return fallback_domain;

    if (!strcmp(service, "Unknown"))
        return "unknown";

    return service;
}
