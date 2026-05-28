#include "stamonitord_history_service.h"

#include <stddef.h>
#include <string.h>

typedef struct {
    const char *pattern;
    const char *service;
} service_pattern_t;

static const service_pattern_t SERVICE_PATTERNS[] = {
    /* Video / streaming */
    {"youtube", "YouTube"},
    {"youtu.be", "YouTube"},
    {"youtubei", "YouTube"},
    {"googlevideo", "YouTube"},
    {"ytimg", "YouTube"},
    {"yt3.", "YouTube"},
    {"ggpht", "YouTube"},
    {"netflix", "Netflix"},
    {"nflxvideo", "Netflix"},
    {"amazonvideo", "PrimeVideo"},
    {"primevideo", "PrimeVideo"},
    {"hotstar", "DisneyPlusHotstar"},
    {"disneyplus", "DisneyPlus"},
    {"spotify", "Spotify"},
    {"jiohotstar", "JioHotstar"},
    {"sonyliv", "SonyLIV"},
    {"zee5", "ZEE5"},
    {"jiocinema", "JioCinema"},
    {"mxplayer", "MXPlayer"},

    /* Social / messaging */
    {"whatsapp", "WhatsApp"},
    {"wa.me", "WhatsApp"},
    {"facebook", "Facebook"},
    {"fbcdn", "Facebook"},
    {"fb.com", "Facebook"},
    {"messenger", "Facebook"},
    {"instagram", "Instagram"},
    {"cdninstagram", "Instagram"},
    {"threads.net", "Instagram"},
    {"tiktok", "TikTok"},
    {"tiktokcdn", "TikTok"},
    {"linkedin", "LinkedIn"},
    {"twitter", "Twitter"},
    {"twimg", "Twitter"},
    {"x.com", "Twitter"},
    {"snapchat", "Snapchat"},
    {"reddit", "Reddit"},
    {"discord", "Discord"},
    {"telegram", "Telegram"},
    {"pinterest", "Pinterest"},
    {"quora", "Quora"},

    /* Meetings / productivity */
    {"zoom", "Zoom"},
    {"teams.microsoft", "MicrosoftTeams"},
    {"skype", "Skype"},
    {"slack", "Slack"},
    {"notion", "Notion"},
    {"dropbox", "Dropbox"},
    {"box.com", "Box"},
    {"office", "Microsoft"},
    {"office365", "Microsoft"},
    {"microsoft", "Microsoft"},
    {"live.com", "Microsoft"},
    {"outlook", "Microsoft"},
    {"onedrive", "Microsoft"},
    {"sharepoint", "Microsoft"},

    /* Ads / analytics / observability */
    {"doubleclick", "GoogleAds"},
    {"googleads", "GoogleAds"},
    {"googlesyndication", "GoogleAds"},
    {"adservice.google", "GoogleAds"},
    {"analytics.google", "GoogleAnalytics"},
    {"googletagmanager", "GoogleAnalytics"},
    {"criteo", "Criteo"},
    {"newrelic", "NewRelic"},
    {"sentry", "Sentry"},
    {"appsflyer", "AppsFlyer"},
    {"branch.io", "Branch"},
    {"moengage", "MoEngage"},
    {"clevertap", "CleverTap"},

    /* Search / cloud / app platforms */
    {"googleapis", "Google"},
    {"google.com", "Google"},
    {"gstatic", "Google"},
    {"googleusercontent", "Google"},
    {"gvt1", "Google"},
    {"android.clients", "Google"},
    {"firebase", "Firebase"},
    {"crashlytics", "Firebase"},
    {"apple", "Apple"},
    {"icloud", "Apple"},
    {"itunes", "Apple"},
    {"mzstatic", "Apple"},
    {"amazonaws", "AmazonAWS"},
    {"cloudfront", "AmazonCloudFront"},
    {"aws", "AmazonAWS"},
    {"cloudflare", "Cloudflare"},
    {"akamaized", "Akamai"},
    {"akamai", "Akamai"},
    {"fastly", "Fastly"},
    {"github", "GitHub"},
    {"gitlab", "GitLab"},
    {"bitbucket", "Bitbucket"},

    /* Shopping / delivery / travel */
    {"amazon.in", "Amazon"},
    {"amazon.com", "Amazon"},
    {"devices.a2z.com", "Amazon"},
    {"bdtelemetry.amazon", "Amazon"},
    {"mshop", "Amazon"},
    {"flipkart", "Flipkart"},
    {"myntra", "Myntra"},
    {"meesho", "Meesho"},
    {"ajio", "AJIO"},
    {"nykaa", "Nykaa"},
    {"bookmyshow", "BookMyShow"},
    {"bmscdn", "BookMyShow"},
    {"swiggy", "Swiggy"},
    {"zomato", "Zomato"},
    {"blinkit", "Blinkit"},
    {"bigbasket", "BigBasket"},
    {"grofers", "Blinkit"},
    {"uber", "Uber"},
    {"olacabs", "Ola"},
    {"makemytrip", "MakeMyTrip"},
    {"goibibo", "Goibibo"},
    {"irctc", "IRCTC"},

    /* Payments / finance */
    {"phonepe", "PhonePe"},
    {"paytm", "Paytm"},
    {"razorpay", "Razorpay"},
    {"cashfree", "Cashfree"},
    {"stripe", "Stripe"},
    {"paypal", "PayPal"},
    {"billdesk", "BillDesk"},
    {"hdfcbank", "HDFCBank"},
    {"icicibank", "ICICIBank"},
    {"axisbank", "AxisBank"},
    {"sbi.co.in", "SBI"},
    {"onlinesbi", "SBI"},

    /* Games */
    {"pubg", "PUBG"},
    {"krafton", "Krafton"},
    {"roblox", "Roblox"},
    {"minecraft", "Minecraft"},
    {"epicgames", "EpicGames"},
    {"steampowered", "Steam"},
    {"steamcontent", "Steam"},
    {"riotgames", "RiotGames"},
    {"ea.com", "EA"},
    {"playstation", "PlayStation"},
    {"xboxlive", "Xbox"},

    /* Device / OEM clouds */
    {"vivoglobal", "Vivo"},
    {"heytap", "HeyTap"},
    {"allawnos", "HeyTap"},
    {"oppo", "OPPO"},
    {"oneplus", "OnePlus"},
    {"xiaomi", "Xiaomi"},
    {"miui", "Xiaomi"},
    {"mi.com", "Xiaomi"},
    {"samsung", "Samsung"},
    {"hicloud", "Huawei"},
    {"huawei", "Huawei"},
    {"lenovo", "Lenovo"},
    {"motorola", "Motorola"},

    /* Smaller app-specific services seen in the field */
    {"sponsor.ajay.app", "SponsorBlock"},
};

const char *service_from_domain(
    const char *domain)
{
    if (!domain || !domain[0])
        return "Unknown";

    for (size_t i = 0; i < sizeof(SERVICE_PATTERNS) / sizeof(SERVICE_PATTERNS[0]); i++) {
        if (strstr(domain, SERVICE_PATTERNS[i].pattern))
            return SERVICE_PATTERNS[i].service;
    }

    return "Unknown";
}
