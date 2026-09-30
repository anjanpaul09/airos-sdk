#include "logd.h"
#include "logd_config.h"

#include <uci.h>

static const char *s_default_tags[] = {
    "air-onbd",
    "air-cgwd",
    "air-netconfd",
    "air-stamond",
    "air-eventd",
    "air-netstatsd",
    "airuid",
    "air-cmdexecd",
    "air-onbd-recovery",
    "air-ssid-check",
    "air_led_state",
    "hostapd",
    "dnsmasq",
    "netifd",
    NULL
};

void logd_config_apply_defaults(logd_config_t *cfg)
{
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->enabled = true;
    snprintf(cfg->log_dir, sizeof(cfg->log_dir), "%s", LOGD_DEFAULT_DIR);
    snprintf(cfg->log_file, sizeof(cfg->log_file), "%s", LOGD_DEFAULT_FILE);
    cfg->max_size_bytes = LOGD_DEFAULT_MAX_SIZE;
    cfg->max_backups = LOGD_DEFAULT_MAX_BACKUPS;
    cfg->compress = true;
    snprintf(cfg->min_severity, sizeof(cfg->min_severity), "info");
    cfg->rate_limit_enable = true;
    cfg->rate_limit_burst = LOGD_DEFAULT_BURST;
    cfg->rate_limit_rate = LOGD_DEFAULT_RATE;

    cfg->tag_count = 0;
    for (int i = 0; s_default_tags[i] != NULL && cfg->tag_count < LOGD_MAX_TAGS; i++) {
        snprintf(cfg->tags[cfg->tag_count++], LOGD_TAG_LEN, "%s", s_default_tags[i]);
    }
}

bool logd_config_load(logd_config_t *cfg)
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *sec = NULL;
    struct uci_element *e = NULL;

    if (!cfg) return false;
    logd_config_apply_defaults(cfg);

    ctx = uci_alloc_context();
    if (!ctx) return false;

    if (uci_load(ctx, "aircnms", &pkg) != UCI_OK || !pkg) {
        uci_free_context(ctx);
        return true; /* Return true with defaults if config file is not yet populated */
    }

    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *candidate = uci_to_section(e);
        if (candidate && candidate->type && !strcmp(candidate->type, "logd")) {
            sec = candidate;
            break;
        }
    }

    if (!sec) {
        uci_unload(ctx, pkg);
        uci_free_context(ctx);
        return true;
    }

    const char *val;

    val = uci_lookup_option_string(ctx, sec, "enabled");
    if (val) cfg->enabled = (atoi(val) != 0);

    val = uci_lookup_option_string(ctx, sec, "log_dir");
    if (val && *val) snprintf(cfg->log_dir, sizeof(cfg->log_dir), "%s", val);

    val = uci_lookup_option_string(ctx, sec, "log_file");
    if (val && *val) snprintf(cfg->log_file, sizeof(cfg->log_file), "%s", val);

    val = uci_lookup_option_string(ctx, sec, "max_size_kb");
    if (val) {
        int kb = atoi(val);
        if (kb >= 16 && kb <= 10240) {
            cfg->max_size_bytes = (size_t)kb * 1024;
        }
    }

    val = uci_lookup_option_string(ctx, sec, "max_backups");
    if (val) {
        int backups = atoi(val);
        if (backups >= 1 && backups <= 10) {
            cfg->max_backups = backups;
        }
    }

    val = uci_lookup_option_string(ctx, sec, "compress");
    if (val) cfg->compress = (atoi(val) != 0);

    val = uci_lookup_option_string(ctx, sec, "min_severity");
    if (val && *val) snprintf(cfg->min_severity, sizeof(cfg->min_severity), "%s", val);

    val = uci_lookup_option_string(ctx, sec, "rate_limit_enable");
    if (val) cfg->rate_limit_enable = (atoi(val) != 0);

    val = uci_lookup_option_string(ctx, sec, "rate_limit_burst");
    if (val) {
        int burst = atoi(val);
        if (burst >= 10 && burst <= 1000) cfg->rate_limit_burst = burst;
    }

    val = uci_lookup_option_string(ctx, sec, "rate_limit_rate");
    if (val) {
        int rate = atoi(val);
        if (rate >= 1 && rate <= 500) cfg->rate_limit_rate = rate;
    }

    struct uci_option *opt = uci_lookup_option(ctx, sec, "tag");
    if (opt && opt->type == UCI_TYPE_LIST) {
        struct uci_element *te;
        cfg->tag_count = 0;
        uci_foreach_element(&opt->v.list, te) {
            if (cfg->tag_count < LOGD_MAX_TAGS && te->name) {
                snprintf(cfg->tags[cfg->tag_count++], LOGD_TAG_LEN, "%s", te->name);
            }
        }
    }

    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return true;
}
