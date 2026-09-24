#ifndef PORTAL_DB_H_INCLUDED
#define PORTAL_DB_H_INCLUDED

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#define PORTAL_ID_LEN       64
#define PORTAL_NAME_LEN     16
#ifndef PORTAL_PATH_LEN
#define PORTAL_PATH_LEN     512
#endif
#define PORTAL_VIF_LEN      16
#define PORTAL_MAX_ENTRIES  16
#define PORTAL_MAX_VIFS     32

typedef struct portal_entry {
    char portal_id[PORTAL_ID_LEN];
    char network[PORTAL_NAME_LEN];
    char bridge[PORTAL_NAME_LEN];
    char interface[PORTAL_NAME_LEN];
    char tun[PORTAL_NAME_LEN];
    char ipaddr[32];
    char netmask[32];
    char metadata_path[PORTAL_PATH_LEN];
    int ref_count;
    pid_t pid;
    bool running;
} portal_entry_t;

typedef struct portal_vif_ref {
    char vif_name[PORTAL_VIF_LEN];
    char portal_id[PORTAL_ID_LEN];
} portal_vif_ref_t;

void portal_db_init(void);
portal_entry_t *portal_db_get(const char *portal_id);
portal_entry_t *portal_db_add(const char *portal_id);
void portal_db_remove(const char *portal_id);
int portal_db_count(void);
portal_entry_t *portal_db_at(int idx);
const char *portal_db_get_vif_portal(const char *vif_name);
void portal_db_set_vif_portal(const char *vif_name, const char *portal_id);
void portal_db_clear_vif_portal(const char *vif_name);

#endif /* PORTAL_DB_H_INCLUDED */
