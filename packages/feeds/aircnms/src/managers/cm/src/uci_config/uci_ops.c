#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <radio_vif.h>

#include "uci_ops.h"

int uciGetSectionName(const char *pkg, char *sec_type, struct airpro_mgr_get_all_uci_section_names *sec_arr_names);
static struct uci_context *ctx;

int uciSet(const char *pkg, char *sec, char *opt, char *val)
{
    struct uci_ptr ptr;
    int ret = UCI_OK;
    char optv[UCI_MAX_STR_LEN*2];

    snprintf(optv, sizeof(optv), "%s.%s.%s=%s", pkg, sec, opt, val);

    if (uci_lookup_ptr(ctx, &ptr, optv, true) != UCI_OK) {
        return -1;
    }

    ret = uci_set(ctx, &ptr);
    if (ret != UCI_OK)
        return -1;

    ret = uci_save(ctx, ptr.p);
    if (ret != UCI_OK)
        return -1;

    return 0;
}

int uciAddList(const char *pkg, char *sec, char *opt, char *val)
{
    struct uci_ptr ptr;
    int ret = UCI_OK;
    char optv[UCI_MAX_STR_LEN*2];

    snprintf(optv, sizeof(optv), "%s.%s.%s=%s", pkg, sec, opt, val);
    if (uci_lookup_ptr(ctx, &ptr, optv, true) != UCI_OK) {
        return -1;
    }
    ret = uci_add_list(ctx, &ptr);
    if (ret != UCI_OK)
        return -1;
    ret = uci_save(ctx, ptr.p);
    if (ret != UCI_OK)
        return -1;

    return 0;
}

int uciDelList(const char *pkg, char *sec, char *opt, char *val)
{
    struct uci_ptr ptr;
    int ret = UCI_OK;
    char optv[UCI_MAX_STR_LEN*2];

    snprintf(optv, sizeof(optv), "%s.%s.%s=%s", pkg, sec, opt, val);

    if (uci_lookup_ptr(ctx, &ptr, optv, true) != UCI_OK) {
        return -1;
    }
    ret = uci_del_list(ctx, &ptr);
    if (ret != UCI_OK)
        return -1;

    ret = uci_save(ctx, ptr.p);
    if (ret != UCI_OK)
        return -1;

    return 0;
}


int uciEmptyList(const char *pkg, char *sec, char *opt)
{
    struct uci_ptr ptr;
    //int ret = UCI_OK;
    char optv[UCI_MAX_STR_LEN*2];

    snprintf(optv, sizeof(optv), "%s.%s=%s", pkg, sec, opt);

    if (uci_lookup_ptr(ctx, &ptr, optv, true) != UCI_OK) {
        return -1;
    }
    // Check if the list is empty
    if (ptr.o != NULL && ptr.o->type == UCI_TYPE_STRING) {
        printf("The list is not empty\n");
        return 0;
    }
    return 1;
}

int uciGet(const char *pkg, char *sec, char *opt, char *val)
{
    struct uci_ptr ptr;
    //struct uci_element *e;
    char optv[UCI_MAX_STR_LEN];

    snprintf(optv, sizeof(optv), "%s.%s.%s", pkg, sec, opt);

    if (uci_lookup_ptr(ctx, &ptr, optv, true) != UCI_OK) {
        return ERROR;
    }

    if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
        return ERROR;
    }

    //e = ptr.last;
    //if (e->type != UCI_TYPE_LIST || ptr.o->type != UCI_TYPE_STRING)
    //    return ERROR;


    strlcpy(val, ptr.o->v.string, UCI_MAX_STR_LEN);

    //printf("get string %s\n", ptr.o->v.string);
    return SUCCESS;

}

int uciGetList(const char *pkg, char *sec, char *opt, char *val)
{   
    struct uci_ptr ptr;
    struct uci_element *e;
    char optv[UCI_MAX_STR_LEN];
        
    snprintf(optv, sizeof(optv), "%s.%s.%s", pkg, sec, opt);
        
    if (uci_lookup_ptr(ctx, &ptr, optv, true) != UCI_OK) {
        return ERROR;
    }   
        
    if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
        return ERROR;
    }
        
    e = ptr.last; 
    uci_foreach_element(&ptr.o->v.list, e) {
        strcat(val, e->name);
        strcat(val, " ");
    }
        
    return SUCCESS;
}


int uciCommit(char *pkg)
{
    struct uci_ptr ptr;

    if (uci_lookup_ptr(ctx, &ptr, pkg, true) != UCI_OK) {
        return ERROR;
    }

    if (uci_commit(ctx, &ptr.p, false) != UCI_OK)
        return ERROR;

    if (ptr.p)
        uci_unload(ctx, ptr.p);

    return SUCCESS;
}

int uciInit()
{
    ctx = uci_alloc_context();
    if (!ctx) {
        fprintf(stderr, "Out of memory\n");
        return ERROR;
    }

    return SUCCESS;
}

int uciDestroy()
{
    uci_free_context(ctx);
    return SUCCESS;
}

int uciDelete(const char *pkg, char *sec, const char *opt)
{
    struct uci_ptr ptr;
    int ret = UCI_OK;
    char optv[UCI_MAX_STR_LEN * 2];

    snprintf(optv, sizeof(optv), "%s.%s.%s", pkg, sec, opt);
    if (uci_lookup_ptr(ctx, &ptr, optv, true) != UCI_OK) {
        return ERROR;
    }

    ret = uci_delete(ctx, &ptr);

    if (ret != UCI_OK)
        return ERROR;

    return SUCCESS;
}

int uciGetSectionNameFromRecordID(const char *pkg, char *sec_name, char *record_id)
{
    struct uci_element *elm = NULL;
    struct uci_package *p;
    struct uci_ptr ptr;
    //int num_entry = 0;

    if (uci_lookup_ptr(ctx, &ptr, (char *)pkg, true) != UCI_OK) {
        return ERROR;
    }

    elm = ptr.last;
    p = ptr.p;
    uci_foreach_element(&p->sections, elm) {
        struct uci_section *s = uci_to_section(elm);
        struct uci_element *e;
        //const char *cname;
        //const char *sname;
        //cname = s->package->e.name;
        //sname = s->e.name;
        uci_foreach_element(&s->options, e) {
            struct uci_option *o = uci_to_option(e);
            if (!strcmp(o->v.string, record_id)) {
                strcpy(sec_name, o->section->e.name);
                return SUCCESS;
            }
        }
    }

    return ERROR;
}


int uciGetSectionNameFromIfName(const char *pkg, char *sec_name, char *ifname)
{
    struct uci_element *elm = NULL;
    struct uci_package *p;
    struct uci_ptr ptr;
    //int num_entry = 0;

    if (uci_lookup_ptr(ctx, &ptr, (char *)pkg, true) != UCI_OK) {
        return ERROR;
    }

    elm = ptr.last;
    p = ptr.p;
    uci_foreach_element(&p->sections, elm) {
        struct uci_section *s = uci_to_section(elm);
        struct uci_element *e;
        //const char *cname;
        //const char *sname;
        //cname = s->package->e.name;
        //sname = s->e.name;
        uci_foreach_element(&s->options, e) {
            struct uci_option *o = uci_to_option(e);
            if (!strcmp(o->v.string, ifname)) {
                strcpy(sec_name, o->section->e.name);
                return SUCCESS;
            }
        }
    }

    return ERROR;
}
/*
int uciGetSectionName(const char *pkg, char *sec_type, struct airpro_mgr_get_all_uci_section_names *sec_arr_names)
{
    struct uci_element *elm = NULL;
    struct uci_package *p;
    struct uci_ptr ptr;
    int num_entry = 0;

    if (uci_lookup_ptr(ctx, &ptr, (char *)pkg, true) != UCI_OK) {
        return 1;
    }

    elm = ptr.last;
    p = ptr.p;
    uci_foreach_element(&p->sections, elm) {
        struct uci_section *s = uci_to_section(elm);
        if (!strcmp(s->type, sec_type)) {
            strcpy(sec_arr_names->sec_name[num_entry], s->e.name);
            num_entry++;
        }
    }
    sec_arr_names->num_entry = num_entry;

    return SUCCESS;
}
*/

int uciSectionExist(const char *pkg, const char *opt, const char *sectionName)
{
    //struct uci_section *s = NULL;
    //int ret = UCI_OK;
    struct uci_ptr ptr;
    char optv[UCI_MAX_STR_LEN * 2];
    struct uci_element* element_section = NULL;
    int status = SUCCESS;
        
    snprintf(optv, sizeof(optv), "%s.%s=%s", pkg, sectionName, opt);
    
    if (uci_lookup_ptr(ctx, &ptr, optv, true) != UCI_OK) {
        return -1;
    }
    
    uci_foreach_element(&ptr.p->sections, element_section) {
        struct uci_section* section = NULL;
        section = uci_to_section(element_section);

        if (!strcmp(section->e.name, sectionName)) {
            status = ERROR;
        }
    }

    return status;
}

int uciGetSectionNameFromRVID(const char *pkg, char *sec_name, int radio_idx, int vap_idx)
{
    struct uci_element *elm = NULL;
    struct uci_package *p;
    struct uci_ptr ptr;
    int wifi0_vap_idx = 0, wifi1_vap_idx = 0, wifi2_vap_idx = 0;

    if (uci_lookup_ptr(ctx, &ptr, (char *)pkg, true) != UCI_OK) {
        return 1;
    }

    elm = ptr.last;
    p = ptr.p;
    uci_foreach_element(&p->sections, elm) {
        struct uci_section *s = uci_to_section(elm);
        struct uci_element *e;
        //const char *cname;
        //const char *sname;
        //cname = s->package->e.name;
        //sname = s->e.name;
        //printf("%s.%s=%s\n", cname, sname, s->type);
        if (!strncmp(s->type, "wifi-iface", 10)) {
            uci_foreach_element(&s->options, e) {
                struct uci_option *o = uci_to_option(e);
                int radio_index = 0;
                if (!strncmp(o->e.name, "device", 6)) {
                    sscanf(o->v.string, "wifi%d", &radio_index);
                    //printf("%s.%s.%s=%s\n", o->section->package->e.name,o->section->e.name, o->e.name, o->v.string);
                    if (radio_index == 0) {
                        if (radio_index == radio_idx) {
                            if (wifi0_vap_idx == vap_idx) {
                                strcpy(sec_name, o->section->e.name);
                                return SUCCESS;
                            }
                        }
                        wifi0_vap_idx++;
                    } else if (radio_index == 1) {
                        if (radio_index == radio_idx) {
                            if (wifi1_vap_idx == vap_idx) {
                                strcpy(sec_name, o->section->e.name);
                                return SUCCESS;
                            }
                        }
                        wifi1_vap_idx++;
                    } else if (radio_index == 2) {
                        if (radio_index == radio_idx) {
                            if (wifi2_vap_idx == vap_idx) {
                                strcpy(sec_name, o->section->e.name);
                                return SUCCESS;
                            }
                        }
                        wifi2_vap_idx++;
                    }
                }
            }
        }
    }

    return ERROR;
}

int uciGetSectionNameFromUciIdx(const char *pkg, char *sec_name, int uci_idx)
{   
    //struct uci_parse_context *pctx = ctx->pctx;
    //struct uci_section *s = NULL;
    //int ret = UCI_OK;
    struct uci_ptr ptr;
    char optv[UCI_MAX_STR_LEN * 2];
    struct uci_element* element_section = NULL;
    int uidx = 0;
    
    snprintf(optv, sizeof(optv), "%s.%s", pkg, "wifi0");

    if (uci_lookup_ptr(ctx, &ptr, optv, true) != UCI_OK) {
        return -1;
    }

    uci_foreach_element(&ptr.p->sections, element_section) {
        struct uci_section *section = uci_to_section(element_section);
    
        if (section->e.type == UCI_TYPE_SECTION) {
            if (!strcmp(section->type,"wifi-iface")) {
                if (uidx == uci_idx) {
                    strcpy(sec_name, section->e.name);
                    break;
                }
                uidx++;
            }
            
        }
    }

    return SUCCESS;
}


int uciAddSection(const char *pkg, const char *opt, const char *sectionName)
{
    //struct uci_section *s = NULL;
    int ret = UCI_OK;
    struct uci_ptr ptr;
    char optv[UCI_MAX_STR_LEN * 2];
    struct uci_element* element_section = NULL;
    int vaps = 0;

    snprintf(optv, sizeof(optv), "%s.%s=%s", pkg, sectionName, opt);

    if (uci_lookup_ptr(ctx, &ptr, optv, true) != UCI_OK) {
        return -1;
    }

    ret = uci_set(ctx, &ptr);
    if (ret != UCI_OK)
        return -1;

    ret = uci_save(ctx, ptr.p);
    if (ret != UCI_OK)
        return -1;


    uci_foreach_element(&ptr.p->sections, element_section) {
        struct uci_section* section = NULL;
        section = uci_to_section(element_section);

        if (section->e.type == UCI_TYPE_SECTION) {
        }
        if (!strcmp(section->type,"wifi-iface")) {
            vaps++;
        }
    }
    return vaps;
}

int uciDeleteSection(const char *pkg, const char *sectionName)
{
    //struct uci_section *s = NULL;
    int ret = UCI_OK;
    struct uci_ptr ptr;
    char optv[UCI_MAX_STR_LEN * 2];
    struct uci_element* element_section = NULL;
    int vaps = 0; 

    snprintf(optv, sizeof(optv), "%s.%s", pkg, sectionName);
    if (uci_lookup_ptr(ctx, &ptr, optv, true) != UCI_OK) {
        return ERROR;
    }

    ret = uci_delete(ctx, &ptr);
    
    if (ret != UCI_OK)
        return ERROR;

     uci_foreach_element(&ptr.p->sections, element_section) {
        struct uci_section* section = NULL;
        section = uci_to_section(element_section);

        if (!strcmp(section->type,"wifi-iface")) {
            vaps++;
        }
    }
    return vaps;
}

