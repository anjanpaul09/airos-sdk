#include <uci.h>
//#include <radio_vif.h>
//#include <radio_vif.h>

#define UCI_MAX_STR_LEN 256

/* error codes */
#define  SUCCESS       (0)
#define  ERROR         (-1)
#define  ESETUCI       (2)



int uciSet(const char *pkg, char *sec, char *opt, char *val);
int uciAddList(const char *pkg, char *sec, char *opt, char *val);
int uciDelList(const char *pkg, char *sec, char *opt, char *val);
int uciGet(const char *pkg, char *sec, char *opt, char *val);
int uciCommit(char *pkg);
int uciInit();
int uciDestroy();
int uciDelete(const char *pkg, char *sec, const char *opt);
int uciAddSection(const char *pkg , const char *opt, const char *sectionName);
int uciDeleteSection(const char *pkg , const char *sectionName);
int uciGetSectionNameFromRVID(const char *pkg, char *sec_name, int radio_idx, int vap_idx);
int uciGetList(const char *pkg, char *sec, char *opt, char *val);
//int uciGetSectionName(const char *pkg, char *sec_type, struct airpro_mgr_get_all_uci_section_names *sec_arr_names);
