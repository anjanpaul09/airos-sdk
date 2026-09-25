#include <stdio.h>
#include <string.h>
#include <uci.h>
#include "cgw_uci.h"
#include "log.h"
static bool set_option(struct uci_context *ctx,const char *section,const char *option,const char *value){
 struct uci_ptr p={0}; char path[128];
 if(!ctx||!section||!option||!value||snprintf(path,sizeof(path),"aircnms.%s.%s",section,option)>=(int)sizeof(path)) return false;
 if(uci_lookup_ptr(ctx,&p,path,true)!=UCI_OK) return false;
 p.value=value;
 return uci_set(ctx,&p)==UCI_OK;
}
static bool replace_topics(struct uci_context *ctx,const cgw_mqtt_topic_list *t){
 struct uci_ptr p={0}; char path[64]; int i,j;
 if(!ctx||!t||t->n_topic<1||t->n_topic>16) return false;
 snprintf(path,sizeof(path),"aircnms.@aircnms[0].topics");
 if(uci_lookup_ptr(ctx,&p,path,true)==UCI_OK&&p.o&&uci_delete(ctx,&p)!=UCI_OK) return false;
 for(i=0;i<t->n_topic;i++){ for(j=0;j<i;j++) if(!strcmp(t->topic[i],t->topic[j])) break; if(j<i) continue;
  memset(&p,0,sizeof(p)); snprintf(path,sizeof(path),"aircnms.@aircnms[0].topics");
  if(uci_lookup_ptr(ctx,&p,path,true)!=UCI_OK) return false;
  p.value=t->topic[i];
  if(uci_add_list(ctx,&p)!=UCI_OK) return false;
 }
 return true;
}
bool cgw_uci_commit_enrollment(const cgw_enrollment_uci_t *v){
 static const char *names[]={"device","client","vif","neighbor","config","cmdr","status","website_usage"};
 const char *vals[8]; struct uci_context *ctx=NULL; struct uci_package *pkg=NULL; bool ok=false; size_t i;
 if(!v||!v->device_id||!v->network_id||!v->org_id||!v->username||!v->password||!v->broker||!v->port||!v->topics||!v->stats) return false;
 vals[0]=v->stats->device; vals[1]=v->stats->client; vals[2]=v->stats->vif; vals[3]=v->stats->neighbor; vals[4]=v->stats->config; vals[5]=v->stats->cmdr; vals[6]=v->stats->status; vals[7]=v->stats->website_usage;
 ctx=uci_alloc_context(); if(!ctx||uci_load(ctx,"aircnms",&pkg)!=UCI_OK) goto out;
#define S(n,x) do{if(!set_option(ctx,"@aircnms[0]",n,x))goto out;}while(0)
 S("device_id",v->device_id); S("network_id",v->network_id); S("org_id",v->org_id); S("username",v->username); S("password",v->password); S("ipaddr",v->broker); S("port",v->port); S("online","0");
#undef S
 if(!replace_topics(ctx,v->topics)) goto out;
 for(i=0;i<8;i++) if(!vals[i][0]||!set_option(ctx,"@stats-topic[0]",names[i],vals[i])) goto out;
 if(uci_commit(ctx,&pkg,false)!=UCI_OK) goto out;
 ok=true;
out: if(!ok) LOG(ERR,"Enrollment UCI transaction failed"); if(pkg) uci_unload(ctx,pkg); if(ctx) uci_free_context(ctx); return ok;
}
