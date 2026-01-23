#include <linux/export.h>
#include <linux/etherdevice.h>
#include <linux/inet.h>
#include "air_coplane.h"
#include "air_ioctl.h" /* for IFNAME_HASH */

extern struct airpro_coplane *coplane;

int remove_client_from_coplane_table(uint8_t *macaddr);
int remove_client_from_reg_table(uint8_t *macaddr, char *ifname);
struct client_node *client_reg_table_lookup(uint8_t *macaddr);
struct client_node *client_reg_table_alloc(char *macaddr);
struct wlan_sta *sta_table_lookup(uint8_t *macaddr, int dir, uint8_t ifindex);

int airdpi_sta_add(const u8 *macaddr, const char *ifname)
{
    struct client_node *cn;
    struct wlan_sta *se = NULL;
    int vap_id;

    if (!macaddr)
        return -EINVAL;

    printk("AIRDPI: client event received: MAC=%02x:%02x:%02x:%02x:%02x:%02x ifname=%s\n",
           macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5],
           ifname ? ifname : "NULL");

    cn = client_reg_table_lookup((uint8_t *)macaddr);
    if (!cn) {
        cn = client_reg_table_alloc((char *)macaddr);
        if (!cn)
            return -ENOMEM;
    }
    /* Mark as wireless since this comes from mac80211 */
    cn->is_wireless = 1;

  /* Update interface name on roaming or initial association */
  if (ifname) {
    if (cn->ifname[0] != '\0' && strcmp(cn->ifname, ifname) != 0) {
      printk("AIRDPI: client ifname update: MAC=%02x:%02x:%02x:%02x:%02x:%02x "
             "from ifname=%s to ifname=%s\n",
             macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4],
             macaddr[5], cn->ifname, ifname);
    }
    strncpy(cn->ifname, ifname, sizeof(cn->ifname) - 1);
    cn->ifname[sizeof(cn->ifname) - 1] = '\0';
  }

    vap_id = IFNAME_HASH(ifname);
    se = sta_table_lookup((uint8_t *)macaddr, PACKET_INGRESS, vap_id);

    return 0;
}
EXPORT_SYMBOL_GPL(airdpi_sta_add);

int airdpi_sta_del(const u8 *macaddr, const char *ifname)
{
    int rc_reg = -EINVAL;
    int rc_coplane = -EINVAL;

    if (!macaddr)
        return -EINVAL;

  printk("AIRDPI: client disconnection event received: "
         "MAC=%02x:%02x:%02x:%02x:%02x:%02x ifname=%s\n",
         macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5],
         ifname ? ifname : "NULL");

    if (ifname)
        rc_reg = remove_client_from_reg_table((uint8_t *)macaddr, (char *)ifname);

  /* Only remove from coplane if client was removed from reg table
   * If rc_reg != 0, client's ifname doesn't match (roamed to different
   * interface)
   */
  if (rc_reg == 0) {
    rc_coplane = remove_client_from_coplane_table((uint8_t *)macaddr);
  } else {
    printk("AIRDPI: client NOT removed from queue - likely roamed to different "
           "interface: "
           "MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
           macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4],
           macaddr[5]);
  }

    if (rc_reg == 0 || rc_coplane == 0)
        return 0;

    return -ENOENT;
}
EXPORT_SYMBOL_GPL(airdpi_sta_del);


