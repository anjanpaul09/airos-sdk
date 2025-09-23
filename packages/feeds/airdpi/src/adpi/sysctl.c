#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include "air_vif.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define USE_PROC_OPS 1
#endif

extern struct air_vif *vif;

#define MAX_IP_ADDR_LEN 16
#define PROC_DIR "airpro"
#define INFO_FILE "stainfo"
#define FLUSH_FILE "staflush"

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_info;
static struct proc_dir_entry *proc_flush;

void air_get_ip_str(u32 *sip, u8 *ipstr)
{
    snprintf(ipstr, MAX_IP_ADDR_LEN, "%pI4", sip);
}

static int info_proc_show(struct seq_file *m, void *v) 
{
    struct client_node *node = NULL;

    OS_SPIN_LOCK(&vif->nc.lock);
    TAILQ_FOREACH(node, &vif->nc.client_list, nl) {
            //char tbuf[256] = {0};
        char sipstr[16] = {0};
        air_get_ip_str(&node->ip, sipstr);
        if (!strlen(node->hostname)) {
            strcpy(node->hostname, "Unknown");
        }
        seq_printf(m, "%02x:%02x:%02x:%02x:%02x:%02x %s %s %s %u %u %u\n", node->macaddr[0], node->macaddr[1],
                                    node->macaddr[2], node->macaddr[3], node->macaddr[4], node->macaddr[5],
                                        sipstr, node->hostname, node->ifname, node->rxbytes, node->txbytes,
                                        node->connected_tms);

    }
    OS_SPIN_UNLOCK(&vif->nc.lock);


    return 0;
}

static int info_proc_open(struct inode *inode, struct file *file) 
{
    return single_open(file, info_proc_show, NULL);
}

static ssize_t flush_proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos) 
{
    return count;
}

#if USE_PROC_OPS
static const struct proc_ops info_proc_fops = {
    .proc_open    = info_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static const struct proc_ops flush_proc_fops = {
    .proc_write   = flush_proc_write,
};
#else
static const struct file_operations info_proc_fops = {
    .owner   = THIS_MODULE,
    .open    = info_proc_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

static const struct file_operations flush_proc_fops = {
    .owner   = THIS_MODULE,
    .write   = flush_proc_write,
};
#endif

int air_vif_node_sysctl_register(struct air_vif *vif)
{
    proc_dir = proc_mkdir(PROC_DIR, NULL);
    if (!proc_dir) {
        pr_err("Failed to create /proc/%s\n", PROC_DIR);
        return -ENOMEM;
    }

    // ✅ Create `/proc/air/node_tble/info`
    proc_info = proc_create(INFO_FILE, 0444, proc_dir, &info_proc_fops);
    if (!proc_info) {
        pr_err("Failed to create /proc/%s/%s\n", PROC_DIR, INFO_FILE);
        goto cleanup;
    }

    // ✅ Create `/proc/air/node_tble/flush`
    proc_flush = proc_create(FLUSH_FILE, 0222, proc_dir, &flush_proc_fops);
    if (!proc_flush) {
        pr_err("Failed to create /proc/%s/%s\n", PROC_DIR, FLUSH_FILE);
        goto cleanup;
    }

    pr_info("Proc entries created successfully!\n");
    return 0;

cleanup:
    remove_proc_entry(INFO_FILE, proc_dir);
    remove_proc_entry(PROC_DIR, NULL);
    return -ENOMEM;
}

void air_vif_node_sysctl_unregister(void)
{
    if (proc_flush) remove_proc_entry(FLUSH_FILE, proc_dir);
    if (proc_info) remove_proc_entry(INFO_FILE, proc_dir);
    if (proc_dir) remove_proc_entry(PROC_DIR, NULL);

    pr_info("Node table proc entries removed!\n");
    
}

