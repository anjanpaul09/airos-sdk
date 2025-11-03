#include <linux/spinlock.h>
#include <linux/export.h>
#include "air_api.h"

/* Ops registration/getter so mac80211 can call without hard dependency */
static const struct airdpi_ops *airdpi_ops_ptr;
static DEFINE_SPINLOCK(airdpi_ops_lock);

int airdpi_register_ops(const struct airdpi_ops *ops)
{
    unsigned long flags;

    if (!ops) {
        printk("AIRDPI: register_ops called with NULL ops\n");
        return -EINVAL;
    }

    if (!ops->sta_add || !ops->sta_del) {
        printk("AIRDPI: register_ops called with invalid ops (NULL callbacks)\n");
        return -EINVAL;
    }

    spin_lock_irqsave(&airdpi_ops_lock, flags);
    if (airdpi_ops_ptr) {
        spin_unlock_irqrestore(&airdpi_ops_lock, flags);
        printk("AIRDPI: register_ops failed - ops already registered\n");
        return -EBUSY;
    }
    airdpi_ops_ptr = ops;
    spin_unlock_irqrestore(&airdpi_ops_lock, flags);
    
    printk("AIRDPI: ops registered successfully (sta_add=%p, sta_del=%p)\n",
           ops->sta_add, ops->sta_del);
    return 0;
}
EXPORT_SYMBOL_GPL(airdpi_register_ops);

void airdpi_unregister_ops(const struct airdpi_ops *ops)
{
    unsigned long flags;

    spin_lock_irqsave(&airdpi_ops_lock, flags);
    if (airdpi_ops_ptr == ops) {
        airdpi_ops_ptr = NULL;
        printk("AIRDPI: ops unregistered successfully\n");
    } else {
        printk("AIRDPI: unregister_ops called but ops don't match\n");
    }
    spin_unlock_irqrestore(&airdpi_ops_lock, flags);
}
EXPORT_SYMBOL_GPL(airdpi_unregister_ops);

const struct airdpi_ops *airdpi_get_ops(void)
{
    unsigned long flags;
    const struct airdpi_ops *ops;

    spin_lock_irqsave(&airdpi_ops_lock, flags);
    ops = airdpi_ops_ptr;
    spin_unlock_irqrestore(&airdpi_ops_lock, flags);

    /* Only log when ops are missing to help diagnose registration issues */
    if (!ops) {
        printk("AIRDPI: WARNING - get_ops called but ops not registered yet (module may not be loaded)\n");
    }

    return ops;
}
EXPORT_SYMBOL_GPL(airdpi_get_ops);


