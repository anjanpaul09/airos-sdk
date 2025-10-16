#include <linux/spinlock.h>
#include <linux/export.h>
#include "air_api.h"

/* Ops registration/getter so mac80211 can call without hard dependency */
static const struct airdpi_ops *airdpi_ops_ptr;
static DEFINE_SPINLOCK(airdpi_ops_lock);

int airdpi_register_ops(const struct airdpi_ops *ops)
{
    unsigned long flags;

    if (!ops)
        return -EINVAL;

    spin_lock_irqsave(&airdpi_ops_lock, flags);
    if (airdpi_ops_ptr) {
        spin_unlock_irqrestore(&airdpi_ops_lock, flags);
        return -EBUSY;
    }
    airdpi_ops_ptr = ops;
    spin_unlock_irqrestore(&airdpi_ops_lock, flags);
    return 0;
}
EXPORT_SYMBOL_GPL(airdpi_register_ops);

void airdpi_unregister_ops(const struct airdpi_ops *ops)
{
    unsigned long flags;

    spin_lock_irqsave(&airdpi_ops_lock, flags);
    if (airdpi_ops_ptr == ops)
        airdpi_ops_ptr = NULL;
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

    return ops;
}
EXPORT_SYMBOL_GPL(airdpi_get_ops);


