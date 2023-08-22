#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "platform.h"

#include "util.h"
#include "net.h"

#define DUMMY_MTU UINT16_MAX // 65535
#define DUMMY_IRQ INTR_IRQ_BASE

static int dummy_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);

    // データを破棄

    intr_raise_irq(DUMMY_IRQ);

    return 0;
}

static int dummy_isr(unsigned int irq, void *id)
{
    debugf("irq=%u, dev=%s", irq, ((struct net_device *)id)->name);

    return 0;
}

static struct net_device_ops dummy_ops = {
    .transmit = dummy_transmit,
};

struct net_device *dummy_init(void)
{
    struct net_device *dev;

    dev = net_device_alloc();
    if (dev == NULL)
    {
        errorf("net_device_alloc() failed");
        return NULL;
    }

    // デバイスの作成
    dev->type = NET_DEVICE_TYPE_DUMMY;
    dev->mtu = DUMMY_MTU;
    dev->hlen = 0;
    dev->alen = 0;
    dev->ops = &dummy_ops;

    // デバイスを登録する
    if (net_device_register(dev) != 0)
    {
        errorf("net_device_register() failed");
        return NULL;
    }

    // 割り込みハンドラを登録する
    intr_request_irq(DUMMY_IRQ, dummy_isr, INTR_IRQ_SHARED, dev->name, dev);

    debugf("initialized, dev=%s", dev->name);
    return dev;
}
