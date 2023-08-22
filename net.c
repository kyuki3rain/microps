#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "platform.h"

#include "util.h"
#include "net.h"

static struct net_device *devices;

struct net_device *net_device_alloc(void)
{
    struct net_device *dev;

    dev = memory_alloc(sizeof(*dev));
    if (dev == NULL)
    {
        errorf("memory_alloc() failed");
        return NULL;
    }

    return dev;
}

int net_device_register(struct net_device *dev)
{
    static unsigned int index = 0;

    // 実行する度にindexがインクリメントされる
    dev->index = index++;
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);

    // devicesの先頭に追加
    dev->next = devices;
    devices = dev;

    infof("registered dev=%s, type=0x%04x", dev->name, dev->type);

    return 0;
}

static int net_device_open(struct net_device *dev)
{
    if (NET_DEVICE_IS_UP(dev))
    {
        errorf("device is already up, dev=%s", dev->name);
        return -1;
    }

    if (dev->ops->open)
    {
        if (dev->ops->open(dev) != 0)
        {
            errorf("open() failed, dev=%s", dev->name);
            return -1;
        }
    }

    dev->flags |= NET_DEVICE_FLAG_UP; // UPフラグを立てる
    infof("device is up, dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

static int net_device_close(struct net_device *dev)
{
    if (!NET_DEVICE_IS_UP(dev))
    {
        errorf("device is already down, dev=%s", dev->name);
        return -1;
    }

    if (dev->ops->close)
    {
        if (dev->ops->close(dev) != 0)
        {
            errorf("close() failed, dev=%s", dev->name);
            return -1;
        }
    }

    dev->flags &= ~NET_DEVICE_FLAG_UP; // UPフラグを下げる
    infof("device is down, dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

int net_device_output(struct net_device *dev, uint16_t type, const void *data, size_t len, const void *dst)
{
    // デバイスがUPでなければ送信できない
    if (!NET_DEVICE_IS_UP(dev))
    {
        errorf("device is down, dev=%s", dev->name);
        return -1;
    }

    // mtuより大きいパケットは送信できない
    if (len > dev->mtu)
    {
        errorf("too large packet, dev=%s, len=%zu, mtu=%u", dev->name, len, dev->mtu);
        return -1;
    }

    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    if (dev->ops->transmit(dev, 0, data, len, dst) != 0)
    {
        errorf("transmit() failed, dev=%s, len=%zu", dev->name, len);
        return -1;
    }

    return 0;
}

int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);

    return 0;
}

int net_run(void)
{
    struct net_device *dev;

    if (intr_run() == -1)
    {
        errorf("intr_run() failed");
        return -1;
    }

    debugf("open all devices...");
    for (dev = devices; dev != NULL; dev = dev->next)
    {
        net_device_open(dev);
    }
    debugf("running...");

    return 0;
}

void net_shutdown(void)
{
    struct net_device *dev;

    debugf("close all devices...");
    for (dev = devices; dev != NULL; dev = dev->next)
    {
        net_device_close(dev);
    }

    intr_shutdown();

    debugf("shutdown");
}

int net_init(void)
{
    if (intr_init() == -1)
    {
        errorf("intr_init() failed");
        return -1;
    }

    infof("initialized");
    return 0;
}