#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"

struct net_protocol
{
    struct net_protocol *next;
    uint16_t type;
    struct queue_head queue;
    void (*handler)(const uint8_t *data, size_t len, struct net_device *dev);
};

struct net_protocol_queue_entry
{
    struct net_device *dev;
    size_t len;
    uint8_t data[];
};

static struct net_device *devices;
static struct net_protocol *protocols;

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

int net_device_add_iface(struct net_device *dev, struct net_iface *iface)
{
    struct net_iface *entry;

    for (entry = dev->ifaces; entry; entry = entry->next)
    {
        if (entry->family == iface->family)
        {
            errorf("iface is already registered, dev=%s, family=%d", dev->name, iface->family);
            return -1;
        }
    }

    iface->dev = dev;

    iface->next = dev->ifaces;
    dev->ifaces = iface;

    return 0;
}

struct net_iface *net_device_get_iface(struct net_device *dev, int family)
{
    struct net_iface *iface;

    for (iface = dev->ifaces; iface; iface = iface->next)
    {
        if (iface->family == family)
        {
            return iface;
        }
    }

    return NULL;
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
    if (dev->ops->transmit(dev, type, data, len, dst) != 0)
    {
        errorf("transmit() failed, dev=%s, len=%zu", dev->name, len);
        return -1;
    }

    return 0;
}

int net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev))
{
    struct net_protocol *proto;

    for (proto = protocols; proto; proto = proto->next)
    {
        if (proto->type == type)
        {
            errorf("protocol is already registered, type=0x%04x", type);
            return -1;
        }
    }

    proto = memory_alloc(sizeof(*proto));
    if (proto == NULL)
    {
        errorf("memory_alloc() failed");
        return -1;
    }

    proto->type = type;
    proto->handler = handler;
    queue_init(&proto->queue);

    proto->next = protocols;
    protocols = proto;
    infof("registered, type=0x%04x", type);

    return 0;
}

int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);

    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;

    for (proto = protocols; proto; proto = proto->next)
    {
        if (proto->type == type)
        {
            entry = memory_alloc(sizeof(*entry) + len);
            if (entry == NULL)
            {
                errorf("memory_alloc() failed");
                return -1;
            }

            entry->dev = dev;
            entry->len = len;
            memcpy(entry->data, data, len);

            if (queue_push(&proto->queue, entry) == NULL)
            {
                errorf("queue_push() failed");
                return -1;
            }

            debugf("queue pushed (num=%u), type=0x%04x, len=%zu", proto->queue.num, type, len);
            debugdump(data, len);

            intr_raise_irq(INTR_IRQ_SOFTIRQ);

            return 0;
        }
    }

    // unsupported protocol
    return 0;
}

int net_softirq_handler(void)
{
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;

    for (proto = protocols; proto; proto = proto->next)
    {
        while (1)
        {
            entry = queue_pop(&proto->queue);
            if (!entry)
            {
                break;
            }

            debugf("queue poped (num:%u), dev=%s, type=0x%04x, len=%zu", proto->queue.num, entry->dev->name, proto->type, entry->len);
            debugdump(entry->data, entry->len);

            proto->handler(entry->data, entry->len, entry->dev);
            memory_free(entry);
        }
    }

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

    if (ip_init() == -1)
    {
        errorf("ip_init() failed.");
        return -1;
    }

    infof("initialized");
    return 0;
}