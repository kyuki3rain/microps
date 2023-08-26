#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"

struct ip_hdr
{
    uint8_t version_ihl;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    ip_addr_t source;
    ip_addr_t destination;
    uint8_t options[];
};

struct ip_protocol
{
    struct ip_protocol *next;
    uint8_t type;
    void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface);
};

const ip_addr_t IP_ADDR_ANY = 0x00000000;       // 0.0.0.0
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; // 255.255.255.255

static struct ip_iface *ifaces;
static struct ip_protocol *protocols;

// IPアドレスを文字列に変換する
int ip_addr_pton(const char *p, ip_addr_t *n)
{
    char *sp, *ep; // start pointer, end pointer
    int idx;
    long ret;

    sp = (char *)p;
    for (idx = 0; idx < 4; idx++)
    {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255)
        {
            return -1;
        }
        if (ep == sp)
        {
            return -1;
        }
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.'))
        {
            return -1;
        }
        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1;
    }

    return 0;
}

// 文字列をIPアドレスに変換する
char *ip_addr_ntop(const ip_addr_t *n, char *p, size_t size)
{
    uint8_t *u8 = (uint8_t *)n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return p;
}

static void ip_dump(const uint8_t *data, size_t len)
{
    struct ip_hdr *hdr;
    uint8_t version, ihl, hdr_len, flags;
    uint16_t total_len, offset;
    char addr[IP_ADDR_STR_LEN];

    flockfile(stderr);
    hdr = (struct ip_hdr *)data;

    version = hdr->version_ihl >> 4;
    ihl = hdr->version_ihl & 0x0f;
    hdr_len = ihl * 4;
    fprintf(stderr, "            version: %u\n", version);
    fprintf(stderr, "      header_length: %u (%u)\n", ihl, hdr_len);

    fprintf(stderr, "    type_of_service: 0x%02x\n", hdr->type_of_service);

    total_len = ntoh16(hdr->total_length);
    fprintf(stderr, "       total_length: %u (payload: %u)\n", total_len, total_len - hdr_len);

    fprintf(stderr, "                 id: %u\n", ntoh16(hdr->id));

    offset = ntoh16(hdr->flags_fragment_offset);
    flags = (offset & 0xe000) >> 13;
    offset = offset & 0x1fff;
    fprintf(stderr, "              flags: 0x%02x, fragment_offset: %u\n", flags, offset);

    fprintf(stderr, "       time_to_live: %u\n", hdr->time_to_live);
    fprintf(stderr, "           protocol: %u\n", hdr->protocol);
    fprintf(stderr, "    header_checksum: 0x%04x\n", ntoh16(hdr->header_checksum));
    fprintf(stderr, "             source: %s\n", ip_addr_ntop(&hdr->source, addr, sizeof(addr)));
    fprintf(stderr, "        destination: %s\n", ip_addr_ntop(&hdr->destination, addr, sizeof(addr)));

#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif

    funlockfile(stderr);
}

struct ip_iface *ip_iface_alloc(const char *unicast, const char *netmask)
{
    struct ip_iface *iface;

    iface = memory_alloc(sizeof(*iface));
    if (iface == NULL)
    {
        errorf("memory_alloc() failed");
        return NULL;
    }

    // ip_ifaceのメンバの先頭はnet_ifaceであるため、net_ifaceとみなせば更新ができる
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;

    if (ip_addr_pton(unicast, &iface->unicast) != 0)
    {
        memory_free(iface);

        errorf("ip_addr_pton() failed, unicast=%s", unicast);
        return NULL;
    }

    if (ip_addr_pton(netmask, &iface->netmask) != 0)
    {
        memory_free(iface);

        errorf("ip_addr_pton() failed, netmask=%s", netmask);
        return NULL;
    }

    iface->broadcast = iface->unicast | ~iface->netmask;

    return iface;
}

int ip_iface_register(struct net_device *dev, struct ip_iface *iface)
{
    char addr1[IP_ADDR_STR_LEN], addr2[IP_ADDR_STR_LEN], addr3[IP_ADDR_STR_LEN];

    if (net_device_add_iface(dev, NET_IFACE(iface)) != 0)
    {
        errorf("net_device_add_iface() failed");
        return -1;
    }

    iface->next = ifaces;
    ifaces = iface;

    infof("registerd: dev=%s, unicast=%s, netmask=%s, broadcast=%s", dev->name,
          ip_addr_ntop(&iface->unicast, addr1, sizeof(addr1)),
          ip_addr_ntop(&iface->netmask, addr2, sizeof(addr2)),
          ip_addr_ntop(&iface->broadcast, addr3, sizeof(addr3)));

    return 0;
}

struct ip_iface *ip_iface_select(ip_addr_t addr)
{
    struct ip_iface *iface;

    for (iface = ifaces; iface; iface = iface->next)
    {
        if ((addr & iface->netmask) == (iface->unicast & iface->netmask))
        {
            return iface;
        }
    }

    return NULL;
}

int ip_protocol_register(uint8_t type, void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface))
{
    struct ip_protocol *entry;

    for (entry = protocols; entry; entry = entry->next)
    {
        if (entry->type == type)
        {
            errorf("ip_protocol is already registered, type=0x%04x", type);
            return -1;
        }
    }

    entry = memory_alloc(sizeof(entry));
    if (entry == NULL)
    {
        errorf("memory_alloc() failed");
        return -1;
    }

    entry->type = type;
    entry->handler = handler;
    entry->next = protocols;
    protocols = entry;

    infof("registered, type=%u", entry->type);
    return 0;
}

static void ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip_hdr *hdr;
    uint8_t version;
    uint16_t hdr_len, total_len, offset;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    struct ip_protocol *proto;

    if (len < IP_HDR_SIZE_MIN)
    {
        errorf("too short, len=%u", len);
        return;
    }

    hdr = (struct ip_hdr *)data;

    version = hdr->version_ihl >> 4;
    if (version != IP_VERSION_IPV4)
    {
        errorf("invalid version, version=%u", version);
        return;
    }

    hdr_len = (hdr->version_ihl & 0x0f) * 4;
    if (hdr_len > len)
    {
        errorf("too short, hdr_len=%u, len=%u", hdr_len, len);
        return;
    }

    total_len = ntoh16(hdr->total_length);
    if (total_len > len)
    {
        errorf("too short, total_len=%u, len=%u", total_len, len);
        return;
    }

    if (cksum16((uint16_t *)hdr, hdr_len, 0) != 0)
    {
        errorf("checksum error");
        return;
    }

    offset = ntoh16(hdr->flags_fragment_offset);
    if (offset & 0x2000 || offset & 0x1fff)
    {
        errorf("fragment is not supported");
        return;
    }

    iface = (struct ip_iface *)net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (iface == NULL)
    {
        errorf("no ip interface");
        return;
    }

    if (hdr->destination == IP_ADDR_BROADCAST)
    {
        debugf("dev=%s, protocol=%u, total=%u", dev->name, hdr->protocol, total_len);
        ip_dump(data, len);
        return;
    }

    if (iface->unicast != hdr->destination && iface->broadcast != hdr->destination)
    {
        debugf("not my address, dev=%s, protocol=%u, total=%u", dev->name, hdr->protocol, total_len);
        ip_dump(data, len);
        return;
    }

    debugf("dev=%s, iface=%s, protocol=%u, total=%u", dev->name, ip_addr_ntop(&iface->unicast, addr, sizeof(addr)), hdr->protocol, total_len);
    ip_dump(data, len);

    for (proto = protocols; proto; proto = proto->next)
    {
        if (hdr->protocol == proto->type)
        {
            proto->handler(data + hdr_len, total_len - hdr_len, hdr->source, hdr->destination, iface);
            return;
        }
    }

    // unsupported protocol
}

static int ip_output_device(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t dst)
{
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};

    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP)
    {
        if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST)
        {
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_DEVICE_ADDR_LEN);
        }
        else
        {
            errorf("arp doesn't support");
            return -1;
        }
    }

    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data, len, hwaddr);
}

static ssize_t ip_output_core(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, uint16_t id, uint16_t offset)
{
    uint8_t buf[IP_TOTAL_SIZE_MAX];
    struct ip_hdr *hdr;
    uint16_t header_length, total;
    char addr[IP_ADDR_STR_LEN];

    hdr = (struct ip_hdr *)buf;

    header_length = IP_HDR_SIZE_MIN;
    hdr->version_ihl = (IP_VERSION_IPV4 << 4) | (header_length / 4);

    total = header_length + len;
    hdr->total_length = hton16(total);

    hdr->id = hton16(id);
    hdr->flags_fragment_offset = hton16(offset);
    hdr->flags_fragment_offset |= hton16(0x4000); // Don't Fragment
    hdr->time_to_live = 255;
    hdr->protocol = protocol;
    hdr->source = src;
    hdr->destination = dst;
    hdr->header_checksum = 0;
    hdr->header_checksum = cksum16((uint16_t *)hdr, IP_HDR_SIZE_MIN, 0);

    memcpy(buf + IP_HDR_SIZE_MIN, data, len);

    debugf("dev=%s, dst=%s, protocol=%u, len=%u", NET_IFACE(iface)->dev->name, ip_addr_ntop(&dst, addr, sizeof(addr)), protocol, len);
    ip_dump(buf, total);

    return ip_output_device(iface, buf, total, dst);
}

static uint16_t ip_generate_id(void)
{
    static mutex_t mutex = MUTEX_INITIALIZER;
    static uint16_t id = 128;
    uint16_t ret;

    mutex_lock(&mutex);
    ret = id++;
    mutex_unlock(&mutex);

    return ret;
}

ssize_t ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    uint16_t id;

    if (src == IP_ADDR_ANY)
    {
        errorf("ip routing is not supported");
        return -1;
    }
    else
    {
        iface = ip_iface_select(src);
        if (iface == NULL)
        {
            errorf("no interface, src=%s", ip_addr_ntop(&src, addr, sizeof(addr)));
            return -1;
        }

        if (dst != IP_ADDR_BROADCAST && (dst & iface->netmask) != (iface->unicast & iface->netmask))
        {
            // 到達不能
            errorf("no route, src=%s, dst=%s", ip_addr_ntop(&src, addr, sizeof(addr)), ip_addr_ntop(&dst, addr, sizeof(addr)));
            return -1;
        }
    }

    if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len)
    {
        errorf("too large, dev=%s, mtu=%u, len=%u", NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
        return -1;
    }

    id = ip_generate_id();
    if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, id, 0) == -1)
    {
        errorf("ip_output_core() failed");
        return -1;
    }

    return len;
}

int ip_init(void)
{
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1)
    {
        errorf("net_protocol_register() failed.");
        return -1;
    }

    return 0;
}