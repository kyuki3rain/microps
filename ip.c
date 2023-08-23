#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

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

const ip_addr_t IP_ADDR_ANY = 0x00000000;       // 0.0.0.0
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; // 255.255.255.255

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
    uint8_t *u8 = (uint8_t *)&n;
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

    fprintf(stderr, "                 id: 0x%04x\n", ntoh16(hdr->id));

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

static void
ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip_hdr *hdr;
    uint8_t version;
    uint16_t hdr_len, total_len, offset;

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

    debugf("dev=%s, protocol=%u, total=%u", dev->name, hdr->protocol, total_len);
    ip_dump(data, len);
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