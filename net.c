#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "platform.h"

#include "util.h"
#include "net.h"

static struct net_device *devices;

struct net_device *net_device_alloc(void)
{
}

int net_device_register(struct net_device *dev)
{
}

static int net_device_open(struct net_device *dev)
{
}

static int net_device_close(struct net_device *dev)
{
}

int net_device_output(struct net_device *dev, const void *data, size_t len, const void *dst)
{
}

int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
}

int net_run(void)
{
}

void net_shutdown(void)
{
}

int net_init(void)
{
}