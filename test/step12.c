#include <stdio.h>
#include <signal.h>
#include <stddef.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s)
{
    (void)s;
    terminate = 1;
}

static int setup(void)
{
    struct net_device *dev;
    struct ip_iface *iface;

    signal(SIGINT, on_signal);

    // プロトコルスタックの初期化
    if (net_init() != 0)
    {
        errorf("net_init() failed");
        return -1;
    }

    // ダミーのネットワークデバイスを作成
    dev = loopback_init();
    if (!dev)
    {
        errorf("loopback_init() failed");
        return -1;
    }

    // IPアドレスを設定
    iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface)
    {
        errorf("ip_iface_alloc() failed");
        return -1;
    }

    // ネットワークデバイスにIPアドレスを登録
    if (ip_iface_register(dev, iface) != 0)
    {
        errorf("ip_iface_register() failed");
        return -1;
    }

    // イーサネットデバイスを作成
    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev)
    {
        errorf("ether_tap_init() failed");
        return -1;
    }

    // IPアドレスを設定
    iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface)
    {
        errorf("ip_iface_alloc() failed");
        return -1;
    }

    // ネットワークデバイスにIPアドレスを登録
    if (ip_iface_register(dev, iface) != 0)
    {
        errorf("ip_iface_register() failed");
        return -1;
    }

    // プロトコルスタックの起動
    if (net_run() != 0)
    {
        errorf("net_run() failed");
        return -1;
    }

    return 0;
}

static void cleanup(void)
{
    net_shutdown();
}

int main(int argc, char *argv[])
{
    signal(SIGINT, on_signal);
    if (setup() != 0)
    {
        errorf("setup() failed");
        return -1;
    }

    while (!terminate)
    {
        sleep(1);
    }
    cleanup();
}