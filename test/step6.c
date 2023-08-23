#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"

#include "driver/loopback.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s)
{
    (void)s;
    terminate = 1;
}

int main(int argc, char *argv[])
{
    struct net_device *dev;

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

    // プロトコルスタックの起動
    if (net_run() != 0)
    {
        errorf("net_run() failed");
        return -1;
    }

    while (!terminate)
    {
        if (net_device_output(dev, NET_PROTOCOL_TYPE_IP, test_data, sizeof(test_data), NULL) != 0)
        {
            errorf("net_device_output() failed");
            return -1;
        }
        sleep(1);
    }
}