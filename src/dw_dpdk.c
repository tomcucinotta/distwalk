#include "dw_dpdk.h"

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

#define MBUF_POOL_NAME      "MBUF_POOL"
#define NUM_MBUFS           8191        // 2^n - 1 (per queue)
#define MBUF_CACHE_SIZE     250
#define MBUF_PRIV_SIZE      0
#define RX_RING_SIZE        1024
#define TX_RING_SIZE        1024
#define DW_ETHERTYPE        0x88B5      // IEEE Local Experimental Ethertype 1

static int num_queues = 1;

static struct rte_mempool *mbuf_pool = NULL;
static uint16_t dpdk_port = 0;
static struct rte_ether_addr port_local_mac;

static int port_init(uint16_t port_id, struct rte_ether_addr *out_mac) {
    int ret;
    struct rte_eth_conf port_conf = {0};
    uint16_t nb_rxd = RX_RING_SIZE, nb_txd = TX_RING_SIZE;

    if (!rte_eth_dev_is_valid_port(port_id))
        return -1;

    ret = rte_eth_dev_configure(port_id, num_queues, num_queues, &port_conf);
    if (ret != 0) {
        fprintf(stderr, "[DPDK] Cannot configure port %u\n", port_id);
        return ret;
    }

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    if (ret != 0) {
        fprintf(stderr, "[DPDK] Cannot adjust descriptors for port %u\n", port_id);
        return ret;
    }

    for (int q = 0; q < num_queues; q++) {
        ret = rte_eth_rx_queue_setup(port_id, q, nb_rxd,
                                      rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
        if (ret < 0) {
            fprintf(stderr, "[DPDK] Cannot setup RX queue %d for port %u\n", q, port_id);
            return ret;
        }
    }

    for (int q = 0; q < num_queues; q++) {
        ret = rte_eth_tx_queue_setup(port_id, q, nb_txd,
                                      rte_eth_dev_socket_id(port_id), NULL);
        if (ret < 0) {
            fprintf(stderr, "[DPDK] Cannot setup TX queue %d for port %u\n", q, port_id);
            return ret;
        }
    }

    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        fprintf(stderr, "[DPDK] Cannot start port %u: %s\n", port_id, rte_strerror(-ret));
        return -1;
    }

    ret = rte_eth_macaddr_get(port_id, out_mac);
    if (ret < 0) {
        fprintf(stderr, "[DPDK] Cannot get MAC for port %u: %s\n", port_id, rte_strerror(-ret));
        rte_eth_dev_stop(port_id);
        return -1;
    }

    return 0;
}

int dpdk_init(const dpdk_config_t *config) {
    int ret;

    if (!config) {
        fprintf(stderr, "[DPDK] Invalid config\n");
        return -1;
    }

    if (!config->iface && !config->pci) {
        fprintf(stderr, "[DPDK] Need either iface or pci\n");
        return -1;
    }

    num_queues = config->num_queues > 0 ? config->num_queues : 1;

    int eal_argc = 0;
    char *eal_args[20];
    char fp_arg[64];
    char dev_arg[256];
    char lcore_arg[256];
    char mem_arg[16];

    // build lcore list string from core_list
    int off = 0;
    for (int i = 0; i < config->num_cores; i++) {
        if (i > 0)
            lcore_arg[off++] = ',';
        off += snprintf(lcore_arg + off, sizeof(lcore_arg) - off, "%d", config->core_list[i]);
    }
    if (off == 0)
        snprintf(lcore_arg, sizeof(lcore_arg), "0");

    eal_args[eal_argc++] = "dw";
    eal_args[eal_argc++] = "-l";
    eal_args[eal_argc++] = lcore_arg;
    snprintf(fp_arg, sizeof(fp_arg), "--file-prefix=dw_%d", getpid());
    eal_args[eal_argc++] = fp_arg;

    if (config->pci) {
        eal_args[eal_argc++] = "-a";
        eal_args[eal_argc++] = (char*)config->pci;
        printf("[DPDK] PCI mode: %s\n", config->pci);
    } else {
        eal_args[eal_argc++] = "--no-pci";
        eal_args[eal_argc++] = "--no-huge";
        // num_nbufs * mbuf_size = 8191 * ~2.3KB ~ 19MB (+ mempool overhead)
        int mem_mb = 64 * num_queues;
        snprintf(mem_arg, sizeof(mem_arg), "%d", mem_mb);
        eal_args[eal_argc++] = "-m";
        eal_args[eal_argc++] = mem_arg;
        snprintf(dev_arg, sizeof(dev_arg),
                 "--vdev=net_af_packet0,iface=%s,qpairs=%d,qdisc_bypass=1",
                 config->iface, num_queues);
        eal_args[eal_argc++] = dev_arg;
        printf("[DPDK] af_packet mode: %s\n", config->iface);
    }

    eal_args[eal_argc] = NULL;

    ret = rte_eal_init(eal_argc, eal_args);
    if (ret < 0) {
        fprintf(stderr, "[DPDK] Error with EAL initialization\n");
        return -1;
    }

    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 1) {
        fprintf(stderr, "[DPDK] Need at least 1 port, found %u\n", nb_ports);
        rte_eal_cleanup();
        return -1;
    }

    mbuf_pool = rte_pktmbuf_pool_create(
        MBUF_POOL_NAME,
        NUM_MBUFS * num_queues,
        MBUF_CACHE_SIZE,
        MBUF_PRIV_SIZE,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id()
    );
    if (mbuf_pool == NULL) {
        fprintf(stderr, "[DPDK] Cannot create mbuf pool (count=%d): %s\n",
                NUM_MBUFS * num_queues, rte_strerror(rte_errno));
        rte_eal_cleanup();
        return -1;
    }

    dpdk_port = 0; // each distwalk entity owns 1 port
    if (port_init(dpdk_port, &port_local_mac) < 0) {
        rte_eal_cleanup();
        return -1;
    }

    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             port_local_mac.addr_bytes[0], port_local_mac.addr_bytes[1],
             port_local_mac.addr_bytes[2], port_local_mac.addr_bytes[3],
             port_local_mac.addr_bytes[4], port_local_mac.addr_bytes[5]);

    printf("[DPDK] Ready: %s (MAC: %s)\n",
           config->pci ? config->pci : config->iface, mac_str);

    return 0;
}

void dpdk_cleanup(void) {
    rte_eth_dev_stop(dpdk_port);
    rte_eth_dev_close(dpdk_port);
    rte_eal_cleanup();
    mbuf_pool = NULL;
}
