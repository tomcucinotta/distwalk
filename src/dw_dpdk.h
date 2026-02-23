#ifndef __DW_DPDK_H__
#define __DW_DPDK_H__

#define RX_BURST_SIZE 32
#define TX_BURST_SIZE 32

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *iface;         // af_packet interface (e.g., "veth0")
    const char *pci;           // PCI address (e.g., "0000:04:02.0"), alternative to iface
    int *core_list;            // array of core IDs for EAL lcore list
    int num_cores;             // length of core_list
    int num_queues;            // number of RX/TX queue pairs (node: 1 per worker, client: always 1)
} dpdk_config_t;

int dpdk_init(const dpdk_config_t *config);
void dpdk_cleanup(void);

#endif
