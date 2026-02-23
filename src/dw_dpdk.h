#ifndef __DW_DPDK_H__
#define __DW_DPDK_H__

#define RX_BURST_SIZE 32
#define TX_BURST_SIZE 32

#include <stddef.h>
#include <stdint.h>
#include <rte_mbuf.h>

typedef struct {
    const char *iface;         // af_packet interface (e.g., "veth0")
    const char *pci;           // PCI address (e.g., "0000:04:02.0"), alternative to iface
    int *core_list;            // array of core IDs for EAL lcore list
    int num_cores;             // length of core_list
    int num_queues;            // number of RX/TX queue pairs (node: 1 per worker, client: always 1)
} dpdk_config_t;

int dpdk_init(const dpdk_config_t *config);
void dpdk_cleanup(void);
uint16_t dpdk_get_port(void);

void *dpdk_get_payload_ptr(struct rte_mbuf *mbuf);
void dpdk_set_payload_len(struct rte_mbuf *mbuf, size_t len);
void dpdk_extract_src_mac(struct rte_mbuf *mbuf, uint8_t *mac);

struct rte_mbuf *dpdk_alloc_tx_mbuf(const uint8_t *dest_mac);

int dpdk_is_dw_packet(struct rte_mbuf *mbuf);

void dpdk_flush_tx(struct rte_mbuf **mbufs, uint16_t *count, uint16_t queue_id);

#endif
