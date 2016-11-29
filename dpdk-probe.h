#ifndef __DPDK_PROBE_H___
#define __DPDK_PROBE_H___

#define WEKA_POOL_OPS "WEKA_stack_pool_ops"

struct rte_mempool *weka_init_mbuf_pool(uint32_t size, uint32_t align,
        uint32_t data_room_size, uint32_t priv_size, uint32_t cache_size, int socket_id,
        const char *pool_name, const char *pool_ops_name);


#endif /** __DPDK_PROBE_H___ */
