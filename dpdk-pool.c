/*
 * dpdk-mempool.c
 *
 *  Created on: Aug 16, 2016
 *      Author: garik
 */
#include <unistd.h>
#include <stddef.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "dpdk-probe.h"

static void weka_pktmbuf_init(struct rte_mempool *mp,
         __attribute__((unused)) void *opaque_arg,
         void *_m,
         __attribute__((unused)) unsigned i)
{
    struct rte_mbuf *m = _m;
    uint32_t mbuf_size, buf_len, priv_size;

    priv_size = rte_pktmbuf_priv_size(mp);
    mbuf_size = sizeof(struct rte_mbuf) + priv_size;
    buf_len = rte_pktmbuf_data_room_size(mp);

    RTE_ASSERT(RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) == priv_size);
    RTE_ASSERT(mp->elt_size >= mbuf_size);
    RTE_ASSERT(buf_len <= UINT16_MAX);
    RTE_ASSERT((uintptr_t)m & (mp->elt_align - 1));

    //void *next = m->next;
    //memset(m, 0, mp->elt_size);
    //m->next = next;
    memset(m, 0, sizeof(struct rte_mbuf));

    /* start of buffer is after mbuf structure and priv data */
    m->priv_size = priv_size;
    m->buf_addr = (char *)m + mbuf_size;
    m->buf_physaddr = rte_mempool_virt2phy(mp, m) + mbuf_size;
    m->buf_len = (uint16_t)buf_len;

    /* keep some headroom between start of buffer and data */
    m->data_off = RTE_MIN(RTE_PKTMBUF_HEADROOM, (uint16_t)m->buf_len);

    /* init some constant fields */
    m->pool = mp;
    m->nb_segs = 1;
    m->port = 0xff;
}

struct rte_mempool *weka_init_mbuf_pool(uint32_t size, uint32_t align,
        uint32_t data_room_size, uint32_t priv_size, uint32_t cache_size, int socket_id,
        const char *pool_name, const char *pool_ops_name)
{

    struct rte_pktmbuf_pool_private mbp_priv = {
        .mbuf_data_room_size = data_room_size,
        .mbuf_priv_size = priv_size
    };

    if (RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) != priv_size) {
        RTE_LOG(ERR, MBUF, "mbuf priv_size=%u is not aligned\n",
            priv_size);
        rte_errno = EINVAL;
        return NULL;
    }
    uint32_t elt_size = sizeof(struct rte_mbuf) + priv_size + data_room_size;

    struct rte_mempool *mp = rte_mempool_create_empty(pool_name, size, elt_size, cache_size,
         sizeof(struct rte_pktmbuf_pool_private), socket_id, 0);
    if (mp == NULL)
        return NULL;

    rte_errno = rte_mempool_set_ops_byname(mp, pool_ops_name, NULL);
    if (rte_errno != 0) {
        RTE_LOG(ERR, MBUF, "error setting mempool handler\n");
        return NULL;
    }
    rte_pktmbuf_pool_init(mp, &mbp_priv);
	mp->elt_align = align;

    int ret = rte_mempool_populate_default(mp);
    if (ret < 0) {
        rte_mempool_free(mp);
        rte_errno = -ret;
        return NULL;
    }

    rte_mempool_obj_iter(mp, weka_pktmbuf_init, NULL);
    rte_mempool_list_dump(stdout);

    return mp;
}
