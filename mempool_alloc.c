#include <stdlib.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_eal_memconfig.h>
#include <rte_errno.h>


#define MEMPOOL_HEADER_SZ (64)
#define DATA_SZ           (1<<12)
#define HEADER_SZ         (512)
#define EXPECTED_PROTO_SZ 90
#define MBUF_SZ			(DATA_SZ + HEADER_SZ * 2)
#define MAX_PACKET_SZ (MBUF_SZ - MEMPOOL_HEADER_SZ)

static int is_all_data_aligned = 1;
static char * last_end_pointer = NULL;

static void my_mbuf_mempool_obj_init(struct rte_mempool * mp, void * opaque_arg, void * _mbuf, unsigned index)
{
    struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
    if (((uintptr_t)_mbuf < mcfg->pfaddr) || ((uintptr_t)_mbuf >= mcfg->pladdr)) {
                printf("wrong buffer[%u] address %p. mp %p\n", index, _mbuf, mp);
    }

    rte_pktmbuf_init(mp, opaque_arg, _mbuf, index);
    // Now make sure that the data is indeed aligned to 512.
    struct rte_mbuf * mbuf = _mbuf;
    if (0 != (rte_pktmbuf_mtod(mbuf, unsigned long) + EXPECTED_PROTO_SZ) % 512) {
        printf("init of %d mbuf, data offset for 512 is %lu data ptr is %p "
                   "mbuf ptr is %p mbuf offset is %lu\n",
                   index, (rte_pktmbuf_mtod(mbuf, unsigned long) + EXPECTED_PROTO_SZ) % 512,
                   rte_pktmbuf_mtod(mbuf, char *), mbuf,
                   ((unsigned long)mbuf) % 512);
        is_all_data_aligned = 0;
    }
    // Now check what the beginning of the 4k data and the end of the 4k data all fit within the same 2M page.
    //mbuf->tx_offload = EthernetHeader.sizeof | (IPv4Header.sizeof << 7);
    mbuf->tx_offload = (14) | (20 << 7);
    mbuf->ol_flags = PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
    char * data_start = rte_pktmbuf_mtod(mbuf, char *) + EXPECTED_PROTO_SZ;
    char * data_end = data_start + 4096;
    char * page_start = (char *)((unsigned long)data_start >> 21);
    char * page_end = (char *)((unsigned long)data_end >> 21);
    if (page_start != page_end) {
        printf("init of %d mbuf at %p, data start is %p, data end is %p, ended up in different pages %p != %p\n",
                   index, mbuf, data_start, data_end, page_start, page_end);
        is_all_data_aligned = 0;
    }

    if (rte_pktmbuf_mtod(mbuf, char *) <= last_end_pointer) {
        printf("init of %d mbuf at %p ended up inside of previous mbuf!!! data_start %p data_end %p last_end %p\n",
                   index, mbuf, data_start, data_end, last_end_pointer);
        is_all_data_aligned = 0;
    }

    last_end_pointer = data_end;

    // Now, we'll also zero the mbufs, so we don't have to do it each time
    void * netbuf = rte_mbuf_to_baddr(_mbuf);
    memset(netbuf, 0, 88);
}


static inline int  is_memseg_valid(struct rte_memseg * free_memseg, size_t requested_page_size,
                                   int socket_id)
{
        if (free_memseg->len == 0) {
                return 0;
        }

        if (socket_id != SOCKET_ID_ANY &&
            free_memseg->socket_id != SOCKET_ID_ANY &&
            free_memseg->socket_id != socket_id) {
                printf("memseg goes not qualify for socked_id, requested %d got %d\n",
                         socket_id, free_memseg->socket_id);
                return 0;
        }

        if (free_memseg->len < requested_page_size) {
                printf("memseg too small. len %lu < requested_page_size %lu\n",
                         free_memseg->len, requested_page_size);
                return 0;
        }


        if (free_memseg->hugepage_sz != requested_page_size) {
                printf("memset hugepage size != requested page size %lu != %lu",
                         free_memseg->hugepage_sz,
                         requested_page_size);
                return 0;
        }

        return 1;
}


static inline void build_physical_pages(phys_addr_t * phys_pages, int num_phys_pages, size_t sz,
                                        struct rte_memseg *memseg, int num_seg)
{
        size_t accounted_for_size =0;
        int curr_page = 0;
        int i;
        uint64_t j;

        printf("Phys pages are at %p 2M is %d mz pagesize is %lu trailing zeros: %d\n",
                 phys_pages, RTE_PGSIZE_2M, memseg->hugepage_sz, __builtin_ctz(memseg->hugepage_sz));

        for (i = 0; i < num_seg; i++) {
                size_t mz_remaining_len = memseg[i].len; 
                for (j = 0; (j <= memseg[i].len / RTE_PGSIZE_2M) && (0 < mz_remaining_len) ; j++) {
                        phys_pages[curr_page++] = memseg[i].phys_addr + j * RTE_PGSIZE_2M;

                        size_t added_len = RTE_MIN((size_t)RTE_PGSIZE_2M, mz_remaining_len);
                        accounted_for_size += added_len;
                        mz_remaining_len -= added_len;

                        if (sz <= accounted_for_size) {
                                printf("Filled in %d pages of the physical pages array\n", curr_page);
                                return;
                        }
                        if (num_phys_pages < curr_page) {
                                printf("When building physcial pages array, "
                                           "used pages (%d) is more than allocated pages %d. "
                                           "accounted size %lu size %lu\n",
                                           curr_page, num_phys_pages, accounted_for_size, sz);
                                abort();
                        }
                }
        }

        if (accounted_for_size < sz) {
                printf("Finished going over %d memory zones, and still accounted size is %lu "
                           "and requested size is %lu\n",
                           num_seg, accounted_for_size, sz);
                abort();
        }
}


#define MEMPOOL_FLAGS (MEMPOOL_F_NO_SPREAD|MEMPOOL_F_SC_GET|MEMPOOL_F_SP_PUT)

static void calc_mempool_requirements(size_t * sz, uint32_t * pages_num, uint32_t elt_size, uint32_t elt_num) 
{
    struct rte_mempool_objsz    obj_sz;
    uint64_t total_size;
    total_size = rte_mempool_calc_obj_size(elt_size - MEMPOOL_HEADER_SZ, MEMPOOL_FLAGS, &obj_sz);

    *sz = elt_num * total_size;
    /* We now have to account for the "gaps" at the end of each page. Worst case is that we get
     * all distinct pages, so we have to add the gap for each possible page. */
    *pages_num = (*sz + RTE_PGSIZE_2M -1) / RTE_PGSIZE_2M;
    int page_gap = RTE_PGSIZE_2M % total_size;
    // Also account for extra pages added by the many possible gaps.
    *sz += (*pages_num + (*pages_num + 1)* page_gap /RTE_PGSIZE_2M )* page_gap;
    *pages_num = (*sz + RTE_PGSIZE_2M -1) / RTE_PGSIZE_2M;
    printf("mempool: elt_size %u elt_num %u nr pages %u total size %lu\n",
              elt_size, elt_num, *pages_num, *sz);
}

static struct rte_mempool *scattered_mempool_create(const char * name, uint32_t elt_size, uint32_t elt_num, unsigned cache_size,
                                             int32_t socket_id,
                                             rte_mempool_ctor_t *mp_init, void *mp_init_arg,
                                             rte_mempool_obj_ctor_t *obj_init, void *obj_init_arg)
{
        struct rte_mempool		*mp;
        size_t		sz;
        uint pages_num;

        calc_mempool_requirements(&sz, &pages_num, elt_size + MEMPOOL_HEADER_SZ, elt_num);
        struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
        size_t reserved_mem = mcfg->memseg[0].addr_64 - mcfg->priv_memseg[0].addr_64;
        if (reserved_mem < sz) {
                printf("not enough reserved memory: need %lu have %lu\n",
                           sz, reserved_mem);
                abort();
        }

        printf("Mempool %s with elt_size %u num %u. Will have to allocate %u 2M pages for the page table.\n",
                 name, elt_size, elt_num, pages_num);

        // Now will "break" the pages into smaller ones
        phys_addr_t * phys_pages = malloc(sizeof(phys_addr_t)*pages_num);
        if(phys_pages == NULL) {
            printf("phys_pages is null. aborting\n");
            abort();
        }
        cache_size = 0; // Lets see what happens with cache of size 0
        build_physical_pages(phys_pages, pages_num, sz, mcfg->priv_memseg, mcfg->privseg_cnt); 
        printf("Beginning of vaddr is %p beginning of physical addr is 0x%lx\n", mcfg->memseg->addr, mcfg->memseg->phys_addr);
        mp = rte_mempool_xmem_create(name, elt_num, elt_size,
                                     cache_size, sizeof(struct rte_pktmbuf_pool_private),
                                     mp_init, mp_init_arg, obj_init, obj_init_arg,
                                     socket_id, MEMPOOL_FLAGS, (char *)mcfg->priv_memseg->addr,
                                     phys_pages, pages_num, rte_bsf32(RTE_PGSIZE_2M));

        printf("rte_mempool_xmem_create returned %p for socket_id %d\n", mp, socket_id);
        if (NULL != mp) {
            return mp;
        }

        printf("rte_mempool_xmem_create failed for socket %d will try with SOCKET_ID_ANY\n", socket_id);
        mp = rte_mempool_xmem_create(name, elt_num, elt_size,
                                     cache_size, sizeof(struct rte_pktmbuf_pool_private),
                                     mp_init, mp_init_arg, obj_init, obj_init_arg,
                                     SOCKET_ID_ANY, MEMPOOL_FLAGS, (char *)mcfg->priv_memseg->addr,
                                     phys_pages, pages_num, rte_bsf32(RTE_PGSIZE_2M));
        printf("rte_mempool_xmem_create returned %p for SOCKET_ID_ANY\n", mp);
        return mp;

}

struct rte_mempool *pools_init(uint32_t mbuf_count);
struct rte_mempool *pools_init(uint32_t mbuf_count) 
{
    struct rte_pktmbuf_pool_private mbp_priv = {
            .mbuf_data_room_size = MBUF_SZ + RTE_PKTMBUF_HEADROOM,
            .mbuf_priv_size      = 0
    };
     
    return scattered_mempool_create("WEKA MBUF Pool", MAX_PACKET_SZ, mbuf_count,  257, rte_socket_id(),
                                   rte_pktmbuf_pool_init, &mbp_priv,
                                   my_mbuf_mempool_obj_init, NULL);

}

