

#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <inttypes.h>
#include <byteswap.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_timer.h>
#include <rte_hexdump.h>
#include <rte_common.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <getopt.h>
#include <time.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define MBUF_SIZE (6 * 1024)
#define NUM_MBUFS (500 * 1024)
#define MBUF_CACHE_SIZE 0
#define BURST_SIZE 128
#define MAX_LOCAL_PORTS 4
#define MAX_PEERS 128
#define MAX_FRAME_SIZE ((MBUF_SIZE) - 512)
#define DEFAULT_UDP_FRAME_SIZE 128
#define DEFAULT_UPD_PORT 3103
#define MAX_ROCE_ARGS 32

#define MAX_RESOLVE_COUNT	5

#define DEBUG 0

enum op_modes {
	MODE_NONE = 0,
	MODE_UDP,
	MODE_ICMP,
	MODE_ROCE,
	MODES_NUM
};

struct packet {
    uintptr_t port_id;
    struct rte_mbuf *mbuf;
    void *l2, *l3, *l4;
};

struct port_addr {
    struct ether_addr ethernet;
    struct in_addr    ip;
};

struct port_device {
    struct port_addr addr;
    struct rte_eth_conf eth_conf;
    struct rte_eth_dev_info dev_info;
};

enum data_ops_e {
    OP_REQUEST = 0xfa,
    OP_RESPONSE = 0xda,
};

struct peer {
#define PEER_HAS_MAC    1
    struct port_addr addr;
    uint64_t flags;
    struct rte_timer tm;
    struct rte_timer stat_tm;
    enum data_ops_e tm_op;
    uint64_t sequence;
    uint64_t requests_out_num;
    uint64_t requests_in_num;
    uint64_t responses_out_num;
    uint64_t responses_in_num;
    uint32_t resolve_count;
};

struct udp_ping_data {
    uint64_t seq;
    enum data_ops_e op;
    union {
        uint8_t   uint8_data[0];
        uint64_t  uint64_data[0];
    };
} __attribute__((__packed__));

#if 1
#define RX_DEFAULT_ETH_CONF {                                           \
        .rxmode = {                                                     \
		.max_rx_pkt_len	= 9000,                                \
		.header_split   = 0,    /* Header Split disabled */             \
		.hw_ip_checksum = 1,    /* IP checksum offload enabled */       \
		.hw_vlan_filter = 0,    /* VLAN filtering disabled */           \
		.jumbo_frame    = 1,    /* Jumbo Frame Support enabled */       \
		.hw_strip_crc   = 1,    /* CRC stripped by hardware */          \
		.hw_vlan_strip	= 1,                                            \
        },                                                              \
        .txmode = {                                                     \
                .mq_mode = ETH_MQ_TX_NONE,                              \
        },                                                              \
}
#else
#define RX_DEFAULT_ETH_CONF {                                           \
        .rxmode = {                                                     \
		.max_rx_pkt_len	= ETHER_MAX_LEN,                                \
		.header_split   = 0,    /* Header Split disabled */             \
		.hw_ip_checksum = 1,    /* IP checksum offload enabled */       \
		.hw_vlan_filter = 0,    /* VLAN filtering disabled */           \
		.jumbo_frame    = 1,    /* Jumbo Frame Support enabled */       \
		.hw_strip_crc   = 1,    /* CRC stripped by hardware */          \
		.hw_vlan_strip	= 1,                                            \
        },                                                              \
        .txmode = {                                                     \
                .mq_mode = ETH_MQ_TX_NONE,                              \
        },                                                              \
        .intr_conf = {                                                  \
            .lsc = 1,                                                   \
            .rxq = 0,                                                   \
        },                                                              \
}
#endif

static struct port_device local_ports[MAX_LOCAL_PORTS] = {
    { .eth_conf = RX_DEFAULT_ETH_CONF },
    { .eth_conf = RX_DEFAULT_ETH_CONF },
    { .eth_conf = RX_DEFAULT_ETH_CONF },
    { .eth_conf = RX_DEFAULT_ETH_CONF },
};

static struct peer peers[MAX_PEERS];

static int nb_ports = 0;
static int nb_peers = 0;
static struct rte_mempool *mbuf_pool = NULL;
static struct rte_timer tx_timer;

static int      mbuf_chain = 0;
static int      udp_jam = 0;
static int      no_dump = 0;
static int      no_dump_arp = 1;
static int      burst = 1;
static int      verify_payload = 0;
static int      unlimited = 1;
static int      rounds = 0;
static uint16_t udp_port = DEFAULT_UPD_PORT;
static uint16_t frame_size = DEFAULT_UDP_FRAME_SIZE;
static uint64_t udp_tmout = 1000000; /** 1sec */
static uint32_t peer_resolve_count = MAX_RESOLVE_COUNT;
static enum op_modes op_mode = MODE_NONE;

#define IB_CLIENT  0
#define IB_SERVER  1

static char *roce_dev;
static char *roce_guid;
static int  roce_mode = IB_SERVER;


static struct peer *find_peer_by_ip(uint32_t ip);

static void dump_arp(const struct arp_hdr *arp);

static void __idle(struct rte_timer *rte_tm, void *tm_arg);
static void resolve_peer_mac(struct rte_timer *rte_tm, void *tm_arg);
static void tm_dispatcher(struct rte_timer *rte_tm, void *tm_arg);
static void send_packets(struct rte_mbuf **mbuf, size_t burst);
static void dump_stats(struct peer *peer);

static void pkt_assemble_none(struct rte_mbuf **mbuf, struct peer *peer, enum data_ops_e op, int burst);
static void pkt_assemble_udp(struct rte_mbuf **mbuf, struct peer *peer, enum data_ops_e op, int burst);
static void pkt_assemble_icmp_request(struct rte_mbuf **mbuf, struct peer *peer, enum data_ops_e op, int burst);
static void roce_init(void);

struct rte_mempool *weka_init_mbuf_pool(uint32_t mbufs_count);

static const struct  {
	const char *name;
	void (*pkt_assemble)(struct rte_mbuf **mbuf, struct peer *peer, enum data_ops_e op, int burst);
	enum op_modes mode;
} mode_keys[MODES_NUM] = {
	{ "none", pkt_assemble_none, MODE_NONE},
	{ "udp", pkt_assemble_udp, MODE_UDP },
	{ "icmp", pkt_assemble_icmp_request, MODE_ICMP},
	{ "roce", NULL, MODE_ROCE}
};

static void show_time(const char *msg)
{
	struct timespec t;

	int x = clock_gettime(CLOCK_MONOTONIC, &t);
	if (x == -1) {
		rte_exit(EXIT_FAILURE, "%s: failed to get time\n", msg);
	}
	printf("%ld:%ld %s\n", t.tv_sec, t.tv_nsec, msg);
}

static void
signal_handler(int signum)
{
	uint8_t portid;
	uint8_t nb_ports = rte_eth_dev_count();

	/* When we receive a SIGINT signal */
	if (signum == SIGINT) {
		for (portid = 0; portid < nb_ports; portid++) {
			rte_eth_dev_close(portid);
		}
	}
	rte_exit(EXIT_SUCCESS, "\n User forced exit\n");
}

static void dump_ethernet_data(const struct ether_hdr *eth)
{
    char src_str[32], dst_str[32];
    ether_format_addr(src_str, 32, &eth->s_addr);
    ether_format_addr(dst_str, 32, &eth->d_addr);
    fprintf(stdout, "ETH[%s->%s proto %04x] ",
            src_str, dst_str, __bswap_16(eth->ether_type));

}

static void dump_ip_data(const struct rte_mbuf *mbuf,
                         const struct ipv4_hdr *ip, const char *tag)
{
    char ip_src[32], ip_dst[32];
    const struct in_addr *src_addr, *dst_addr;
    src_addr = (const struct in_addr *)&ip->src_addr;
    dst_addr = (const struct in_addr *)&ip->dst_addr;
    strcpy(ip_src, inet_ntoa(*src_addr));
    strcpy(ip_dst, inet_ntoa(*dst_addr));
    fprintf(stdout, "IP[%s->%s len %u proto %02x] ",
            ip_src, ip_dst,
            __bswap_16(ip->total_length),
            ip->next_proto_id);

    if (mbuf->ol_flags & (PKT_RX_IP_CKSUM_BAD | PKT_RX_L4_CKSUM_BAD)) {
        fprintf(stdout, "BAD RX CSUM ");
    }

    switch (ip->next_proto_id) {
        case IPPROTO_ICMP: {
            const struct icmp_hdr *icmp = mbuf_chain && mbuf->next ?
                                    (const struct icmp_hdr *)rte_pktmbuf_mtod(mbuf->next, void *) : 
                                    (const struct icmp_hdr *)(ip + 1);

            fprintf(stdout, "ICMP[%s seq %u] ",
                    icmp->icmp_type == IP_ICMP_ECHO_REQUEST ? "REQUEST" : "REPLY",
                    __bswap_16(icmp->icmp_seq_nb));
             
        }
        break;

        case IPPROTO_UDP: {
            const struct udp_hdr *udp = (const struct udp_hdr*)(ip + 1);
            const struct udp_ping_data *data = mbuf_chain && mbuf->next ?
                                                (const struct udp_ping_data *)rte_pktmbuf_mtod(mbuf->next, struct udp_ping_data *) : 
                                                (const struct udp_ping_data *)(udp + 1);

            char str_op[16];
            switch (data->op) {
                case OP_REQUEST:
                    strcpy(str_op, "REQUEST");
                    break;

                case OP_RESPONSE:
                    strcpy(str_op, "RESPONSE");
                    break;

                default:
                    strcpy(str_op, "UNKNOWN");
            }

            fprintf(stdout,"UDP[ ");
            if (!strcmp(tag, "IN")) {
                uint16_t udp_csum = udp->dgram_cksum;
                uint16_t local_udp_csum;
            
                ((struct udp_hdr *)udp)->dgram_cksum = 0;
                local_udp_csum = rte_ipv4_udptcp_cksum(ip, udp);
                ((struct udp_hdr *)udp)->dgram_cksum = udp_csum;
                
                if (local_udp_csum != udp_csum) {
                    fprintf(stdout,
                            "BAD CSUM pkt:0x%x local:0x%x ",
                            udp_csum, local_udp_csum);
			_exit(-131);
                }
            }

            fprintf(stdout, "SEQ %lu op %x %s] ",
                    data->seq, data->op, str_op); 
        }
        break;
    }
}

static void dump_packet(int port_id, const struct rte_mbuf *mbuf, const char *tag)
{
    if (no_dump) {
        return;
    }

    //rte_pktmbuf_dump(stdout, mbuf, mbuf->pkt_len);

    const uint8_t *rx_data = (const uint8_t *)rte_ctrlmbuf_data(mbuf);
    const struct ether_hdr *ethernet = (const struct ether_hdr *)rx_data; 
    uint16_t eth_type = __bswap_16(ethernet->ether_type);
    switch (eth_type) {
        case ETHER_TYPE_ARP: {
            const struct arp_hdr *arp = (const struct arp_hdr *)(ethernet + 1);
            if (!no_dump_arp ){
                fprintf(stdout, "%s[%d] ", tag, port_id);
                dump_ethernet_data(ethernet);
                dump_arp(arp);
                fprintf(stdout, "\n");
            }
        }
        break;

        case ETHER_TYPE_IPv4: {
            const struct ipv4_hdr *ip = (const struct ipv4_hdr *)(ethernet + 1);
            fprintf(stdout, "%s[%d] ", tag, port_id);
            dump_ethernet_data(ethernet);
            dump_ip_data(mbuf, ip, tag);
            fprintf(stdout, "\n");
        }
        break; 
    }
}

static int do_icmp_request(int port_id, struct rte_mbuf *mbuf)
{
    struct ether_addr aux_eth;
    uint32_t          aux_ip, cksum;

    struct icmp_hdr *icmp = rte_pktmbuf_mtod(mbuf, struct icmp_hdr *);
    icmp->icmp_type = IP_ICMP_ECHO_REPLY;
    cksum = ~icmp->icmp_cksum & 0xffff;
    cksum += ~htons(IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
    cksum += htons(IP_ICMP_ECHO_REPLY << 8);
    cksum = (cksum & 0xffff) + (cksum >> 16);
    cksum = (cksum & 0xffff) + (cksum >> 16);
    icmp->icmp_cksum = ~cksum;

    mbuf->data_off -= sizeof(struct ipv4_hdr);
    struct ipv4_hdr *ip = rte_pktmbuf_mtod(mbuf, struct ipv4_hdr *);
    aux_ip = ip->src_addr;
    ip->src_addr = ip->dst_addr;
    ip->dst_addr = aux_ip;

    mbuf->data_off -= sizeof(struct ether_hdr);
    struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    ether_addr_copy(&eth->s_addr, &aux_eth);
    ether_addr_copy(&eth->d_addr, &eth->s_addr);
    ether_addr_copy(&aux_eth,     &eth->d_addr);

    dump_packet(port_id, mbuf, "OUT");
    int ret = rte_eth_tx_burst(port_id, 0, &mbuf, 1);
    return (ret == 1) ? 0 : 1; 
}

static inline int validate_udp_csum(struct ipv4_hdr *ip, struct udp_hdr *udp)
{
    uint16_t udp_csum = udp->dgram_cksum;
    uint16_t local_udp_csum;

    udp->dgram_cksum = 0;
    local_udp_csum = rte_ipv4_udptcp_cksum(ip, udp);
    udp->dgram_cksum = udp_csum;
    if (local_udp_csum != udp_csum) {
        fprintf(stderr, "UDP RX checksum got x%x calculated x%x\n", udp_csum, local_udp_csum);
    }
    return local_udp_csum == udp_csum; 
}

static inline int process_incoming_ip(int port_id, struct rte_mbuf *mbuf)
{
    int free_mbuf = 1;
    struct ipv4_hdr *ip = rte_pktmbuf_mtod(mbuf, struct ipv4_hdr *);
    struct peer *peer = find_peer_by_ip(ip->src_addr);
    if (!peer) {
        if (!no_dump) printf("cannot find peer for incoming IP\n"); 
        goto f1;
    }

    mbuf->data_off += sizeof(struct ipv4_hdr);
    switch (ip->next_proto_id) {
        case IPPROTO_UDP: {
            struct udp_hdr *udp = (struct udp_hdr *)(ip + 1);
            if (!validate_udp_csum(ip, udp)) {
                rte_pktmbuf_dump(stderr, mbuf, mbuf->buf_len);
                exit(-131);
            }
                struct udp_ping_data *data = (struct udp_ping_data *)(udp + 1);
                if (data->op == OP_REQUEST) {
                    rte_pktmbuf_reset(mbuf);
                    pkt_assemble_udp(&mbuf, peer, OP_RESPONSE, 1);
                    send_packets(&mbuf, 1);
                    peer->requests_in_num++;
                    peer->responses_out_num++;
                    free_mbuf = 0;
                } else if (data->op == OP_RESPONSE) {
                    peer->responses_in_num++;
                    if (verify_payload) {
                        int verdict = 1;
                        int i, size = frame_size - sizeof(struct ether_hdr) - 
                                      sizeof(struct ipv4_hdr) - sizeof(struct udp_hdr);
                        for (i = 0; i < size - 64; i++) {
                            if (data->uint8_data[i] != (uint8_t)i) {
                                verdict = 0;
                                if (0) fprintf(stderr, "invalid payload at offset[%d] have %u expect %u\n",
                                        i, data->uint8_data[i], (uint8_t)i);
                            }
                        }
                        if (!verdict) fprintf(stderr, "data verification NOK\n");
                    }
                }
        }
        break;

        case IPPROTO_ICMP: {
            struct icmp_hdr *icmp = (struct icmp_hdr *)(ip + 1);
            switch (icmp->icmp_type) {
            	case IP_ICMP_ECHO_REQUEST: {
            		if (icmp->icmp_code == 0) free_mbuf = do_icmp_request(port_id, mbuf);
            	}
            	break;

            	case IP_ICMP_ECHO_REPLY: {
            		if (icmp->icmp_ident == rte_cpu_to_be_16(3103)) peer->responses_in_num++;
            	}
            	break;
            }
        }
        break;
    }

f1:
    return free_mbuf;
}

static void dump_mac(const struct ether_addr *mac, char *buf)
{
    sprintf(buf, "%02x:%02x:%02x:%02x%02x:%02x",
			mac->addr_bytes[0], mac->addr_bytes[1],
			mac->addr_bytes[2], mac->addr_bytes[3],
			mac->addr_bytes[4], mac->addr_bytes[5]);

}

static void dump_arp(const struct arp_hdr *arp)
{
    char ip_src[32], ip_dst[32], mac[32];
    
    struct in_addr s = { arp->arp_data.arp_sip };
    struct in_addr d = { arp->arp_data.arp_tip }; 
    strcpy(ip_src, inet_ntoa(s));
    strcpy(ip_dst, inet_ntoa(d));
  
    uint16_t op = __bswap_16(arp->arp_op);
    if (op == ARP_OP_REQUEST) {
        fprintf(stdout, "ARP[REQUEST for %s from %s] ", ip_dst, ip_src);
    } else if (op == ARP_OP_REPLY) {
        dump_mac(&arp->arp_data.arp_sha, mac);
        fprintf(stdout, "ARP[REPLY  %s is at %s] ", ip_src, mac);
    } else {
        fprintf(stdout, "ARP[type: 0x%04x] ", op);
    }
}

static inline int ip_to_mac(uint32_t ip)
{
    int px;
    for (px = 0; px < 1; px++) {
        if (local_ports[px].addr.ip.s_addr == ip) return px;
    }
    return -1;
}

static int process_incoming_arp(int port_id, struct rte_mbuf *mbuf)
{
    int px = 0, free_mbuf = 1;
    struct arp_hdr *arp = rte_pktmbuf_mtod(mbuf, struct arp_hdr *);
    mbuf->data_off -= sizeof(struct ether_hdr);
    struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    uint16_t arp_op = __bswap_16(arp->arp_op);
    if (arp_op == ARP_OP_REQUEST) {
        /** Build ARP reply */
        struct ether_addr eth_addr;
        uint32_t ip_addr;

        if (local_ports[0].addr.ip.s_addr != arp->arp_data.arp_tip) {
            goto f1;
        }

        /* Use source MAC address as destination MAC address. */
        ether_addr_copy(&eth->s_addr, &eth->d_addr);
        /* Set source MAC address with MAC address of TX port */
        ether_addr_copy(&local_ports[px].addr.ethernet, &eth->s_addr);

        arp->arp_op = __bswap_16(ARP_OP_REPLY);
        ether_addr_copy(&arp->arp_data.arp_tha, &eth_addr);
        ether_addr_copy(&arp->arp_data.arp_sha, &arp->arp_data.arp_tha);
        ether_addr_copy(&eth->s_addr, &arp->arp_data.arp_sha);

        /* Swap IP addresses in ARP payload */
        ip_addr = arp->arp_data.arp_sip;
        arp->arp_data.arp_sip = arp->arp_data.arp_tip;
        arp->arp_data.arp_tip = ip_addr;
        
        dump_packet(port_id, mbuf, "OUT");
        int ret = rte_eth_tx_burst(port_id, 0, &mbuf, 1);
        free_mbuf = (ret == 1) ? 0 : 1;

    } else if (arp_op == ARP_OP_REPLY) {
        struct peer *peer = find_peer_by_ip(arp->arp_data.arp_sip);
        if (!peer) {
        	struct in_addr s = { arp->arp_data.arp_sip };
        	struct in_addr d = { arp->arp_data.arp_tip };
			char sip[32], tip[32];
			strcpy(sip, inet_ntoa(s));
			strcpy(tip, inet_ntoa(d));

        	printf("no peer for ARP reply sip %s tip %s\n", sip, tip);
        	goto f1;
        }

		if (!(peer->flags & PEER_HAS_MAC)) {
			char local[32], remote[32];
			strcpy(local, inet_ntoa(local_ports[0].addr.ip));
			strcpy(remote, inet_ntoa(peer->addr.ip));
			printf("[%s] peer found - %s\n", local, remote);

        	ether_addr_copy(&arp->arp_data.arp_sha, &peer->addr.ethernet);
        	peer->flags |= PEER_HAS_MAC;
        }

        peer->tm_op = OP_REQUEST; 
        rte_timer_stop_sync(&peer->tm);
		rte_timer_init(&peer->tm);

#if 1
		tm_dispatcher(NULL, peer);
#else
		rte_timer_reset(
			&peer->tm,
			0,
			SINGLE,
			rte_lcore_id(),
			tm_dispatcher, peer);
#endif
    } else {
    	char msg[128];
    	sprintf(msg, "unknown ARP type %04x", arp_op);
    	rte_hexdump(stdout, msg, (uint8_t *)arp - 14, 128);
    }

f1:
    return free_mbuf;
}

static void process_rx(int port_id, struct rte_mbuf *mbuf)
{
    int free_mbuf = 1;
    if (DEBUG) printf("DEBUG: process incoming mbuf %p\n", mbuf);
    struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    mbuf->data_off += sizeof(struct ether_hdr);
    switch (__bswap_16(eth->ether_type)) {
    	case ETHER_TYPE_ARP:
            free_mbuf = process_incoming_arp(port_id, mbuf);
            break;
        case ETHER_TYPE_IPv4:
            free_mbuf = process_incoming_ip(port_id, mbuf);
            break;
        default: {
#if 0
        	char msg[128];
        	sprintf(msg, "UNRESOLVED ETH TYPE %04x", __bswap_16(eth->ether_type));
        	rte_hexdump(stdout, msg, (uint8_t *)eth - 128, 512);
#endif
        }
        break;
    }

    if (free_mbuf) {
        static struct rte_mbuf *rx_stash = NULL;
        static uint32_t rx_stash_size = 0;
        mbuf->next = rx_stash;
        rx_stash = mbuf;
        if (++rx_stash_size >= mbuf->pool->populated_size - 4096) {
                    printf("DEBUG: release mbuf stash size %u\n", rx_stash_size);
                    rte_pktmbuf_free(rx_stash);
                    rx_stash = NULL;
                    rx_stash_size = 0;
        }

    }
}

static int select_tx_port(void)
{
    return 0;
}


static void ethernet_header(struct ether_hdr *eth, struct peer *peer, uint16_t eth_type)
{
    ether_addr_copy(&peer->addr.ethernet, &eth->d_addr);
    ether_addr_copy(&local_ports[0].addr.ethernet, &eth->s_addr);
    eth->ether_type = rte_cpu_to_be_16(eth_type);
}

static void ipv4_header(struct ipv4_hdr *ip, struct peer *peer, uint16_t total_len, uint8_t protocol)
{
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = rte_cpu_to_be_16(total_len);
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = protocol;
    ip->hdr_checksum = 0;
    ip->src_addr = local_ports[0].addr.ip.s_addr;
    ip->dst_addr = peer->addr.ip.s_addr;
}

static void udp_header(struct udp_hdr *udp, uint16_t port, uint16_t len)
{
    udp->src_port = rte_cpu_to_be_16(port);
    udp->dst_port = rte_cpu_to_be_16(port);
    udp->dgram_len = rte_cpu_to_be_16(len);
    udp->dgram_cksum = 0;
}

static void icmp_request_header(struct icmp_hdr *h, uint64_t seq)
{
	h->icmp_type = IP_ICMP_ECHO_REQUEST;
	h->icmp_code = 0;
	h->icmp_cksum = 0;
	h->icmp_ident = rte_cpu_to_be_16(3103);
	h->icmp_seq_nb = rte_cpu_to_be_16(seq & 0xffff);
}

static void icmp_request_checksum(struct icmp_hdr *h, size_t len)
{
    uint16_t csum = rte_raw_cksum(h, len);
	h->icmp_cksum = ~csum;
}

static void format_udp_ping(struct udp_ping_data *data, struct peer *peer,
                            uint16_t size, enum data_ops_e op)
{
    data->seq = peer->sequence++;
    data->op = op;
    if (verify_payload && (op == OP_REQUEST)) {
        int i;
        for (i = 0; i < size - 64; i++) data->uint8_data[i] = (uint8_t)i;
    }
}

static void icmp_request_data(void *data, size_t size)
{
	(void)data;
	(void)size;
}

static void pkt_assemble_icmp_request(struct rte_mbuf **mbuf, struct peer *peer, enum data_ops_e op, int burst)
{
	(void)op;
	int i; for (i = 0; i < burst; i++) {
		struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf[i], struct ether_hdr *);
		struct ipv4_hdr *ip     = (struct ipv4_hdr *)(eth + 1);
        struct icmp_hdr *icmp;

        if (!mbuf_chain) {
            rte_pktmbuf_pkt_len(mbuf[i])  = 
            rte_pktmbuf_data_len(mbuf[i]) = frame_size;

		    icmp   = (struct icmp_hdr *)(ip + 1);
        } else {
            struct rte_mbuf *chain = rte_pktmbuf_alloc(mbuf_pool);
            if (!chain) {
                rte_exit(EXIT_FAILURE, "cannot allocate chain MBUF\n");
            }
            mbuf[i]->nb_segs++;
            mbuf[i]->next = chain;
            chain->data_off = 0;
            rte_pktmbuf_pkt_len(mbuf[i]) = frame_size;
            rte_pktmbuf_data_len(mbuf[i]) = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
            rte_pktmbuf_pkt_len(chain) = 
            rte_pktmbuf_data_len(chain) = frame_size - rte_pktmbuf_data_len(mbuf[i]);
            icmp = rte_pktmbuf_mtod(chain, void *);
        }

		void *data = (icmp + 1);

		ethernet_header(eth, peer, ETHER_TYPE_IPv4);
		size_t data_size = mbuf[i]->pkt_len - sizeof(struct ether_hdr);
		ipv4_header(ip, peer, data_size, IPPROTO_ICMP);
		data_size -= sizeof(struct ipv4_hdr);
		icmp_request_header(icmp, peer->sequence++);
		icmp_request_data(data, data_size - sizeof(*icmp));
		icmp_request_checksum(icmp, data_size);

#if 1
		ip->hdr_checksum = rte_ipv4_cksum(ip);
#else
        ip->hdr_checksum = 0;
		mbuf[i]->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
		mbuf[i]->l2_len = sizeof(struct ether_hdr);
		mbuf[i]->l3_len = sizeof(struct ipv4_hdr);
#endif
	}
}


static void pkt_assemble_udp(struct rte_mbuf **mbuf, struct peer *peer, enum data_ops_e op, int burst)
{
#define UDP_JAM_MASK 3
    static uint32_t jam_cnt = 0;

    int i;
    for (i = 0; i < burst; i++) {
        struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf[i], struct ether_hdr *);
        struct ipv4_hdr *ip     = (struct ipv4_hdr *)(eth + 1);
        struct udp_hdr *udp   = (struct udp_hdr *)(ip + 1);
        struct udp_ping_data *uping = NULL;

        if (mbuf_chain && op == OP_REQUEST) {
            struct rte_mbuf *chain = rte_pktmbuf_alloc(mbuf_pool);
            if (!chain) {
                rte_exit(EXIT_FAILURE, "cannot allocate chain MBUF\n");
            }
            mbuf[i]->nb_segs++;
            mbuf[i]->next = chain;
            chain->data_off = 0;
            rte_pktmbuf_pkt_len(mbuf[i]) = frame_size;
            rte_pktmbuf_data_len(mbuf[i]) = sizeof(struct ether_hdr) + 
                                            sizeof(struct ipv4_hdr)  +
                                            sizeof(struct udp_hdr);
            rte_pktmbuf_pkt_len(chain) =
            rte_pktmbuf_data_len(chain) = frame_size - 
                                          rte_pktmbuf_data_len(mbuf[i]);

            uping = rte_pktmbuf_mtod(chain, struct udp_ping_data *);
        } else {
            rte_pktmbuf_pkt_len(mbuf[i]) = 
            rte_pktmbuf_data_len(mbuf[i]) = frame_size;
            uping = (struct udp_ping_data *)(udp + 1);
        }
        
        ethernet_header(eth, peer, ETHER_TYPE_IPv4);
        size_t data_size = mbuf[i]->pkt_len - sizeof(struct ether_hdr);
        ipv4_header(ip, peer, data_size, IPPROTO_UDP);
        data_size -= sizeof(struct ipv4_hdr);
        udp_header(udp, udp_port, data_size);
        data_size -= sizeof(struct udp_hdr);
        format_udp_ping(uping, peer, data_size, op); 

        //checksum offload
        mbuf[i]->packet_type |= RTE_PTYPE_L4_NONFRAG;
        mbuf[i]->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
#if 1
        mbuf[i]->l2_len = sizeof(struct ether_hdr);
        mbuf[i]->l3_len = sizeof(struct ipv4_hdr);   
#else
        mbuf[i]->tx_offload = (14) | (20 << 7);
#endif
        ip->hdr_checksum = 0;
        udp->dgram_cksum = 0;
        udp->dgram_cksum = rte_ipv4_phdr_cksum(ip, mbuf[i]->ol_flags);

        if (udp_jam && ((jam_cnt++ & UDP_JAM_MASK) == UDP_JAM_MASK)) {
            udp->dgram_cksum++;
        }
    }
}

static void pkt_assemble_none(struct rte_mbuf **mbuf, struct peer *peer, enum data_ops_e op, int burst)
{
	(void)mbuf;
	(void)peer;
	(void)op;
	(void)burst;
}

static void send_packets(struct rte_mbuf **mbuf, size_t burst)
{
    int port_id = select_tx_port();
    if (!no_dump) {
        uint i;
        for (i = 0; i < burst; i++) {
            dump_packet(port_id, mbuf[i], "OUT");
        }
    }

#if 1
    while (burst) {
        uint ret = rte_eth_tx_burst(port_id, 0, mbuf, burst);
        mbuf += ret;
        burst -= ret;
    } 
#else
    uint ret = rte_eth_tx_burst(port_id, 0, mbuf, burst);
    if (ret != burst) {
        fprintf(stderr, "burst %lu sent %u\n", burst, ret);
        mbuf += ret;
        burst -= ret;
        ret = rte_eth_tx_burst(port_id, 0, mbuf, burst);
        if (ret != burst) {
            rte_exit(EXIT_FAILURE, "cannot send MBUF on port %d burst %lu sent %u\n",
                     port_id, burst, ret);
        }
    }
#endif
}

static void tm_dispatcher(struct rte_timer *rte_tm, void *tm_arg)
{
	(void)rte_tm;
	struct peer *peer = tm_arg;

	if (!(peer->flags & PEER_HAS_MAC)) {
		rte_exit(EXIT_FAILURE, "unresolved peer");
	}

	int i;
	struct rte_mbuf *mbuf[BURST_SIZE];
	for (i = 0; i < burst; i++) {
		mbuf[i] = rte_pktmbuf_alloc(mbuf_pool);
		if (!mbuf[i]) {
			rte_exit(EXIT_FAILURE, "cannot allocate MBUF\n");
		}
	}

	mode_keys[op_mode].pkt_assemble(mbuf, peer, peer->tm_op, burst);
	if (op_mode != MODE_NONE) {
        send_packets(mbuf, burst);
        peer->requests_out_num += burst;
    }

	rte_timer_reset(
		&peer->tm,
		udp_tmout,
		SINGLE,
		rte_lcore_id(),
		tm_dispatcher, peer);
}


#define WEKA_PROBE_LEN 128
#define WEKA_PROBE_TYPE 0x776b /* "wk" */
static const uint8_t WEKA_PROBE_ADDR[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static void format_probe_buffer(struct rte_mbuf *mbuf, int port_id)
{
    struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    ether_addr_copy((const struct ether_addr *)WEKA_PROBE_ADDR, &eth->d_addr);
    ether_addr_copy(&local_ports[port_id].addr.ethernet, &eth->s_addr);
    eth->ether_type = __bswap_16(WEKA_PROBE_TYPE);

    mbuf->pkt_len = mbuf->data_len = WEKA_PROBE_LEN;
}

static void send_weka_probe(void)
{
    int p, ret;
    for (p = 0; p < nb_ports; p++) {
        struct rte_mbuf *mbuf = rte_mbuf_raw_alloc(mbuf_pool);
        if (!mbuf) {
            rte_exit(EXIT_FAILURE, "cannot allocate MBUF\n");
        }

        format_probe_buffer(mbuf, p);
        dump_packet(p, mbuf, "OUT");
        ret = rte_eth_tx_burst(p, 0, &mbuf, 1);
        if (ret != 1) {
            rte_pktmbuf_free(mbuf);
        }

    }
}

static void format_arp_request(struct peer *peer, struct rte_mbuf *mbuf)
{
    size_t pkt_size = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
    mbuf->data_len = mbuf->pkt_len = pkt_size;

    struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    memset(eth->d_addr.addr_bytes, 0xFF, ETHER_ADDR_LEN);
    ether_addr_copy(&local_ports[0].addr.ethernet, &eth->s_addr);
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);

    struct arp_hdr *arp = (struct arp_hdr *)(eth + 1);
    arp->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
    arp->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    arp->arp_hln = ETHER_ADDR_LEN;
    arp->arp_pln = sizeof(uint32_t);
    arp->arp_op = rte_cpu_to_be_16(ARP_OP_REQUEST);

    ether_addr_copy(&local_ports[0].addr.ethernet, &arp->arp_data.arp_sha);
    arp->arp_data.arp_sip = local_ports[0].addr.ip.s_addr; 
    memset(&arp->arp_data.arp_tha, 0, ETHER_ADDR_LEN);
    arp->arp_data.arp_tip =
              ((unsigned char *)&peer->addr.ip.s_addr)[0]        |
             (((unsigned char *)&peer->addr.ip.s_addr)[1] << 8)  |
             (((unsigned char *)&peer->addr.ip.s_addr)[2] << 16) |
             (((unsigned char *)&peer->addr.ip.s_addr)[3] << 24);

}

static void dump_stats(struct peer *peer)
{
	char local[32], remote[32];
	strcpy(local, inet_ntoa(local_ports[0].addr.ip));
	strcpy(remote, inet_ntoa(peer->addr.ip));
	printf("=== STATS for %s -> %s: %s [ sent %lu acked %lu %02.5f%%]",
	local, remote,
	mode_keys[op_mode].name,
	peer->requests_out_num, peer->responses_in_num,
	(100.0 * peer->responses_in_num) / peer->requests_out_num);

	if (mode_keys[op_mode].mode == MODE_UDP) {
		printf(" [received %lu acked %lu %02.5f%%]",
		peer->requests_in_num, peer->responses_out_num,
		(100.0 * peer->responses_out_num) / peer->requests_in_num);
	}

	printf("\n");

	if (!unlimited && !(--rounds)) {
		int verdict = peer->responses_in_num > 0 ? 0 : ENETUNREACH;
		rte_exit(verdict, "exit with status %d\n", verdict);
	}

	peer->requests_out_num = peer->responses_in_num = 0;
	peer->requests_in_num = peer->responses_out_num = 0;


}

static void dump_peer_stat(struct rte_timer *rte_tm, void *tm_arg)
{
    (void)rte_tm;
    struct peer *peer = tm_arg;
    dump_stats(peer);
}

static void __idle(struct rte_timer *rte_tm, void *tm_arg)
{
    printf("IDLE\n");
    uint64_t idle_tmout = ((rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S) * (1 * US_PER_S);
    rte_timer_reset(
        rte_tm,
        idle_tmout,
        SINGLE,
        rte_lcore_id(),
        __idle, tm_arg);
}

static void resolve_peer_mac(struct rte_timer *rte_tm, void *tm_arg)
{
    (void)rte_tm;
    struct peer *peer = tm_arg;

    char local[32], remote[32];
    strcpy(local, inet_ntoa(local_ports[0].addr.ip));
    strcpy(remote, inet_ntoa(peer->addr.ip));
    printf("[%s] resolving %s count %d\n",
    	local, remote,
    	peer->resolve_count);

    if (peer->flags & PEER_HAS_MAC) {
        return;
    } else if (++peer->resolve_count > peer_resolve_count) {
    	//rte_exit(ENETUNREACH, "peer is unreachable\n");
    }

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "cannot allocate MBUF\n");
    }

    format_arp_request(peer, mbuf);
    int port_id = select_tx_port();
    dump_packet(port_id, mbuf, "OUT");
    int ret = rte_eth_tx_burst(port_id, 0, &mbuf, 1);
    if (ret != 1) {
        rte_exit(EXIT_FAILURE, "cannot send MBUF on port %d\n", port_id);
    }

    uint64_t tmout = ((rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S) * (1 * MS_PER_S);
    rte_timer_reset(
        &peer->tm,
        tmout,
        SINGLE,
        rte_lcore_id(),
        resolve_peer_mac, peer);

}

static void tx_timer_callback(struct rte_timer *rte_tm, void *tm_arg)
{
    (void)rte_tm;
    (void)tm_arg;
    send_weka_probe();
}

static __attribute__((noreturn)) void
lcore_main(void)
{
    int i, p;
    uint64_t count = 0;
    struct rte_mbuf *bufs[BURST_SIZE];

#if 1
    uint64_t tmout = ((rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S) * (10 * US_PER_S);
    rte_timer_reset(
        &tx_timer,
        tmout,
        PERIODICAL,
        rte_lcore_id(),
        tx_timer_callback, NULL);
#else
    (void)tx_timer_callback;
#endif

    while (1) {

        for (p = 0; p < nb_ports; p++) {
            uint16_t nb_rx = rte_eth_rx_burst(p, 0, bufs, BURST_SIZE);
            if (DEBUG) fprintf(stdout, "RX[%d]: Got %u packets (%lu)\n", p, nb_rx, count++);

            for (i = 0; i < nb_rx; i++) {
                dump_packet(p, bufs[i], "IN");
                process_rx(p, bufs[i]);
            }
        }
        
        rte_timer_manage();

    }
}

/* RX ring configuration */
static const struct rte_eth_rxconf rx_conf = {
        .rx_thresh = {
                .pthresh = 8,   /* Ring prefetch threshold */
                .hthresh = 8,   /* Ring host threshold */
                .wthresh = 4,   /* Ring writeback threshold */
        },
        .rx_free_thresh = 32,    /* Immediately free RX descriptors */
};

/* TX ring configuration */
static struct rte_eth_txconf tx_conf = {
        .tx_thresh = {
                .pthresh = 32,  /* Ring prefetch threshold */
                .hthresh = 0,   /* Ring host threshold */
                .wthresh = 0,   /* Ring writeback threshold */
        },
        .tx_free_thresh	= 0,    /* Use PMD default values */
        .tx_rs_thresh	= 0,    /* Use PMD default values */
};

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &local_ports[port].eth_conf);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), &rx_conf, mbuf_pool);

        if (retval < 0) {
            printf("port %d - failed to allocate RX queue %d on socket %d (%d)\n",
                   port, q, rte_eth_dev_socket_id(port), retval);
            retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE, SOCKET_ID_ANY, &rx_conf, mbuf_pool);
            if (retval < 0) {
                printf("port %d - failed to allocate RX queue %d on socket %d (%d)\n",
                   port, q, SOCKET_ID_ANY, retval);
                return retval;
            }
        }
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), &tx_conf);
		if (retval < 0) {
            printf("port %d - failed to allocate TX queue %d on socket %d\n",
                   port, q, rte_eth_dev_socket_id(port));
            retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE, SOCKET_ID_ANY, NULL);
			if (retval < 0) return retval;
        }
	}

#if 1
	uint16_t mtu=4190;
    retval = rte_eth_dev_set_mtu(port, mtu);
    if (retval < 0) {
        printf("Couldnt set MTU %d on port %d\n", port, mtu);
    } else {
        printf("Set MTU for port %d to %d\n", port, mtu);
    }
#endif

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
    struct ether_addr *mac = &local_ports[port].addr.ethernet;
	rte_eth_macaddr_get(port, mac);
    rte_eth_dev_info_get(port, &local_ports[port].dev_info);
	fprintf(stdout, "Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " ",
			(unsigned)port,
			mac->addr_bytes[0], mac->addr_bytes[1],
			mac->addr_bytes[2], mac->addr_bytes[3],
			mac->addr_bytes[4], mac->addr_bytes[5]);

    fprintf(stdout, "IPv4 TX offload: %s ", local_ports[port].dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM ? "yes" : "no");
    fprintf(stdout, "UDP  TX offload: %s ", local_ports[port].dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM ? "yes" : "no");
    fprintf(stdout, "promiscuous: %s ", rte_eth_promiscuous_get(port) ? "on" : "off");
    fprintf(stdout, "ethernet multicast: %s ", rte_eth_allmulticast_get(port) ? "on" : "off");

    fprintf(stdout, "\n");

    if (0) {
        /* Enable RX in promiscuous mode for the Ethernet device. */
        rte_eth_promiscuous_enable(port);
    }

    if (1) {
        fprintf(stdout, "=== enable ethernet multicast\n");
        rte_eth_allmulticast_enable(port);
    }

	return 0;
}

static int dpdk_init(int argc, char **argv)
{
    signal(SIGINT, signal_handler);

    //rte_set_log_level(RTE_LOG_DEBUG);
    //rte_set_log_type(0xffffffff, 1);
    int p, argn = rte_eal_init(argc, argv);
	if (argn < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    if (rte_lcore_count() > 1)
		fprintf(stdout, "\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count();
    if (!nb_ports) {
        rte_exit(EXIT_FAILURE, "Error: no ports defined"); 
    }

    if (nb_ports > MAX_LOCAL_PORTS) {
        nb_ports = MAX_LOCAL_PORTS;
    }


#if 1
    mbuf_pool = weka_init_mbuf_pool(NUM_MBUFS * nb_ports);
#else
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
                    MBUF_CACHE_SIZE, 0, MBUF_SIZE, rte_socket_id());
#endif

    if (!mbuf_pool) {
        rte_exit(EXIT_FAILURE, "Error: no MBUF pool");
    }

    for (p = 0; p < nb_ports; p++) {
        int ret = port_init(p, mbuf_pool);
        if (ret != 0) {
            rte_exit(EXIT_FAILURE, "Error: failed to init port %d", p);
        }
    }

    return argn;
}

static struct peer *find_peer_by_ip(uint32_t ip)
{
    int px;
    for (px = 0; px < nb_peers; px++) {
        if (peers[px].addr.ip.s_addr == ip) return peers + px;
    }
    return NULL;
}

static struct peer *add_peer(uint32_t peer_ip)
{
    if (nb_peers >= MAX_PEERS) return NULL;
    if (find_peer_by_ip(peer_ip)) return NULL;

    struct peer *p = peers + nb_peers;
    p->addr.ip.s_addr = peer_ip;
    p->flags = 0;
    p->sequence = 0;
    p->requests_out_num = 0;
    p->requests_out_num = 0;
    p->responses_in_num = 0;
    p->responses_out_num = 0;
    p->resolve_count = 0;
    nb_peers++;

    rte_timer_init(&p->tm);
    rte_timer_init(&p->stat_tm);

    printf("add peer\n");
    int ret = rte_timer_reset(
                &p->tm,
                1,
                SINGLE,
                rte_lcore_id(),
                resolve_peer_mac, p);
    if (ret) {
        rte_exit(EXIT_FAILURE, "Error: cannot init peer timer");
    }

    uint64_t tmout = ((rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S) * (10 * MS_PER_S);
    rte_timer_reset(
        &p->stat_tm,
        tmout,
        PERIODICAL,
        rte_lcore_id(),
        dump_peer_stat, p);

    return p;
}

static void parse_config_file(const char *config_file)
{
	FILE *fobj = fopen(config_file, "r");
	if (!fobj) {
		rte_exit(EXIT_FAILURE, "Error: cannot open config file \"%s\"", config_file);
	}

	printf("%s:%d file %s\n", __func__, __LINE__, config_file);

	char *buffer = malloc(1<<10);
	if (!buffer) {
		rte_exit(EXIT_FAILURE, "Error: failed to allocate memory for config file");
	}

	size_t len = fread(buffer, 1, (1<<10), fobj);
	printf("%s:%d len = %lu\n", __func__, __LINE__, len);
	fclose(fobj);
	printf("%s:%d\n", __func__, __LINE__);
	buffer[len] = '\0';
	char *end = buffer + len;
	printf("%s:%d\n", __func__, __LINE__);
	char *p = buffer;
	while(p <= end) {
		uint32_t ip;
		printf("%s:%d\n", __func__, __LINE__);
		char *q = strchr(p, '\n');
		if (!q) {
			break;
		}
		*q = '\0';
		printf("%s:%d\n", __func__, __LINE__);
		int ret = inet_pton(AF_INET, p, &ip);
		if (ret != 1) {
			rte_exit(EXIT_FAILURE, "Error: cannot convert IP address %s", p);
		}
		printf("Peer IP: %s\n", p);
		if (local_ports[0].addr.ip.s_addr == ip) {
			printf("skip local IP address\n");
		} else if (!add_peer(ip)) {
			rte_exit(EXIT_FAILURE, "Error: cannot create peer for IP address %s", p);
		}

		p = q + 1;

	}

}

enum long_opt_e {
	OPT_LOCAL_IP = 0,
	OPT_PEER_IP,
	OPT_FRAME_SIZE,
	OPT_BURST_SIZE,
	OPT_TMOUT,
	OPT_MODE,
	OPT_ROUNDS,
	OPT_CONFIG_FILE,
	OPT_ROCE_DEV,
	OPT_ROCE_GUID,
	OPT_IB_MODE,
    OPT_MBUF_CHAIN,
	OPT_UDP_JAM,
	OPT_NO_DUMP,
	OPT_DUMP_ARP,
};

static const struct option proc_long_opt[] = {
	{ "ip",         required_argument,  0, OPT_LOCAL_IP },
	{ "peer",       required_argument,  0, OPT_PEER_IP  },
	{ "size",       required_argument,  0, OPT_FRAME_SIZE },
	{ "burst",      required_argument,  0, OPT_BURST_SIZE },
	{ "tmout",      required_argument,  0, OPT_TMOUT },
	{ "mode",       required_argument,  0, OPT_MODE },
	{ "rounds",     required_argument,  0, OPT_ROUNDS },
	{ "config",     required_argument,  0, OPT_CONFIG_FILE },
	{ "roce-dev",   required_argument,  0, OPT_ROCE_DEV },
	{ "roce-guid",  required_argument,  0, OPT_ROCE_GUID },
	{ "ib-mode",  required_argument,    0, OPT_IB_MODE },
    { "chain",      no_argument,        0, OPT_MBUF_CHAIN},
	{ "udp-jam",    no_argument,        0, OPT_UDP_JAM },
	{ "no-dump",    no_argument,        0, OPT_NO_DUMP },
	{ "dump-arp",   no_argument,        0, OPT_DUMP_ARP },

	{0, 0, 0, 0}
};


static void parse_arguments(int argc, char **argv)
{
	int ret, opt_index;

	while (1) {
		int opt = getopt_long_only(argc, argv, "", proc_long_opt, &opt_index);
		switch (opt) {
			case OPT_LOCAL_IP:
			printf("LocalPort IP %s\n", optarg);
			ret = inet_pton(AF_INET, optarg, &local_ports[0].addr.ip);
			if (ret != 1) {
				rte_exit(EXIT_FAILURE, "Error: cannot convert IP address %s", optarg);
			}
			break;

			case OPT_PEER_IP: {
				uint32_t ip;
				ret = inet_pton(AF_INET, optarg, &ip);
				if (ret != 1) {
					rte_exit(EXIT_FAILURE, "Error: cannot convert IP address %s", optarg);
				}
				printf("Peer IP: %s\n", optarg);
				if (!add_peer(ip)) {
					rte_exit(EXIT_FAILURE, "Error: cannot create peer for IP address %s", optarg);
				}
			}
			break;

			case OPT_FRAME_SIZE: {
				uint64_t size = atoi(optarg);
				frame_size = size > MAX_FRAME_SIZE ? MAX_FRAME_SIZE : size;
			}
			break;

			case OPT_BURST_SIZE: {
				burst = atoi(optarg);
				if (burst > BURST_SIZE) {
					burst = BURST_SIZE;
				}
			}
			break;

			case OPT_TMOUT: {
				udp_tmout = strtoull(optarg, NULL, 10);
			}
			break;

			case OPT_MODE: {
				int i;
				for (i = 0; i < MODES_NUM; i++) {
					if (!strcmp(optarg, mode_keys[i].name)) {
						op_mode = mode_keys[i].mode;
						break;
					}
				}

			}
			break;

			case OPT_IB_MODE:
				roce_mode = !strcmp(optarg, "server") ? IB_SERVER : IB_CLIENT;
			break;

			case OPT_ROCE_DEV:
				roce_dev = strdup(optarg);
			break;

			case OPT_ROCE_GUID:
				roce_guid = strdup(optarg);
			break;

			case OPT_ROUNDS: {
				unlimited = 0;
				rounds = atoi(optarg);
			}
			break;

			case OPT_CONFIG_FILE: {
				parse_config_file(optarg);
			}
			break;

			case OPT_UDP_JAM: udp_jam = 1; break;

			case OPT_NO_DUMP: no_dump = 1; break;

			case OPT_DUMP_ARP: no_dump_arp = 0; break;

            case OPT_MBUF_CHAIN: mbuf_chain = 1; break;

			case -1: return;
			default: rte_exit(EXIT_FAILURE, "Error: unknown parameter %s", optarg);
		}
	}
}

static void proc_init(int argc, char **argv)
{
	memset(peers, 0, sizeof(struct peer) * MAX_PEERS);
	parse_arguments(argc, argv);

	if (op_mode == MODE_ROCE) {
		roce_init();
		op_mode = MODE_ICMP;
    }

	rte_timer_subsystem_init();
	rte_timer_init(&tx_timer);
	udp_tmout = (udp_tmout * rte_get_tsc_hz()) / 1000000;
}

static char *roce_args[MAX_ROCE_ARGS] = {NULL, };

static void roce_init(void)
{
	char ip[32];
	int count = 0;

	roce_args[count] = strdup("rping");
	count++;

	roce_args[count] = strdup("-C");
	count++;
	roce_args[count] = malloc(64);
	sprintf(roce_args[count], "%d", 100);
	count++;

	if (roce_mode == IB_CLIENT) {
		inet_ntop(AF_INET, &peers[0].addr.ip, ip, 64);
		roce_args[count] = strdup("-c");
	} else {
		inet_ntop(AF_INET, &local_ports[0].addr.ip, ip, 64);
		roce_args[count] = strdup("-s");
	}
	count++;

	roce_args[count] = strdup("-a");
	count++;
	roce_args[count] = malloc(64);
	sprintf(roce_args[count], "%s", ip);
	count++;

	roce_args[count] = NULL;

	int i;
	for (i = 0; i < count; i++) printf("%s ", roce_args[i]);
	printf("\n");

#if 0
	optind = 1;
	int rc = __rping_main(count, (char **)(void *)(uintptr_t)roce_args);
	printf("== rping exited with %d\n", rc);
	if (rc != 0) exit(rc);
#endif
}

static void __dbg_check_mbuf(void)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(mbuf_pool);
    if (!m) _exit(-1);
    rte_pktmbuf_dump(stdout, m, 256);
}

int main(int argc, char **argv)
{
	(void)__idle;

	show_time("START");

	int ret;
	ret = dpdk_init(argc, argv);

	argc -= ret;
	argv += ret;
	proc_init(argc, argv);

    __dbg_check_mbuf();

	lcore_main();
}

static void weka_mempool_dump(struct rte_mempool *mp)
{
    printf("mempool <%s>@%p\n", mp->name, mp);
    printf("  flags=%x\n", mp->flags);
    printf("  pool=%p\n", mp->pool_data);
    printf("  phys_addr=0x%lx\n", mp->mz->phys_addr);
    printf("  nb_mem_chunks=%u\n", mp->nb_mem_chunks);
    printf("  size=%u\n", mp->size);
    printf("  populated_size=%u\n", mp->populated_size);
    printf("  header_size=%u\n", mp->header_size);
    printf("  elt_size=%u\n", mp->elt_size);
    printf("  trailer_size=%u\n", mp->trailer_size);
    printf("  total_obj_size=%u\n",
           mp->header_size + mp->elt_size + mp->trailer_size);
    printf("  private_data_size=%u\n", mp->private_data_size);
    printf("  ops: \"%s\"\n", rte_mempool_get_ops(mp->ops_index)->name);
}

#define DATA_SZ 4096
#define EXPECTED_PROTO_SZ 90
struct rte_mempool *weka_init_mbuf_pool(uint32_t mbufs_count)
{

    uint32_t priv_size = 0;
    uint32_t cache_size = 0;
    uint32_t data_room_size = RTE_ALIGN_CEIL(DATA_SZ + EXPECTED_PROTO_SZ, 1024) + RTE_PKTMBUF_HEADROOM;

    struct rte_pktmbuf_pool_private mbp_priv = {
        .mbuf_data_room_size = data_room_size,
        .mbuf_priv_size = priv_size
    };

    if (RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) != priv_size) {
        printf("mbuf priv_size=%u is not aligned\n", priv_size);
        rte_errno = EINVAL;
        return NULL;
    }
    uint32_t elt_size = sizeof(struct rte_mbuf) + priv_size + data_room_size;

    struct rte_mempool *mp = rte_mempool_create_empty("WEKA MBUF pool", mbufs_count, elt_size, cache_size,
         sizeof(struct rte_pktmbuf_pool_private), rte_socket_id(), 0);
    if (mp == NULL)
        return NULL;

    const char pool_ops[] = "ring_sp_sc";
    void *pool_config = NULL;
    rte_errno = rte_mempool_set_ops_byname(mp, pool_ops, pool_config);
    if (rte_errno != 0) {
        printf("failed to set mempool handler %s (%d)\n", pool_ops, rte_errno);
        return NULL;
    }
    rte_pktmbuf_pool_init(mp, &mbp_priv);

    int ret = rte_mempool_populate_default(mp);
    if (ret < 0) {
        rte_mempool_free(mp);
        rte_errno = -ret;
        return NULL;
    }
    rte_mempool_obj_iter(mp, rte_pktmbuf_init, NULL);
    weka_mempool_dump(mp);
    return mp;
}
