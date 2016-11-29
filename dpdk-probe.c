
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <inttypes.h>
#include <byteswap.h>
#include <unistd.h>
#include <getopt.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_timer.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 2000000
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_LOCAL_PORTS 4

#define DEBUG 0

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
};

static struct port_device local_ports[MAX_LOCAL_PORTS] = {
    {.eth_conf = { .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN } }},
    {.eth_conf = { .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN } }},
    {.eth_conf = { .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN } }},
    {.eth_conf = { .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN } }},
};

static int nb_ports = 0;
static struct rte_mempool *mbuf_pool = NULL;
static struct rte_timer tx_timer;


static void dump_arp(const struct arp_hdr *arp);

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

static void dump_ip_data(const struct ipv4_hdr *ip)
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

    switch (ip->next_proto_id) {
        case IPPROTO_ICMP: {
            const struct icmp_hdr *icmp = (const struct icmp_hdr *)(ip + 1);
            fprintf(stdout, "ICMP[%s seq %u] ",
                    icmp->icmp_type == IP_ICMP_ECHO_REQUEST ? "REQUEST" : "REPLY",
                    __bswap_16(icmp->icmp_seq_nb));
             
        }

    }
}

static void dump_packet(int port_id, const struct rte_mbuf *mbuf, const char *tag)
{
    fprintf(stdout, "%s[%d] ", tag, port_id);
    const uint8_t *rx_data = (const uint8_t *)rte_ctrlmbuf_data(mbuf);
    const struct ether_hdr *ethernet = (const struct ether_hdr *)rx_data; 
    dump_ethernet_data(ethernet);
    uint16_t eth_type = __bswap_16(ethernet->ether_type);
    switch (eth_type) {
        case ETHER_TYPE_ARP: {
            const struct arp_hdr *arp = (const struct arp_hdr *)(ethernet + 1);
            dump_arp(arp);
        }
        break;

        case ETHER_TYPE_IPv4: {
            const struct ipv4_hdr *ip = (const struct ipv4_hdr *)(ethernet + 1);
            dump_ip_data(ip);
        }
        break; 

    }
    fprintf(stdout, "\n");
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

static inline int process_incoming_ip(int port_id, struct rte_mbuf *mbuf)
{
    int free_mbuf = 1;
    struct ipv4_hdr *ip = rte_pktmbuf_mtod(mbuf, struct ipv4_hdr *);
    mbuf->data_off += sizeof(struct ipv4_hdr);
    switch (ip->next_proto_id) {
        case IPPROTO_ICMP: {
            struct icmp_hdr *icmp = (struct icmp_hdr *)(ip + 1);
            if ((icmp->icmp_type == IP_ICMP_ECHO_REQUEST) &&
		       (icmp->icmp_code == 0)) free_mbuf = do_icmp_request(port_id, mbuf); 
        }
    }
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
    if (__bswap_16(arp->arp_op) != ARP_OP_REQUEST) goto f1;
    
    struct ether_addr eth_addr;
    uint32_t ip_addr;

    /*
     * Build ARP reply.
     */

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
    }

    if (free_mbuf) {
        if (DEBUG) printf("DEBUG: release incoming mbuf %p\n", mbuf);
        rte_pktmbuf_free(mbuf);
    }
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
            rte_exit(EXIT_FAILURE, "cannot send MBUF on port %d\n", p);
        }

    }
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
    uint64_t last_run_tsc = rte_rdtsc();
    uint64_t tmout = ((rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S) * (1 * US_PER_S);

    rte_timer_reset(
        &tx_timer,
        tmout,
        PERIODICAL,
        rte_lcore_id(),
        tx_timer_callback, NULL);

    while (1) {
        #define BURST_TX_DRAIN_US 1000000
        const uint64_t drain_tsc = ((rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S) * BURST_TX_DRAIN_US;
        uint64_t now = rte_rdtsc();

        for (p = 0; p < nb_ports; p++) {
            uint16_t nb_rx = rte_eth_rx_burst(p, 0, bufs, BURST_SIZE);
            if (DEBUG) fprintf(stdout, "RX[%d]: Got %u packets (%lu)\n", p, nb_rx, count++);

            for (i = 0; i < nb_rx; i++) {
                dump_packet(p, bufs[i], "IN");
                process_rx(p, bufs[i]);
            }
        }
        
        if ((now - last_run_tsc) > drain_tsc) {
            rte_timer_manage();
            last_run_tsc = now;
        }

    }
}

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
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);

        if (retval < 0) {
            printf("port %d - failed to allocate RX queue %d on socket %d\n",
                   port, q, rte_eth_dev_socket_id(port));
            retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE, SOCKET_ID_ANY, NULL, mbuf_pool);
            if (retval < 0) return retval;
        }
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0) {
            printf("port %d - failed to allocate TX queue %d on socket %d\n",
                   port, q, rte_eth_dev_socket_id(port));
            retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE, SOCKET_ID_ANY, NULL);
			if (retval < 0) return retval;
        }
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
    struct ether_addr *mac = &local_ports[port].addr.ethernet;
	rte_eth_macaddr_get(port, mac);
	fprintf(stdout, "Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " ",
			(unsigned)port,
			mac->addr_bytes[0], mac->addr_bytes[1],
			mac->addr_bytes[2], mac->addr_bytes[3],
			mac->addr_bytes[4], mac->addr_bytes[5]);

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

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
                MBUF_CACHE_SIZE, 0, 6192, rte_socket_id());
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

static const struct option proc_long_opt[] = {
    { "ip", required_argument, 0, 0 },
    {0, 0, 0, 0}
};


static void parse_arguments(int argc, char **argv)
{
    int ret, opt_index;

    while (1) {
        int opt = getopt_long_only(argc, argv, "", proc_long_opt, &opt_index);
        switch (opt) {
            case 0:
                printf("LocalPort IP %s\n", optarg);
                ret = inet_pton(AF_INET, optarg, &local_ports[0].addr.ip);
                if (ret != 1) {
                    rte_exit(EXIT_FAILURE, "Error: cannot convert peer IP address %s", optarg);
                }
                break;

            case -1: return;
            default: rte_exit(EXIT_FAILURE, "Error: unknown parameter %s", optarg);
        }
    }
}

static void proc_init(int argc, char **argv)
{
    parse_arguments(argc, argv);
    rte_timer_subsystem_init();
    rte_timer_init(&tx_timer);
}

int main(int argc, char **argv)
{
    int ret;
    ret = dpdk_init(argc, argv);

    argc -= ret;
    argv += ret;
    proc_init(argc, argv);

    lcore_main();
}
