DPDK: 1c35f666df0786541cd2c83fbad332c1af2a78e7

DPDK MBUF poison patch:
diff --git a/drivers/net/ena/ena_ethdev.c b/drivers/net/ena/ena_ethdev.c
index 80ce1f3..9ccf916 100644
--- a/drivers/net/ena/ena_ethdev.c
+++ b/drivers/net/ena/ena_ethdev.c
@@ -1164,6 +1164,8 @@ static int ena_populate_rx_queue(struct ena_ring *rxq, unsigned int count)
 		struct rte_mbuf *mbuf = mbufs[next_to_use_masked];
 		struct ena_com_buf ebuf;
 
+		rte_pktmbuf_poison(mbuf, RTE_MBUF_POISON);
+
 		rte_prefetch0(mbufs[((next_to_use + 4) & ring_mask)]);
 		/* prepare physical address for DMA transaction */
 		ebuf.paddr = mbuf->buf_physaddr + RTE_PKTMBUF_HEADROOM;
diff --git a/lib/librte_mbuf/rte_mbuf.h b/lib/librte_mbuf/rte_mbuf.h
index 55206d9..c0820a2 100644
--- a/lib/librte_mbuf/rte_mbuf.h
+++ b/lib/librte_mbuf/rte_mbuf.h
@@ -1887,6 +1887,18 @@ rte_pktmbuf_linearize(struct rte_mbuf *mbuf)
  */
 void rte_pktmbuf_dump(FILE *f, const struct rte_mbuf *m, unsigned dump_len);
 
+#define RTE_MBUF_POISON 0x2020414d44204f4eUL
+
+static inline void
+rte_pktmbuf_poison(struct rte_mbuf *m, uint64_t poison)
+{
+	unsigned i;
+	uint64_t *base = m->buf_addr;
+
+	for (i = 0; i < m->buf_len / sizeof(uint64_t); i++)
+		base[i] = poison;
+}
+
 #ifdef __cplusplus
 }
 #endif


Reproduction inctruction:
# cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages 
2048

# dev=<VF PCIADDR>; dpdk-probe -l0 -n1 --log-level=10  --huge-dir=${huge_dir} --proc-type=primary --file-prefix=_${dev}_ -w $dev -m 4096 -- \
	--mode udp  --ip 172.31.22.112  --peer 172.31.19.191 --size 4097 --burst 64 --tmout 100 --no-dump

OUTPUT:
EAL: Detected lcore 0 as core 0 on socket 0
EAL: Detected lcore 1 as core 1 on socket 0
EAL: Detected lcore 2 as core 2 on socket 0
EAL: Detected lcore 3 as core 3 on socket 0
EAL: Detected lcore 4 as core 0 on socket 0
EAL: Detected lcore 5 as core 1 on socket 0
EAL: Detected lcore 6 as core 2 on socket 0
EAL: Detected lcore 7 as core 3 on socket 0
EAL: Support maximum 128 logical core(s) by configuration.
EAL: Detected 8 lcore(s)
EAL: No free hugepages reported in hugepages-1048576kB
85363:197799037 START
EAL: Setting up physically contiguous memory...
EAL: Ask a virtual area of 0x200000 bytes
EAL: Virtual area found at 0x7f4a5ea00000 (size = 0x200000)
EAL: Ask a virtual area of 0xff600000 bytes
EAL: Virtual area found at 0x7f495f200000 (size = 0xff600000)
EAL: Ask a virtual area of 0x200000 bytes
EAL: Virtual area found at 0x7f495ee00000 (size = 0x200000)
EAL: Ask a virtual area of 0x400000 bytes
EAL: Virtual area found at 0x7f495e800000 (size = 0x400000)
EAL: Ask a virtual area of 0x200000 bytes
EAL: Virtual area found at 0x7f495e400000 (size = 0x200000)
EAL: Requesting 2048 pages of size 2MB from socket 0
EAL: TSC frequency is ~2300074 KHz
EAL: Master lcore 0 is ready (tid=60e71940;cpuset=[0])
EAL: PCI device 0000:00:05.0 on NUMA socket -1
EAL:   Invalid NUMA socket, default to 0
EAL:   probe driver: 1d0f:ec20 net_ena
EAL:   PCI memory mapped at 0x7f4a5ec00000
PMD: eth_ena_dev_init(): Initializing 0:0:5.0
mempool <WEKA MBUF pool>@0x7f495e597500
  flags=10
  pool=0x7f49b83bfe00
  phys_addr=0xf13797500
  nb_mem_chunks=1
  size=512000
  populated_size=512000
  header_size=64
  elt_size=5376
  trailer_size=0
  total_obj_size=5440
  private_data_size=64
  ops: "ring_sp_sc"
PMD: Set MTU: 4190
UDP RX checksum got x7d67 calculated x64ff
dump mbuf at 0x7f4a4c1ff280, phys=efffff300, buf_len=5248
  pkt_len=4097, ol_flags=b0000000000000, nb_segs=1, in_port=0
  segment at 0x7f4a4c1ff280, data=0x7f4a4c1ff3a2, data_len=4097
  Dump data at [0x7f4a4c1ff3a2], len=4097
Set MTU for port 0 to 4190
Port 0 MAC: 02 a0 0f 8f 30 39 IPv4 TX offload: yes UDP  TX offload: yes promiscuous: off ethernet multicast: off 
=== enable ethernet multicast
LocalPort IP 172.31.22.112
Peer IP: 172.31.19.191
add peer
dump mbuf at 0x7f49b8d0eac0, phys=e6cb0eb40, buf_len=5248
  pkt_len=0, ol_flags=0, nb_segs=1, in_port=255
  segment at 0x7f49b8d0eac0, data=0x7f49b8d0ebc0, data_len=0
[172.31.22.112] resolving 172.31.19.191 count 0
[172.31.22.112] peer found - 172.31.19.191
00000000: 0C 1F 0C 1F 0F DF 67 7D FF 05 05 00 00 00 00 00 | ......g}........
00000010: DA 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
00000020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
...
00000C30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
00000C40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
00000C50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4E 4F | ..............NO
00000C60: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000C70: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000C80: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000C90: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000CA0: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000CB0: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000CC0: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000CD0: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000CE0: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000CF0: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000D00: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000D10: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000D20: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000D30: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000D40: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000D50: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000D60: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000D70: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000D80: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000D90: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000DA0: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000DB0: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000DC0: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000DD0: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000DE0: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000DF0: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000E00: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000E10: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000E20: 20 44 4D 41 20 20 4E 4F 20 44 00 00 00 00 00 00 |  DMA  NO D......
00000E30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
00000E40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
...
00000FB0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
00000FC0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
00000FD0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4F | ...............O
00000FE0: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00000FF0: 20 44 4D 41 20 20 4E 4F 20 44 4D 41 20 20 4E 4F |  DMA  NO DMA  NO
00001000: 20 |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  
