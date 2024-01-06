#include "xdp_bkd.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int dispatchworkload(struct xdp_md *ctx) {
	void* data_end = (void*)(long)ctx->data_end;
	void* data = (void*)(long)ctx->data;
	
	struct ethhdr* eth = (struct ethhdr*)data;
	if ((void*)eth + sizeof(struct ethhdr) > data_end)
		return XDP_ABORTED;
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return XDP_PASS;
	
	struct iphdr* iph = (struct iphdr*)((void*)eth + sizeof(struct ethhdr));
	if ((void*)iph + sizeof(struct iphdr) > data_end)
		return XDP_ABORTED;	
	if (iph->protocol != IPPROTO_TCP)
		return XDP_PASS;
	
	struct tcphdr* tcph = (struct tcphdr*)((void*)iph + sizeof(struct iphdr));
	if ((void*)tcph + sizeof(struct tcphdr) > data_end)
		return XDP_ABORTED;
		
	if ((bpf_ntohl(iph->daddr) == VAL19(BKX)) || (bpf_ntohl(iph->daddr) == VAL19(BKY))) {
		if ((bpf_ntohl(iph->saddr) & QUAD2V(255, 255, 255, 0)) != VAL19(0)) {
			iph->daddr = bpf_htonl(QUAD2V(192, 168, 25, 10));
			uint8_t* daddr = uint2quad(&(iph->daddr));
			bpf_printk("Packet to be forwrded to the backend address Q1.%u.%u.%u\n", daddr[1], daddr[2], daddr[3]);
		}
	}
		
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
