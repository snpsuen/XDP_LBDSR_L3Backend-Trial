#include "xdp_bkd.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

static __always_inline uint8_t* uint2quad(uint32_t* numptr) {
        uint8_t* quad = (uint8_t*)((void*)numptr);
        return quad;
}

static __always_inline uint32_t quad2uint(uint8_t quad0, uint8_t quad1, uint8_t quad2, uint8_t quad3) {
        uint32_t result = quad0 * 256 * 256 * 256 + quad1 * 256 * 256 + quad2 * 256 + quad3;
        return result;
}

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
		
	if ((bpf_ntohl(iph->daddr) == quad2uint(172, 19, 0, BKX)) || (bpf_ntohl(iph->daddr) == quad2uint(172, 19, 0, BKY))) {
		if ((bpf_ntohl(iph->saddr) & quad2uint(255, 255, 255, 0)) != quad2uint(172, 19, 0, 0)) {
			iph->daddr = bpf_htonl(quad2uint(192, 168, 25, 10));
			uint8_t* daddr = uint2quad(&(iph->daddr));
			bpf_printk("Backend>> Packet to be dispatched to the backend IP Q1: %u ", daddr[0]);
			bpf_printk("Backend>> Packet to be dispatched to the backend IP Q1.%u.%u.%u\n", daddr[1], daddr[2], daddr[3]);
			
			iph->check = iph_csum(iph);
			iph->ttl--;
		}
	}
		
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
