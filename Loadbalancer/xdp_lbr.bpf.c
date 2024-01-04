#include "xdp_lbr.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct five_tuple);
	__type(value, uint32_t);
	__uint(max_entries, 100000);
} forward_flow SEC(".maps");

static __always_inline int ip_decrease_ttl(struct iphdr *iph) {
	u32 check = (__force u32)iph->check;

	check += (__force u32)htons(0x0100);
	iph->check = (__force __sum16)(check + (check >= 0xFFFF));
	return --iph->ttl;
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
		
	if (bpf_ntohl(iph->daddr) == LEND(192, 168, 25, 10)) {
		struct five_tuple forward_key = {};
		forward_key.protocol = iph->protocol;
		forward_key.ip_source = bpf_ntohl(iph->saddr);
		forward_key.ip_destination = bpf_ntohl(iph->daddr);
		forward_key.port_source = bpf_ntohs(tcph->source);
		forward_key.port_destination = bpf_ntohs(tcph->dest);

        forward_backend = bpf_map_lookup_elem(&forward_flow, &forward_key);
        if (forward_backend == NULL) {
			/* backend = BKX + (bpf_get_prandom_u32() % 2); */
			backend = BKX;
            bpf_map_update_elem(&forward_flow, &forward_key, &backend, BPF_ANY);
			bpf_printk("Added a new entry to the forward flow table for the backend ID %d", backend);			
        }
        else {
			backend = *forward_backend;
            bpf_printk("Located the backend ID %d from an existing entry in the forward flow table ", backend);
        }
           
        iph->daddr = bpf_htonl(LADDR18(backend));
		bpf_printk("Packet to be forwrded to the backend address %x", LADDR18(backend));     
		
		struct bpf_fib_lookup fib_params = {};
		fib_params.family = AF_INET;
        fib_params.tos = iph->tos;
        fib_params.l4_protocol = iph->protocol;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = bpf_ntohs(iph->tot_len);
        fib_params.ipv4_src = bpf_ntohl(iph->saddr);
        fib_params.ipv4_dst = bpf_ntohl(iph->daddr);
        fib_params.ifindex = ctx->ingress_ifindex;
		
		rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
        bpf_printk("Looked up relevant information in the FIB table with rc %d", rc);
		
		if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
			bpf_printk("Found fib_params.dmac = %x:%x:%x", fib_params.dmac[3], fib_params.dmac[4], fib_params.dmac[5]);
            bpf_printk("Found fib_params.smac = %x:%x:%x", fib_params.smac[3], fib_params.smac[4], fib_params.smac[5]);
                
            /* ip_decrease_ttl(iph); */
			ip_decrease_ttl(iph);
            memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
            memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
            
            /* bpf_printk("Calling fib_params_redirect ...");
            return bpf_redirect(fib_params.ifindex, 0); */
            
            bpf_printk("Before XDP_TX, iph->saddr = %x, iph->daddr = %x", iph->saddr, iph->daddr);
			bpf_printk("Before XDP_TX, eth->h_source[5] = %x, eth->h_dest[5] = %x", eth->h_source[5], eth->h_dest[5]);
            bpf_printk("Returning XDP_TX ...");
			
			return XDP_TX;
		}
	}
		
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
