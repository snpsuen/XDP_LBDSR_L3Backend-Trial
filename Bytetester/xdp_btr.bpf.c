#include "xdp_btr.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/string.h>

#define __force __attribute__((force))

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __type(key, struct five_tuple);
        __type(value, uint32_t);
        __uint(max_entries, 100000);
} forward_flow SEC(".maps");

static __always_inline int ip_decrease_ttl(struct iphdr *iph) {
        u32 check = (__force u32)iph->check;
        check += (__force u32)bpf_htons(0x0100);
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


        uint8_t iphdaddr[4], iphsaddr[4];
        memcpy(iphdaddr, &(iph->daddr), 4);
        memcpy(iphsaddr, &(iph->saddr), 4);

        bpf_printk("iph->daddr = %u\n", iph->daddr);
        bpf_printk("bpf_ntohl(iph->daddr) = %u\n", bpf_ntohl(iph->daddr));
        bpf_printk("iphdaddr[0] = %u, iphdaddr[1] = %u, iphdaddr[2] = %u,", iphdaddr[0],  iphdaddr[1], iphdaddr[2]);
        bpf_printk("iphdaddr[3] = %u\n", iphdaddr[3]);

        uint32_t iph_daddr = iphdaddr[0] * 256 * 256 * 256 + iphdaddr[1] * 256 * 256 +  iphdaddr[2] * 256 + iphdaddr[3];
        bpf_printk("In big endian, iph_daddr = %u\n", iph_daddr);

        bpf_printk("iph->saddr = %u\n", iph->saddr);
        bpf_printk("bpf_ntohl(iph->saddr) = %u\n", bpf_ntohl(iph->saddr));
        bpf_printk("iphsaddr[0] = %u, iphsaddr[1] = %u, iphsaddr[2] = %u,", iphsaddr[0],  iphsaddr[1], iphsaddr[2]);
        bpf_printk("iphsaddr[3] = %u\n", iphsaddr[3]);

        uint32_t iph_saddr = iphsaddr[0] * 256 * 256 * 256 + iphsaddr[1] * 256 * 256 +  iphsaddr[2] * 256 + iphsaddr[3];
        bpf_printk("In big endian, iph_saddr = %u\n", iph_saddr);

        return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
