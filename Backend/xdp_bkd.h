#include "vmlinux.h"

#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif

#ifndef BPF_RB_FORCE_WAKEUP
#define BPF_RB_FORCE_WAKEUP 2
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef BPF_ANY
#define BPF_ANY 0
#endif
 
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 0)
#endif

#define LADDR18(x) (unsigned int)(172 + (18 << 8) + (0 << 16) + (x << 24))
#define LADDR17(x) (unsigned int)(172 + (17 << 8) + (0 << 16) + (x << 24))
#define LEND(a, b, c, d) (unsigned int)(a + (b << 8) + (c << 16) + (d << 24))
#define BEND(a, b, c, d) (unsigned int)((a << 24) + (b << 16) + (c << 8) + d)

#define LBR 2
#define RTR 3
#define BKX 4
#define BKY 5
#define CUR 6

/*
struct xdp_md {
  __u32 data;
  __u32 data_end;
  __u32 data_meta;
  __u32 ingress_ifindex;
  __u32 rx_queue_index;
  __u32 egress_ifindex;
};
*/

struct five_tuple {
    uint8_t  protocol;
    uint32_t ip_source;
    uint32_t ip_destination;
    uint16_t port_source;
    uint16_t port_destination;
};
