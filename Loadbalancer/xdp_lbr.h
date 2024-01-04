#define LADDR18(x) (unsigned int)(172 + (18 << 8) + (0 << 16) + (x << 24))
#define LADDR17(x) (unsigned int)(172 + (17 << 8) + (0 << 16) + (x << 24))
#define LEND(a, b, c, d) (unsigned int)(a + (b << 8) + (c << 16) + (d << 24))
#define BEND(a, b, c, d) (unsigned int)((a << 24) + (b << 16) + (c << 8) + d)

#define LBR 2
#define RTR 3
#define BKX 4
#define BKY 5
#define CUR 6

struct five_tuple {
    uint8_t  protocol;
    uint32_t ip_source;
    uint32_t ip_destination;
    uint16_t port_source;
    uint16_t port_destination;
};
