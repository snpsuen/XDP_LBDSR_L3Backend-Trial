#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int main(int argc, char *argv[]) {
        char* ifname;
        if (argc < 2)
                ifname = "eth0";
        else
                ifname = argv[1];

        unsigned int rc = if_nametoindex(ifname);
        if (rc) {
    
            printf("Interface [%s] has index : %d\n", ifname, rc);
        }
        else {
            printf("if_nametoindex error: %s\n", strerror(errno));
        }

        return rc;
}
