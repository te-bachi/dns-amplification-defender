
#include "config.h"
#include "dns_defender.h"

int
main(int argc, char *argv[])
{
    config_t config = {
        .ifname     = "vr1",
        .timeout    = 500
    };
    
    if (dns_defender_init(&config)) {
        dns_defender_mainloop();
    }
    
    return 0;
}
