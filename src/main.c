

#ifdef UNIT_TEST

#include "unittest/unittest.h"

#else

#include "config.h"
#include "dns_defender.h"

#endif

int
main(int argc, char *argv[])
{
#ifdef UNIT_TEST
    
    
    
#else
    config_t config = {
        .ifname     = "re0",
        .timeout    = 1
    };
    
    if (dns_defender_init(&config)) {
        dns_defender_mainloop();
    }
#endif
    
    return 0;
}
