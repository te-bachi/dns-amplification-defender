
#include "dns_defender.h"

int
main(int argc, char *argv[])
{
    
    if (dns_defender_init()) {
        dns_defender_mainloop();
    }
    
    return 0;
}
