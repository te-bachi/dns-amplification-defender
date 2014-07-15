
#include "pf.h"
#include "log.h"

#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include <stdlib.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/pfvar.h>
#include <arpa/inet.h>

const static char  *pf_device       = "/dev/pf";
const static int    pf_mode         = O_RDWR;
const static char  *pf_table_name   = "hacker";

static int pf_alter_ipv4_address(struct in_addr *addr, unsigned long request);

int
pf_add_ipv4_address(struct in_addr *addr)
{
    return pf_alter_ipv4_address(addr, DIOCRADDADDRS);
}

int
pf_remove_ipv4_address(struct in_addr *addr)
{
    return pf_alter_ipv4_address(addr, DIOCRDELADDRS);
}

static int
pf_alter_ipv4_address(struct in_addr *addr, unsigned long request)
{
    int                 dev;
    struct pfioc_table  io;
    struct pfr_table    table;
    struct pfr_addr     address;
    
    /* table */
    strncpy(table.pfrt_anchor, "",            sizeof(table.pfrt_anchor));
    strncpy(table.pfrt_name,   pf_table_name, sizeof(table.pfrt_name));
    table.pfrt_flags = 0;
    table.pfrt_fback = 0;
    
    /* address */
    bzero(&address, sizeof(struct pfr_addr));               /**< clean the whole struct, otherwise
                                                                 ioctl() failes with "Invalid argument" */
    address.pfra_ip4addr        = *addr;
    address.pfra_af             = AF_INET;
    address.pfra_net            = 32;                       /**< single IP */
    address.pfra_not            = 0;                        /**< not inverted */
    address.pfra_fback          = PFR_FB_NONE;              /**< no feeback */
    
    /* ioctl table */
    bzero(&io, sizeof(struct pfioc_table));
    io.pfrio_flags  = 0;
    io.pfrio_table  = table;
    io.pfrio_buffer = &address;
    io.pfrio_esize  = sizeof(struct pfr_addr);
    io.pfrio_size   = 1;
    
    dev = open(pf_device, pf_mode);
    if (dev == -1) {
        LOG_ERRNO(LOG_FIREWALL_PF, LOG_ERROR, errno, ("Couldn't open device %s", pf_device));
        goto pf_alter_ipv4_address_error;
    }
    
    if (ioctl(dev, request, &io)) {
        LOG_ERRNO(LOG_FIREWALL_PF, LOG_ERROR, errno, ("Couldn't manipulate device %s", pf_device));
        goto pf_alter_ipv4_address_error;
    }
    
    switch (request) {
        case DIOCRADDADDRS: LOG_PRINTLN(LOG_FIREWALL_PF, LOG_INFO, ("Add %" PRIu8 " IPv4 %s", io.pfrio_nadd, io.pfrio_nadd > 1 ? "addresses" : "address"));       break;
        case DIOCRDELADDRS: LOG_PRINTLN(LOG_FIREWALL_PF, LOG_INFO, ("Remove %" PRIu8 " IPv4 %s", io.pfrio_ndel, io.pfrio_nadd > 1 ? "addresses" : "address"));    break;
    }
    
    return 0;
    
pf_alter_ipv4_address_error:
    if (dev != -1) {
        if (close(dev) == -1) {
            LOG_ERRNO(LOG_FIREWALL_PF, LOG_ERROR, errno, ("Couldn't close device %s", pf_device));
        }
    }
    return -1;
}

