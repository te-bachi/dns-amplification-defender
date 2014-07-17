#include "packet/network_interface.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/param.h>

#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_dl.h>

static vlan_t       *network_interface_create_vlan(void);
static ipv4_alias_t *network_interface_create_ipv4_alias(void);
static ipv6_alias_t *network_interface_create_ipv6_alias(void);

static char * sock_ntop_host(const struct sockaddr *sa);

static char *
sock_ntop_host(const struct sockaddr *sa)
{
    static char str[128]; /* Unix domain is largest */

    switch (sa->sa_family) {
    case AF_INET: {
        struct sockaddr_in *sin = (struct sockaddr_in *) sa;

        if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
            return(NULL);
        return(str);
    }
    
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;

        if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL)
            return(NULL);
        return(str);
    }
    
    case AF_UNIX: {
        struct sockaddr_un *unp = (struct sockaddr_un *) sa;

            /* OK to have no pathname bound to the socket: happens on
every connect() unless client calls bind() first. */
        if (unp->sun_path[0] == 0)
            strcpy(str, "(no pathname bound)");
        else
            snprintf(str, sizeof(str), "%s", unp->sun_path);
        return(str);
    }
    
    case AF_LINK: {
        struct sockaddr_dl *sdl = (struct sockaddr_dl *) sa;

        if (sdl->sdl_alen > 0)
            //snprintf(str, sizeof(str), "%*s", sdl->sdl_alen, &sdl->sdl_data[sdl->sdl_nlen]);
            //ether_ntoa_r((const struct ether_addr *) &sdl->sdl_data[sdl->sdl_nlen], str);
            ether_ntoa_r((const struct ether_addr *) LLADDR(sdl), str);
        else
            snprintf(str, sizeof(str), "<Link#%d>", sdl->sdl_index);
        return(str);
    }
    
    default:
        snprintf(str, sizeof(str), "sock_ntop_host: unknown AF_xxx: %d",
                 sa->sa_family);
        return(str);
    }
    return (NULL);
}

bool
network_interface_init(network_interface_t *netif, const char *name)
{
    int                     sockfd;
    int                     n;
    struct ifconf           ifc;
    struct ifreq           *ifr;
    int                     ifr_num;
    int                     idx;
    
    struct sockaddr_in     *sin;
    struct sockaddr_in6    *sin6;
    struct sockaddr_dl     *sdl;
    
    char           *addr_str;
    
    /* string copy name */
    strncpy(netif->name, name, NETWORK_INTERFACE_NAME_SIZE);
    
    /* set to zero */
    memcpy(netif->mac.addr, MAC_ADDRESS_NULL.addr, MAC_ADDRESS_LEN);
    netif->vlan = NULL;
    netif->ipv4 = NULL;
    netif->ipv6 = NULL;
    
    /* create socket (required for ioctl) */
    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        LOG_ERRNO(LOG_NETWORK_INTERFACE, LOG_ERROR, errno, ("socket failed"));
        return false;
    }
    
    /* get interface configuration over ioctl */
    bzero(&ifc, sizeof(ifc));
    n   = 1;
    ifr = NULL;
    do {
        /* allocate as much memory as ioctl wants to have */
        n *= 2;
        if ((ifr = realloc(ifr, PAGE_SIZE * n)) == NULL) {
            LOG_ERRNO(LOG_NETWORK_INTERFACE, LOG_ERROR, errno, ("realloc failed"));
        }
        bzero(ifr, PAGE_SIZE * n);
        ifc.ifc_req = ifr;
        ifc.ifc_len = n * PAGE_SIZE;
        
    /* if not successfully, retry with more allocated memory */
    } while ((ioctl(sockfd, SIOCGIFCONF, &ifc) == -1) || (ifc.ifc_len >= ((n - 1) * PAGE_SIZE)));
    ifr_num = ifc.ifc_len / sizeof(struct ifreq);
    LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_ERROR, ("len = %d, ifr_num = %d", ifc.ifc_len, ifr_num));
    
    /* if ptr not reaches end of buf */
    for (idx = 0; idx < ifr_num; idx++) {
        
        /* network interface name matches */
        if (strcmp(name, ifr[idx].ifr_name) == 0) {
        
            switch (ifr[idx].ifr_addr.sa_family) {
                case AF_INET:   sin = (struct sockaddr_in *) &ifr[idx].ifr_addr;
                                break;
                
                case AF_INET6:  sin6 = (struct sockaddr_in6 *) &ifr[idx].ifr_addr;
                                break;
                
                case AF_LINK:   sdl = (struct sockaddr_dl *) &ifr[idx].ifr_addr;
                                break;
                                
                default:        continue;
            }
        }
        addr_str = sock_ntop_host((const struct sockaddr *) &ifr[idx].ifr_addr);
        printf("\t%s family=%u ip addr: %s\n", ifr[idx].ifr_name, ifr[idx].ifr_addr.sa_family, addr_str);

        //if ((ifrcopy.ifr_flags & IFF_UP) && ((ifrcopy.ifr_flags & IFF_LOOPBACK) == 0)) {
        //    strncpy(ifname, ifr->ifr_name, IFNAMSIZ); 
        //    break;
        //}
    }
    
    return true;
}

static vlan_t *
network_interface_create_vlan(void)
{
    return (vlan_t *) malloc(sizeof(vlan_t));
}

static ipv4_alias_t *
network_interface_create_ipv4_alias(void)
{
    return (ipv4_alias_t *) malloc(sizeof(ipv4_alias_t));
}

static ipv6_alias_t *
network_interface_create_ipv6_alias(void)
{
    return (ipv6_alias_t *) malloc(sizeof(ipv6_alias_t));
}

bool
network_interface_add_mac_address(network_interface_t *netif, const mac_address_t *mac)
{
    
}

bool
network_interface_add_vlan(network_interface_t *netif, const uint16_t vid)
{
    
}

bool
network_interface_add_ipv4_address(network_interface_t *netif, const ipv4_address_t *address, const ipv4_address_t *netmask, const ipv4_address_t *gateway)
{
    
}

bool
network_interface_add_ipv6_address(network_interface_t *netif, const ipv6_address_t *address, const uint8_t prefixlen, ipv6_state_t state)
{
    
}

