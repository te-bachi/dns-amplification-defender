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
#include <net/if_var.h>
#include <net/if_vlan_var.h>

#include <ifaddrs.h>

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
    caddr_t                 buf, ptr;
    struct ifconf           ifc;
    struct ifreq           *ifcr;
    struct ifreq            ifr;
    struct vlanreq          vreq;
    int                     len;
    
    mac_address_t          *mac;
    ipv4_address_t         *ipv4_address;
    ipv4_address_t         *ipv4_broadcast;
    ipv4_address_t         *ipv4_netmask;
    ipv6_address_t         *ipv6_address;
    
    
    
    char           *addr_str;
    char           vlan_str[64];
    
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
    buf = NULL;
    do {
        /* allocate as much memory as ioctl wants to have */
        n *= 2;
        if ((buf = realloc(buf, PAGE_SIZE * n)) == NULL) {
            LOG_ERRNO(LOG_NETWORK_INTERFACE, LOG_ERROR, errno, ("realloc failed"));
        }
        bzero(buf, PAGE_SIZE * n);
        ifc.ifc_buf = buf;
        ifc.ifc_len = n * PAGE_SIZE;
        
    /* if not successfully, retry with more allocated memory */
    } while ((ioctl(sockfd, SIOCGIFCONF, &ifc) == -1) || (ifc.ifc_len >= ((n - 1) * PAGE_SIZE)));
    
    /* if ptr not reaches end of buf */
    for (ptr = buf; ptr < (buf + ifc.ifc_len); ) {
        ifcr = (struct ifreq *) ptr;
        len = ifcr->ifr_addr.sa_len;
        ptr += sizeof(ifcr->ifr_name) + len; 
        
        /* network interface name matches */
        if (strcmp(name, ifcr->ifr_name) == 0) {
        
            switch (ifcr->ifr_addr.sa_family) {
                case AF_INET:   //ipv4_address = (struct ipv4_address *)  &ifcr->ifr_addr;

                                break;
                
                case AF_INET6:  //sin6 = (struct sockaddr_in6 *) &ifcr->ifr_addr;
                                break;
                
                case AF_LINK:   //sdl  = (struct sockaddr_dl *)  &ifcr->ifr_addr;
                                break;
                                
                default:        continue;
            }
            
        }
        
        
        bzero((char *) &ifr, sizeof(ifr));
        strcpy(ifr.ifr_name, ifcr->ifr_name);
        bzero((char *) &vreq, sizeof(vreq));
        ifr.ifr_data = (caddr_t) &vreq;
        if (ioctl(sockfd, SIOCGETVLAN, &ifr) != -1) {
            snprintf(vlan_str, sizeof(vlan_str), "vid=%u parent=%s", vreq.vlr_tag, vreq.vlr_parent[0] == '\0' ? "<none>" : vreq.vlr_parent);
        } else {
            snprintf(vlan_str, sizeof(vlan_str), "no VLAN interface");
        }
        
        addr_str = sock_ntop_host((const struct sockaddr *) &ifcr->ifr_addr);
        printf("\t%s family=%u ip addr: %s vlan: %s\n", ifcr->ifr_name, ifcr->ifr_addr.sa_family, addr_str, vlan_str);

        //if ((ifrcopy.ifr_flags & IFF_UP) && ((ifrcopy.ifr_flags & IFF_LOOPBACK) == 0)) {
        //    strncpy(ifname, ifr->ifr_name, IFNAMSIZ); 
        //    break;
        //}
    }
    
    {
        struct ifaddrs         *myaddrs, *ifa;
        struct sockaddr_in     *s4;
        struct sockaddr_in     *s4broad;
        struct sockaddr_in     *s4net;
        struct sockaddr_in6    *s6;
        struct sockaddr_in6    *s6broad;
        struct sockaddr_in6    *s6net;
        struct sockaddr_dl     *sdl;
        struct sockaddr_dl     *sdlbroad;
        struct sockaddr_dl     *sdlnet;
        int                     status;
        char                    buf[64];
        char                    buf2[64];
        char                    buf3[64];
        
        status = getifaddrs(&myaddrs);
        if (status != 0) {
            perror("getifaddrs");
            exit(1);
        }
        
        for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;
            if ((ifa->ifa_flags & IFF_UP) == 0) continue;
            
            if (ifa->ifa_addr->sa_family == AF_INET) {
                s4      = (struct sockaddr_in *)(ifa->ifa_addr);
                s4broad = (struct sockaddr_in *)(ifa->ifa_broadaddr);
                s4net   = (struct sockaddr_in *)(ifa->ifa_netmask);
                if (inet_ntop(ifa->ifa_addr->sa_family, (void *)&(s4->sin_addr),      buf,  sizeof(buf))  == NULL ||
                    inet_ntop(ifa->ifa_addr->sa_family, (void *)&(s4broad->sin_addr), buf2, sizeof(buf2)) == NULL ||
                    inet_ntop(ifa->ifa_addr->sa_family, (void *)&(s4net->sin_addr),   buf3, sizeof(buf3)) == NULL) {
                    printf("%s: inet_ntop failed!\n", ifa->ifa_name);
                } else {
                    printf("%s: %s %s %s\n", ifa->ifa_name, buf, buf2, buf3);
                }
            } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                s6      = (struct sockaddr_in6 *)(ifa->ifa_addr);
                s6broad = (struct sockaddr_in6 *)(ifa->ifa_broadaddr);
                s6net   = (struct sockaddr_in6 *)(ifa->ifa_netmask);
                if (inet_ntop(ifa->ifa_addr->sa_family, (void *)&(s6->sin6_addr),      buf,  sizeof(buf))  == NULL ||
                    inet_ntop(ifa->ifa_addr->sa_family, (void *)&(s6net->sin6_addr),   buf3, sizeof(buf3)) == NULL) {
                    printf("%s: inet_ntop failed!\n", ifa->ifa_name);
                } else {
                    printf("%s: %s %s %s\n", ifa->ifa_name, buf, buf2, buf3);
                }
            } else if (ifa->ifa_addr->sa_family == AF_LINK) {
                sdl      = (struct sockaddr_dl *)(ifa->ifa_addr);
                sdlbroad = (struct sockaddr_dl *)(ifa->ifa_broadaddr);
                sdlnet   = (struct sockaddr_dl *)(ifa->ifa_netmask);
                
                if (sdl->sdl_alen > 0)
                    printf("%s: %s\n", ifa->ifa_name, ether_ntoa((const struct ether_addr *) LLADDR(sdl)));
                else
                    printf("%s: <Link#%d>\n", ifa->ifa_name, sdl->sdl_index);
            }
        }
        
        freeifaddrs(myaddrs);
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
network_interface_add_ipv4_address(network_interface_t *netif, const ipv4_address_t *address, const ipv4_address_t *broadcast, const ipv4_address_t *netmask, const ipv4_address_t *gateway)
{
    
}

bool
network_interface_add_ipv6_address(network_interface_t *netif, const ipv6_address_t *address, const uint8_t prefixlen, ipv6_state_t state)
{
    
}

