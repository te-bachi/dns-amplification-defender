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
    static char str[128];       /* Unix domain is largest */

    switch (sa->sa_family) {
    case AF_INET: {
        struct sockaddr_in  *sin = (struct sockaddr_in *) sa;

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
        struct sockaddr_un  *unp = (struct sockaddr_un *) sa;

            /* OK to have no pathname bound to the socket: happens on
               every connect() unless client calls bind() first. */
        if (unp->sun_path[0] == 0)
            strcpy(str, "(no pathname bound)");
        else
            snprintf(str, sizeof(str), "%s", unp->sun_path);
        return(str);
    }
    
    case AF_LINK: {
        struct sockaddr_dl  *sdl = (struct sockaddr_dl *) sa;

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
    int             sockfd;
    struct ifconf   ifc;
    char            start_buf[8];
    caddr_t         buf, ptr, cptr;
    struct ifreq   *ifr;
    struct ifreq    ifrcopy;
    int             len = 1024;
    int             lastlen;
    char           *sdlname;
    int             idx;
    char           *haddr;
    int             hlen;
    char            ifname[IFNAMSIZ];
    char           *addr_str;
    
    struct sockaddr      sa;
    struct sockaddr_in  *sinptr;
    struct sockaddr_in6 *sin6ptr;
    struct sockaddr_un  *unp;
    struct sockaddr_dl  *sdl;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    
    ifc.ifc_len = 8;
    ifc.ifc_buf = start_buf;
    
    if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_ERROR, ("ioctl 1: len=%d", ifc.ifc_len));
        return false;
    }
    LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_ERROR, ("ioctl 1: len=%d", ifc.ifc_len));
    
    if ((buf = malloc(ifc.ifc_len)) == NULL) {
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_ERROR, ("malloc"));
        return false;
    }
    
    ifc.ifc_buf = buf;
    
    if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_ERROR, ("ioctl 2: len=%d", ifc.ifc_len));
        return false;
    }
    
    for (ptr = buf; ptr < buf + ifc.ifc_len; ) {
        ifr = (struct ifreq *) ptr;

        len = ifr->ifr_addr.sa_len;
        ptr += sizeof(ifr->ifr_name) + len; 
        // 
        // if (ifr->ifr_addr.sa_family == AF_LINK) {
            // struct sockaddr_dl *sdl = (struct sockaddr_dl *) &ifr->ifr_addr;
            // sdlname = ifr->ifr_name;
            // idx = sdl->sdl_index;
            // haddr = sdl->sdl_data + sdl->sdl_nlen;
            // hlen = sdl->sdl_alen;
        // }
            
        // if ( (cptr = strchr(ifr->ifr_name, ':')) != NULL)
            // *cptr = 0;      /* replace colon with null */
            // 
        // ifrcopy = *ifr;
        // if (ioctl(sockfd, SIOCGIFFLAGS, &ifrcopy) < 0)
            // printf("ioctl");
        // 
        // if (sdlname == NULL || strcmp(sdlname, ifr->ifr_name) != 0)
            // idx = hlen = 0;
            // 
        // if (hlen)
            // memcpy(&sa, haddr, hlen);

        /*
        switch (ifr->ifr_addr.sa_family) {
        case AF_INET:
            sinptr = (struct sockaddr_in *) &ifr->ifr_addr;
            addr_str = sock_ntop_host((const struct sockaddr *) sinptr, sizeof(struct sockaddr_in));
            break;

        case AF_INET6:
            sin6ptr = (struct sockaddr_in6 *) &ifr->ifr_addr;
            addr_str = sock_ntop_host((const struct sockaddr *) sin6ptr, sizeof(struct sockaddr_in6));
        
        case AF_LINK:
            sdl = (struct sockaddr_dl *) &ifr->ifr_addr;
            sdlname = ifr->ifr_name;
            idx = sdl->sdl_index;
            haddr = sdl->sdl_data + sdl->sdl_nlen;
            hlen = sdl->sdl_alen;
            addr_str = sock_ntop_host((const struct sockaddr *) sdl, sizeof(struct sockaddr_dl));
        default:
            
            break;
        }
        */
        addr_str = sock_ntop_host((const struct sockaddr *) &ifr->ifr_addr);
        printf("\t%s family=%u ip addr: %s\n", ifr->ifr_name, ifr->ifr_addr.sa_family, addr_str);

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

