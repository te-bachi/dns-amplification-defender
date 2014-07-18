#include "packet/network_interface.h"
#include "log.h"
#include "log_network.h"

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

#define INADDR(x)   ((struct sockaddr_in  *) x)
#define INADDR6(x)  ((struct sockaddr_in6 *) x)
#define LADDR(x)    ((struct sockaddr_dl  *) x)

static vlan_t       *network_interface_create_vlan(void);
static ipv4_alias_t *network_interface_create_ipv4_alias(void);
static ipv6_alias_t *network_interface_create_ipv6_alias(void);

bool
network_interface_init(network_interface_t *netif, const char *name)
{
    int                     sockfd;
    struct ifaddrs         *ifas;
    struct ifaddrs         *ifa;
    struct ifreq            ifr;
    struct vlanreq          vreq;
    
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
    
    /* get interface addresses */
    if (getifaddrs(&ifas) != 0) {
         LOG_ERRNO(LOG_NETWORK_INTERFACE, LOG_ERROR, errno, ("getifaddrs failed"));
        return false;
    }
    
    for (ifa = ifas; ifa != NULL; ifa = ifa->ifa_next) {
        if ((ifa->ifa_addr)           == NULL) continue;
        if ((ifa->ifa_flags & IFF_UP) == 0)    continue;
        
        
        /* network interface name matches */
        if (strcmp(name, ifa->ifa_name) == 0) {
            
            switch (ifa->ifa_addr->sa_family) {
                case AF_INET:   network_interface_add_ipv4_address(netif,
                                                                   IPV4_ADDRESS(&(INADDR(ifa->ifa_addr)->sin_addr)),
                                                                   IPV4_ADDRESS(&(INADDR(ifa->ifa_netmask)->sin_addr)),
                                                                   IPV4_ADDRESS(&(INADDR(ifa->ifa_broadaddr)->sin_addr)),
                                                                   NULL);
                                break;
                
                case AF_INET6:  network_interface_add_ipv6_address(netif,
                                                                   IPV6_ADDRESS(&(INADDR6(ifa->ifa_addr)->sin6_addr)),
                                                                   IPV6_ADDRESS(&(INADDR6(ifa->ifa_netmask)->sin6_addr)),
                                                                   IPV6_STATE_VALID);
                                break;
                
                case AF_LINK:   network_interface_add_mac_address(netif,
                                                                  MAC_ADDRESS(LLADDR(LADDR(ifa->ifa_addr))));
                                
                                bzero((char *) &ifr, sizeof(ifr));
                                bzero((char *) &vreq, sizeof(vreq));
                                strncpy(ifr.ifr_name, netif->name, NETWORK_INTERFACE_NAME_SIZE);
                                ifr.ifr_data = (caddr_t) &vreq;
                                if (ioctl(sockfd, SIOCGETVLAN, &ifr) != -1) {
                                    network_interface_add_vlan(netif, vreq.vlr_tag);
                                }
                                break;
                
                default:        continue;
            }
        }
    }
    
    freeifaddrs(ifas);
    
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
    if (LOG_ENABLE(LOG_NETWORK_INTERFACE, LOG_INFO)) {
        LOG_MAC(mac, mac_str);
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_INFO, ("add_mac_address:        mac = %s", mac_str));
    }
    
    return true;
}

bool
network_interface_add_vlan(network_interface_t *netif, const uint16_t vid)
{
    vlan_t *vlan;
    
    if (LOG_ENABLE(LOG_NETWORK_INTERFACE, LOG_INFO)) {
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_INFO, ("add_vlan:               vid = %u", vid));
    }
    
    if (netif->vlan != NULL) {
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_WARNING, ("overwrite VLAN       vid = %u", netif->vlan->vid));
    }
    
    vlan = network_interface_create_vlan();
    netif->vlan = vlan;
    
    return true;
}

bool
network_interface_add_ipv4_address(network_interface_t *netif, const ipv4_address_t *address, const ipv4_address_t *netmask, const ipv4_address_t *broadcast, const ipv4_address_t *gateway)
{
    ipv4_alias_t *ipv4;
    
    if (LOG_ENABLE(LOG_NETWORK_INTERFACE, LOG_INFO)) {
        LOG_IPV4(address,   address_str);
        LOG_IPV4(broadcast, broadcast_str);
        LOG_IPV4(netmask,   netmask_str);
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_INFO, ("add_ipv4_address:   address = %s", address_str));
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_INFO, ("add_ipv4_address:   netmask = %s", netmask_str));
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_INFO, ("add_ipv4_address: broadcast = %s", broadcast_str));
    }
    
    ipv4 = network_interface_create_ipv4_alias();
    ipv4->next  = netif->ipv4;
    netif->ipv4 = ipv4;
    
    return true;
}

bool
network_interface_add_ipv6_address(network_interface_t *netif, const ipv6_address_t *address, const ipv6_address_t *netmask, const ipv6_state_t state)
{
    ipv6_alias_t *ipv6;
    
    if (LOG_ENABLE(LOG_NETWORK_INTERFACE, LOG_INFO)) {
        LOG_IPV6(address, address_str);
        LOG_IPV6(netmask, netmask_str);
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_INFO, ("add_ipv6_address:   address = %s", address_str));
        LOG_PRINTLN(LOG_NETWORK_INTERFACE, LOG_INFO, ("add_ipv6_address:   netmask = %s", netmask_str));
    }
    
    ipv6 = network_interface_create_ipv6_alias();
    ipv6->next  = netif->ipv6;
    netif->ipv6 = ipv6;
    
    return true;
}

