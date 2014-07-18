#ifndef __NETWORK_INTERFACE_H__
#define __NETWORK_INTERFACE_H__

#include <stdint.h>
#include <stdbool.h>

#include "packet/net_address.h"

#define NETWORK_INTERFACE_NAME_SIZE     16

typedef enum _ipv6_state_t {
    IPV6_STATE_INVALID      = 0x00,
    IPV6_STATE_TENTATIVE    = 0x08,
    IPV6_STATE_TENTATIVE_1  = 0x09, /* 1 probe sent */
    IPV6_STATE_TENTATIVE_2  = 0x0a, /* 2 probes sent */
    IPV6_STATE_TENTATIVE_3  = 0x0b, /* 3 probes sent */
    IPV6_STATE_TENTATIVE_4  = 0x0c, /* 4 probes sent */
    IPV6_STATE_TENTATIVE_5  = 0x0d, /* 5 probes sent */
    IPV6_STATE_TENTATIVE_6  = 0x0e, /* 6 probes sent */
    IPV6_STATE_TENTATIVE_7  = 0x0f, /* 7 probes sent */
    IPV6_STATE_VALID        = 0x10,
    IPV6_STATE_PREFERRED    = 0x30,
    IPV6_STATE_DEPRECATED   = 0x50,
} ipv6_state_t;

typedef struct _ipv4_alias_t    ipv4_alias_t;
typedef struct _ipv6_alias_t    ipv6_alias_t;
typedef struct _vlan_t          vlan_t;

struct _ipv4_alias_t {
    ipv4_address_t          address;
    ipv4_address_t          broadcast;
    ipv4_address_t          netmask;
    ipv4_address_t          gateway;
    ipv4_alias_t           *next;
};

struct _ipv6_alias_t {
    ipv6_address_t          address;
    ipv6_address_t          netmask;
    uint8_t                 prefixlen;
    ipv6_state_t            state;
    ipv6_alias_t           *next;
};

struct _vlan_t {
    uint16_t                vid;
};

typedef struct _network_interface_t {
    char                    name[NETWORK_INTERFACE_NAME_SIZE];
    mac_address_t           mac;
    
    vlan_t                 *vlan;
    ipv4_alias_t           *ipv4;
    ipv6_alias_t           *ipv6;
} network_interface_t;

bool        network_interface_init              (network_interface_t *netif, const char *name);
bool        network_interface_add_mac_address   (network_interface_t *netif, const mac_address_t *mac);
bool        network_interface_add_vlan          (network_interface_t *netif, const uint16_t vid);
bool        network_interface_add_ipv4_address  (network_interface_t *netif, const ipv4_address_t *address, const ipv4_address_t *netmask, const ipv4_address_t *broadcast, const ipv4_address_t *gateway);
bool        network_interface_add_ipv6_address  (network_interface_t *netif, const ipv6_address_t *address, const ipv6_address_t *netmask, const ipv6_state_t state);

#endif

