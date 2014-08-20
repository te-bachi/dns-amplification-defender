#ifndef __ETHERNET_HEADER_H__
#define __ETHERNET_HEADER_H__

typedef struct _ethernet_header_t       ethernet_header_t;

#include "packet/packet.h"
#include "packet/ipv4_header.h"

/* length on the wire! */
#define ETHERNET_HEADER_LEN             14
#define VLAN_HEADER_LEN                 18

#define ETHERNET_HEADER_OFFSET_DEST     0
#define ETHERNET_HEADER_OFFSET_SRC      6
#define ETHERNET_HEADER_OFFSET_TYPE     12
#define VLAN_HEADER_OFFSET_VLAN         14
#define VLAN_HEADER_OFFSET_TYPE         16

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP                   0x0806
#endif

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN                  0x8100
#endif

#ifndef ETHERTYPE_IPV4
#define ETHERTYPE_IPV4                  0x0800
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6                  0x86DD
#endif

typedef struct _vlan_header_t {
    union {
        uint16_t        tci;            /* Tag Control Information */
        struct {
            uint16_t    vid : 12;       /* VLAN Identifier */
            uint16_t    dei : 1;        /* Drop Eligible Indicator (former CFI - Canonical Format Indicator) */
            uint16_t    pcp : 3;        /* Priority Code Point (= Priority) */
        };
    };
    uint16_t            type;
} vlan_header_t;

struct _ethernet_header_t {
    header_t            header;
    
    mac_address_t       dest;
    mac_address_t       src;
    uint16_t            type;
    vlan_header_t       vlan;
};

bool                ethernet_header_init    (void); // used?
ethernet_header_t  *ethernet_header_new     (void);
void                ethernet_header_free    (header_t *header);
packet_len_t        ethernet_header_encode  (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);
header_t           *ethernet_header_decode  (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);

#endif

