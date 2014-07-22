#ifndef __PACKET_H__
#define __PACKET_H__

#include "object.h"

typedef struct _packet_t                packet_t;
typedef struct _header_t                header_t;
typedef enum   _header_type_t           header_type_t;
typedef uint16_t                        packet_len_t;           /**< Length in bytes, 2^16 = 65536  ==>  big enough */
typedef uint16_t                        packet_offset_t;        /**< Offset of origin */

enum _header_type_t {
    PACKET_TYPE_ETHERNET,
    PACKET_TYPE_VLAN,
    PACKET_TYPE_ARP,
    PACKET_TYPE_IPV4,
    PACKET_TYPE_IPV6,
    PACKET_TYPE_UDPV4,
    PACKET_TYPE_TCPV4,
    PACKET_TYPE_UDPV6,
    PACKET_TYPE_TCPV6,
    PACKET_TYPE_DNS,
    PACKET_TYPE_IGNORE,
    PACKET_TYPE_ALL
};

/**
 * A header has has a next header (payload) and
 * could have a previous header (header)
 *
 * |_____________________|
 * |                     |
 * |     Next Header     |
 * |_____________________|
 * |                     |
 * |       Header        |
 * |_____________________|
 * |                     |
 * |   Previous Header   |
 * |_____________________|
 * |                     |
 *
 */
struct _header_t {
    header_type_t           type;
    header_t               *prev;
    header_t               *next;
};

#include "packet/net_address.h"
#include "packet/network_interface.h"
#include "packet/raw_packet.h"
#include "packet/ethernet_header.h"

/**
 * A packet has only a payload (Layer 2)
 */
struct _packet_t {
    object_t                obj;
    header_t               *payload;
};

packet_t *      packet_new      (void);
bool            packet_init     (packet_t *packet);
bool            packet_encode   (netif_t *netif, raw_packet_t *raw_packet, packet_t *packet);
packet_t       *packet_decode   (netif_t *netif, raw_packet_t *raw_packet);

#endif

