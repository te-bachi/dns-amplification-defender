#ifndef __HEADER_H__
#define __HEADER_H__

#include "packet/packet.h"
#include "packet/network_interface.h"
#include "packet/raw_packet.h"

typedef struct _header_t                header_t;
typedef enum   _header_type_t           header_type_t;
typedef struct _header_class_t          header_class_t;

#include "packet/header_storage.h"

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

typedef header_t     *(*header_new_fn)(void);
typedef void          (*header_free_fn)(header_t *header);
typedef header_t     *(*header_decode_fn)(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);
typedef packet_len_t  (*header_encode_fn)(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);

struct _header_class_t {
    header_type_t           type;
    uint16_t                size;
    header_free_fn          free;
};

/**
 * A header has has a next header (payload) and
 * could have a previous header (header)
 *
 * |_____________________|
 * |                     |
 * |     Next Header     | Layer n + 1
 * |_____________________|
 * |                     |
 * |       Header        | Layer n
 * |_____________________|
 * |                     |
 * |   Previous Header   | Layer n - 1
 * |_____________________|
 * |                     |
 *
 */
struct _header_t {
    header_class_t         *klass;
    header_storage_entry_t *entry;      /**< in what storage entry it was allocated so that it can be returned to the creator */
    uint32_t                idx;        /**< index in the allocated storage, used to return a header, @see header_storage_t */
    header_t               *prev;
    header_t               *next;
};

#endif

