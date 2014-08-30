#ifndef __PACKET_H__
#define __PACKET_H__

#include "object.h"

typedef struct _packet_t                packet_t;
typedef enum   _packet_direction_t      packet_direction_t;
typedef uint16_t                        packet_len_t;           /**< Length in bytes, 2^16 = 65536  ==>  big enough */
typedef uint16_t                        packet_offset_t;        /**< Offset of origin */

#define PRIoffset   PRIu16

#include "packet/header.h"
#include "packet/net_address.h"
#include "packet/network_interface.h"
#include "packet/raw_packet.h"

enum _packet_direction_t {
    PACKET_DIRECTION_UNKOWN,
    PACKET_DIRECTION_INGRESS,   /**< entering */
    PACKET_DIRECTION_EGRESS     /**< exiting */
};

/**
 * A packet has only a payload (Layer 2)
 */
struct _packet_t {
    object_t                obj;
    packet_direction_t      direction;
    header_t               *head;
    header_t               *tail;
};

bool            packet_init     (void);
packet_t *      packet_new      (void);
bool            packet_encode   (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet);
packet_t       *packet_decode   (netif_t *netif,                   raw_packet_t *raw_packet);

#endif

