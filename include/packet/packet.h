#ifndef __PACKET_H__
#define __PACKET_H__

#include "object.h"

typedef struct _packet_t                packet_t;
typedef uint16_t                        packet_len_t;           /**< Length in bytes, 2^16 = 65536  ==>  big enough */
typedef uint16_t                        packet_offset_t;        /**< Offset of origin */
typedef uint32_t                        packet_type_t;          /**< Bit-field variable PACKET_TYPE */

#include "packet/net_address.h"
#include "packet/raw_packet.h"
#include "packet/ethernet_header.h"

#define PACKET_TYPE_ETHERNET            0x00000001
#define PACKET_TYPE_VLAN                0x00000002
#define PACKET_TYPE_ARP                 0x00000004
#define PACKET_TYPE_IPV4                0x00000010
#define PACKET_TYPE_IPV6                0x00000020
#define PACKET_TYPE_UDPV4               0x00000100
#define PACKET_TYPE_TCPV4               0x00000200
#define PACKET_TYPE_UDPV6               0x00000400
#define PACKET_TYPE_TCPV6               0x00000800
#define PACKET_TYPE_IGNORE              0x80000000
#define PACKET_TYPE_ALL                 0x7fffffff

struct _packet_t {
    object_t                obj;
    packet_type_t           type;
    ethernet_header_t      *ether;
};

packet_t *      packet_new(void);
bool            packet_init(packet_t *packet);
bool            packet_encode(packet_t *packet, raw_packet_t *raw_packet);
packet_t       *packet_decode(raw_packet_t *raw_packet);

#endif

