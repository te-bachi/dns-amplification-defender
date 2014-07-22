#ifndef __UDPV4_HEADER_H__
#define __UDPV4_HEADER_H__

typedef struct _udpv4_header_t              udpv4_header_t;

#include "packet/packet.h"
#include "packet/dns_header.h"

/* length on the wire! */
#define UDPV4_HEADER_LEN                    8

#define UDPV4_HEADER_OFFSET_SRC_PORT        0
#define UDPV4_HEADER_OFFSET_DEST_PORT       2
#define UDPV4_HEADER_OFFSET_LEN             4
#define UDPV4_HEADER_OFFSET_CHECKSUM        6

#define UDPV4_HEADER_PSEUDO_IPV4_SRC        12
#define UDPV4_HEADER_PSEUDO_IPV4_DEST       8
#define UDPV4_HEADER_PSEUDO_IPV4_ZERO       4
#define UDPV4_HEADER_PSEUDO_IPV4_PROTOCOL   3
#define UDPV4_HEADER_PSEUDO_IPV4_LEN        2

struct _udpv4_header_t {
    header_t        header;
    
    uint16_t        src_port;
    uint16_t        dest_port;
    uint16_t        len;
    uint16_t        checksum;
};

udpv4_header_t *udpv4_header_new    (void);
void            udpv4_header_free   (udpv4_header_t *udpv4);
packet_len_t    udpv4_header_encode (ipv4_header_t *ipv4, raw_packet_t *raw_packet, packet_offset_t udpv4_offset);
udpv4_header_t *udpv4_header_decode (                     raw_packet_t *raw_packet, packet_offset_t udpv4_offset);

#endif

