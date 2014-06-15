#ifndef __DNS_HEADER_H__
#define __DNS_HEADER_H__

typedef struct _dns_header_t                dns_header_t;

#include "packet/packet.h"

/* length on the wire! */
#define DNS_HEADER_LEN                      8

#define DNS_HEADER_OFFSET_SRC_PORT          0
#define DNS_HEADER_OFFSET_DEST_PORT         2
#define DNS_HEADER_OFFSET_LEN               4
#define DNS_HEADER_OFFSET_CHECKSUM          6

#define DNS_HEADER_HEADER_OPCODE_QUERY      0
#define DNS_HEADER_HEADER_OPCODE_IQUERY     1
#define DNS_HEADER_HEADER_OPCODE_STATUS     2
#define DNS_HEADER_HEADER_OPCODE_NOTIFY     4
#define DNS_HEADER_HEADER_OPCODE_UPDATE     5

/**
 *  +---------------------+
 *  |        Header       |
 *  +---------------------+
 *  |       Question      | the question for the name server
 *  +---------------------+
 *  |        Answer       | RRs answering the question
 *  +---------------------+
 *  |      Authority      | RRs pointing toward an authority
 *  +---------------------+
 *  |      Additional     | RRs holding additional information
 *  +---------------------+
 */

typedef struct _dns_domain_name_t {
    uint8_t                         len;
    uint8_t                        *value;
    struct _dns_domain_name_t      *next;
} dns_domain_name_t;

typedef struct _dns_query_section_t {
    dns_domain_name_t              *qname;
    uint16_t                        qtype;
    uint16_t                        qclass;
    struct _dns_query_section_t    *next;
} dns_query_section_t;

struct _dns_header_t {                     
    uint16_t                        id;             /**< Identifier */
    struct {                        
        uint16_t                    rcode   : 4;    /**< Response Code */
        uint16_t                    cd      : 1;    /**< Checking Disabled */
        uint16_t                    ad      : 1;    /**< Authentic Data */
        uint16_t                    z       : 1;    /**< Reserved for future use */
        uint16_t                    ra      : 1;    /**< Recursion Available */
        uint16_t                    rd      : 1;    /**< Recursion Desired */
        uint16_t                    tc      : 1;    /**< TrunCation */
        uint16_t                    aa      : 1;    /**< Authoritative Answer */
        uint16_t                    opcode  : 4;    /**< Operation Code */
        uint16_t                    qr      : 1;    /**< Query / Response */
    } flags;                        
    uint16_t                        qd_count;       /**< Number of entries in the question section */
    uint16_t                        an_count;       /**< Number of resource records in the answer section */
    uint16_t                        ns_count;       /**< Number of name server resource records in the authority records section */
    uint16_t                        ar_count;       /**< Number of resource records in the additional records section */
};

dns_header_t   *dns_header_new      (void);
bool            dns_header_free     (dns_header_t *dns_header);
packet_len_t    dns_header_encode   (packet_t *packet, raw_packet_t *raw_packet, packet_offset_t dns_offset);
void            dns_header_decode   (packet_t *packet, raw_packet_t *raw_packet, packet_offset_t dns_offset);

#endif

