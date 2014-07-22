#ifndef __DNS_HEADER_H__
#define __DNS_HEADER_H__

typedef struct _dns_header_t                dns_header_t;
typedef struct _dns_label_t                 dns_label_t;
typedef struct _dns_query_t                 dns_query_t;
typedef struct _dns_resource_record_t       dns_resource_record_t;

#include "packet/packet.h"

/* length on the wire! */
#define DNS_HEADER_LEN                      12

#define DNS_HEADER_OFFSET_ID                0
#define DNS_HEADER_OFFSET_FLAGS             2
#define DNS_HEADER_OFFSET_QD_COUNT          4
#define DNS_HEADER_OFFSET_AN_COUNT          6
#define DNS_HEADER_OFFSET_NS_COUNT          8
#define DNS_HEADER_OFFSET_AR_COUNT          10

#define DNS_HEADER_OPCODE_QUERY             0
#define DNS_HEADER_OPCODE_IQUERY            1
#define DNS_HEADER_OPCODE_STATUS            2
#define DNS_HEADER_OPCODE_NOTIFY            4
#define DNS_HEADER_OPCODE_UPDATE            5

#define DNS_HEADER_RCODE_NO_ERROR           0
#define DNS_HEADER_RCODE_FORM_ERR           1
#define DNS_HEADER_RCODE_SERV_FAIL          2
#define DNS_HEADER_RCODE_NX_DOMAIN          3
#define DNS_HEADER_RCODE_NOT_IMPL           4
#define DNS_HEADER_RCODE_REFUSED            5
#define DNS_HEADER_RCODE_YX_DOMAIN          6
#define DNS_HEADER_RCODE_YX_RR_SET          7
#define DNS_HEADER_RCODE_NX_RR_SET          8
#define DNS_HEADER_RCODE_NOT_AUTH           9
#define DNS_HEADER_RCODE_NOT_ZONE           10

#define DNS_HEADER_RR_TYPE_A                1
#define DNS_HEADER_RR_TYPE_NS               2
#define DNS_HEADER_RR_TYPE_MD               3
#define DNS_HEADER_RR_TYPE_MF               4
#define DNS_HEADER_RR_TYPE_CNAME            5
#define DNS_HEADER_RR_TYPE_SOA              6
#define DNS_HEADER_RR_TYPE_MB               7
#define DNS_HEADER_RR_TYPE_MG               8
#define DNS_HEADER_RR_TYPE_MR               9
#define DNS_HEADER_RR_TYPE_NULL             10
#define DNS_HEADER_RR_TYPE_WKS              11
#define DNS_HEADER_RR_TYPE_PTR              12
#define DNS_HEADER_RR_TYPE_HINFO            13
#define DNS_HEADER_RR_TYPE_MINFO            14
#define DNS_HEADER_RR_TYPE_MX               15
#define DNS_HEADER_RR_TYPE_TXT              16

#define DNS_HEADER_RR_CLASS_IN              1
#define DNS_HEADER_RR_CLASS_CS              2
#define DNS_HEADER_RR_CLASS_CH              3
#define DNS_HEADER_RR_CLASS_HS              4

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

/**
  *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  *  |                      ID                       |
  *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  *  |QR|   OpCode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
  *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  *  |                QDCOUNT/ZOCOUNT                |
  *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  *  |                ANCOUNT/PRCOUNT                |
  *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  *  |                NSCOUNT/UPCOUNT                |
  *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  *  |                    ARCOUNT                    |
  *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  */
struct _dns_header_t {
    header_t                        header;
    
    uint16_t                        id;             /**< Identifier */
    union {                         
        uint16_t                    raw;
        struct {
            uint16_t                rcode   : 4;    /**< Response Code (LSB) */
            uint16_t                cd      : 1;    /**< Checking Disabled */
            uint16_t                ad      : 1;    /**< Authentic Data */
            uint16_t                z       : 1;    /**< Reserved for future use */
            uint16_t                ra      : 1;    /**< Recursion Available */
            uint16_t                rd      : 1;    /**< Recursion Desired */
            uint16_t                tc      : 1;    /**< TrunCation */
            uint16_t                aa      : 1;    /**< Authoritative Answer */
            uint16_t                opcode  : 4;    /**< Operation Code */
            uint16_t                qr      : 1;    /**< Query / Response (MSB) */
        };
    } flags;
    uint16_t                        qd_count;       /**< Number of entries in the question section */
    uint16_t                        an_count;       /**< Number of resource records in the answer section */
    uint16_t                        ns_count;       /**< Number of name server resource records in the authority records section */
    uint16_t                        ar_count;       /**< Number of resource records in the additional records section */
};

/**
 *  Domain Name as a Series of Labels
 *
 *  <domain-name> is a domain name represented as a series of labels, and
 *  terminated by a label with zero length.  <character-string> is a single
 *  length octet followed by that number of characters.  <character-string>
 *  is treated as binary information, and can be up to 256 characters in
 *  length (including the length octet).
 *
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |         LEN           |                       |
 *  +--+--+--+--+--+--+--+--+                       |
 *  |                                               |
 *  /                     VALUE                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct _dns_label_t {
    dns_label_t                    *next;
    uint8_t                         len;
    uint8_t                        *value;
};

/**
 *  Question section format
 *
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                                               |
 *  /                     QNAME                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QTYPE                     |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QCLASS                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct _dns_query_t {
    dns_query_t                    *next;
    dns_label_t                    *qname;
    uint16_t                        qtype;
    uint16_t                        qclass;
};

/**
 *  Resource record format
 *
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                                               |
 *  /                                               /
 *  /                      NAME                     /
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                      TYPE                     |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     CLASS                     |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                      TTL                      |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                   RDLENGTH                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 *  /                     RDATA                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */

#define DNS_HEADER_RESOURCE_RECORD              \
    dns_resource_record_t          *next;       \
    dns_label_t                    *name;       \
    uint16_t                        type;       \
    uint16_t                        class;      \
    uint32_t                        ttl;        \
    uint16_t                        rdlength;

struct _dns_resource_record_t {
    DNS_HEADER_RESOURCE_RECORD
};

/**
 *  Start of Authority (SOA)
 *
 *  MNAME   The <domain-name> of the name server that was the
 *          original or primary source of data for this zone.
 *          
 *  RNAME   A <domain-name> which specifies the mailbox of the
 *          person responsible for this zone.
 *          
 *  SERIAL  The unsigned 32 bit version number of the original copy
 *          of the zone.  Zone transfers preserve this value.  This
 *          value wraps and should be compared using sequence space
 *          arithmetic.
 *          
 *  REFRESH A 32 bit time interval before the zone should be
 *          refreshed.
 *          
 *  RETRY   A 32 bit time interval that should elapse before a
 *          failed refresh should be retried.
 *          
 *  EXPIRE  A 32 bit time value that specifies the upper limit on
 *          the time interval that can elapse before the zone is no
 *          longer authoritative.
 *
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  /                     MNAME                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  /                     RNAME                     /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    SERIAL                     |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    REFRESH                    |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     RETRY                     |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    EXPIRE                     |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    MINIMUM                    |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct _dns_resource_record_soa_t {
    DNS_HEADER_RESOURCE_RECORD
    
};

/**
 *  Authoritative Name server
 *  A <domain-name> which specifies a host which should be
 *  authoritative for the specified class and domain.
 *
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  /                   NSDNAME                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct _dns_resource_record_ns_t {
    DNS_HEADER_RESOURCE_RECORD
};

struct _dns_resource_record_a_t {
    DNS_HEADER_RESOURCE_RECORD
};

/**
 *  Canonical Name
 *  A <domain-name> which specifies the canonical or primary
 *  name for the owner.  The owner name is an alias.
 *
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  /                     CNAME                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct _dns_resource_record_cname_t {
    DNS_HEADER_RESOURCE_RECORD
    char                           *cname;
};

/**
 *  Pointer
 *  A <domain-name> which points to some location in the
 *  domain name space.
 *
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  /                   PTRDNAME                    /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct _dns_resource_record_ptr_t {
    DNS_HEADER_RESOURCE_RECORD
    char                           *ptrdname;
};




dns_header_t   *dns_header_new      (void);
void            dns_header_free     (dns_header_t *dns_header);
packet_len_t    dns_header_encode   (dns_header_t *dns_header, raw_packet_t *raw_packet, packet_offset_t dns_offset);
dns_header_t   *dns_header_decode   (                          raw_packet_t *raw_packet, packet_offset_t dns_offset);

#endif

