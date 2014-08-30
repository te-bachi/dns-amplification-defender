#ifndef __DNS_HEADER_H__
#define __DNS_HEADER_H__

typedef struct _dns_header_t        dns_header_t;
typedef struct _dns_label_t         dns_label_t;
typedef struct _dns_query_t         dns_query_t;
typedef struct _dns_rr_t            dns_rr_t;
typedef struct _dns_rr_soa_t        dns_rr_soa_t;
typedef struct _dns_rr_ns_t         dns_rr_ns_t;
typedef struct _dns_rr_a_t          dns_rr_a_t;
typedef struct _dns_rr_cname_t      dns_rr_cname_t;
typedef struct _dns_rr_ptr_t        dns_rr_ptr_t;
typedef struct _dns_rr_opt_t        dns_rr_opt_t;

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

/* see RFC 6895 */
#define DNS_HEADER_RCODE_BAD_OPT_VERSION    16
#define DNS_HEADER_RCODE_BAD_SIG_FAILURE    16
#define DNS_HEADER_RCODE_BAD_KEY            17
#define DNS_HEADER_RCODE_BAD_TIME           18
#define DNS_HEADER_RCODE_BAD_MODE           19
#define DNS_HEADER_RCODE_BAD_NAME           20
#define DNS_HEADER_RCODE_BAD_ALGORITHM      21
#define DNS_HEADER_RCODE_BAD_TRUNCATION     22

#define DNS_DOMAIN_MAX_LEN                  253

#define DNS_LABEL_MAX_LEN                   63
#define DNS_LABEL_POINTER_MASK              0xc0

/* relative offsets */
#define DNS_LABEL_OFFSET_LEN                0
#define DNS_LABEL_OFFSET_VALUE              1

#define DNS_LABEL_SIZE_POINTER              2
#define DNS_LABEL_SIZE_LEN                  1

#define DNS_QUERY_MIN_LEN                   5

/* relative offsets */
#define DNS_QUERY_OFFSET_QTYPE              0
#define DNS_QUERY_OFFSET_QCLASS             2
#define DNS_QUERY_SIZE                      4

#define DNS_RR_MIN_LEN                      11
#define DNS_RR_OFFSET_TYPE                  0
#define DNS_RR_OFFSET_CLASS                 2
#define DNS_RR_OFFSET_TTL                   4
#define DNS_RR_OFFSET_RDLENGTH              8
#define DNS_RR_SIZE                         10

#define DNS_TYPE_A                          1
#define DNS_TYPE_NS                         2
#define DNS_TYPE_MD                         3
#define DNS_TYPE_MF                         4
#define DNS_TYPE_CNAME                      5
#define DNS_TYPE_SOA                        6
#define DNS_TYPE_MB                         7
#define DNS_TYPE_MG                         8
#define DNS_TYPE_MR                         9
#define DNS_TYPE_NULL                       10
#define DNS_TYPE_WKS                        11
#define DNS_TYPE_PTR                        12
#define DNS_TYPE_HINFO                      13
#define DNS_TYPE_MINFO                      14
#define DNS_TYPE_MX                         15
#define DNS_TYPE_TXT                        16
/* RFC 2535 */
#define DNS_TYPE_SIG                        24
#define DNS_TYPE_KEY                        25
#define DNS_TYPE_NXT                        30
/* RFC 6891 */
#define DNS_TYPE_OPT                        41
/* RFC 3755 */
#define DNS_TYPE_DS                         43
/* RFC 4034 */
#define DNS_TYPE_RRSIG                      46
#define DNS_TYPE_NSEC                       47
#define DNS_TYPE_DNSKEY                     48
/* RFC 5155 */
#define DNS_TYPE_NSEC3                      50
#define DNS_TYPE_ANY                        255

#define DNS_CLASS_IN                        1
#define DNS_CLASS_CS                        2
#define DNS_CLASS_CH                        3
#define DNS_CLASS_HS                        4
#define DNS_CLASS_ANY                       255


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
    dns_query_t                    *qd;
    uint16_t                        qd_count;       /**< Number of entries in the question section */

    dns_rr_t                       *an;
    uint16_t                        an_count;       /**< Number of resource records in the answer section */

    dns_rr_t                       *ns;
    uint16_t                        ns_count;       /**< Number of name server resource records in the authority records section */

    dns_rr_t                       *ar;
    uint16_t                        ar_count;       /**< Number of resource records in the additional records section */
};

/**
 *  Domain Name as a Series of Labels
 *
 *  <domain-name> is a domain name represented as a series of labels, and
 *  terminated by a label with zero length.  <character-string> is a single
 *  length octet followed by that number of characters.
 *
 *  Labels must be 63 characters or less.
 *
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |         LEN           |                       |
 *  +--+--+--+--+--+--+--+--+                       |
 *  |                                               |
 *  /                     VALUE                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 *  Message compression
 * 
 *  - a sequence of labels ending in a zero octet
 *  - a pointer
 *  - a sequence of labels ending with a pointer
 *
 *  The pointer takes the form of a two octet sequence:
 *
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  | 1  1|                OFFSET                   |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
struct _dns_label_t {
    uint8_t                         len;
    uint8_t                         value[DNS_LABEL_MAX_LEN];
    
    dns_label_t                    *next;
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
    dns_label_t                    *qname;
    uint16_t                        qtype;
    uint16_t                        qclass;
    
    dns_query_t                    *next;
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

#define DNS_RR                                  \
    dns_label_t                    *name;       \
    uint16_t                        type;       \
    uint16_t                        klass;      \
    uint32_t                        ttl;        \
    uint16_t                        rdlength;   \
                                                \
    dns_rr_t                       *next;

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
struct _dns_rr_soa_t {
    DNS_RR
    dns_label_t                    *mname;
    dns_label_t                    *rname;
    uint32_t                        serial;
    uint32_t                        refresh;
    uint32_t                        retry;
    uint32_t                        expire;
    uint32_t                        minimum;
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
struct _dns_rr_ns_t {
    DNS_RR
};

struct _dns_rr_a_t {
    DNS_RR
    ipv4_address_t                  ipv4_address;
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
struct _dns_rr_cname_t {
    DNS_RR
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
struct _dns_rr_ptr_t {
    DNS_RR
    char                           *ptrdname;
};

/**
 *      +------------+--------------+------------------------------+
 *      | Field Name | Field Type   | Description                  |
 *      +------------+--------------+------------------------------+
 *      | NAME       | domain name  | MUST be 0 (root domain)      |
 *      | TYPE       | u_int16_t    | OPT (41)                     |
 *      | CLASS      | u_int16_t    | requestor's UDP payload size |
 *      | TTL        | u_int32_t    | extended RCODE and flags     |
 *      | RDLEN      | u_int16_t    | length of all RDATA          |
 *      | RDATA      | octet stream | {attribute,value} pairs      |
 *      +------------+--------------+------------------------------+
 *                               OPT RR Format
 *
 *
 *                 +0 (MSB)                            +1 (LSB)
 *      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *   0: |         EXTENDED-RCODE        |            VERSION            |
 *      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *   2: | DO|                           Z                               |
 *      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *                            OPT Record TTL Field
 */
struct _dns_rr_opt_t {
    dns_label_t                    *name;
    uint16_t                        type;
    uint16_t                        udp_payload;
    uint8_t                         extended_rcode;
    uint8_t                         version;

    union {
        uint16_t                    raw;
        struct {
            uint16_t                z       : 15;   /**< Reserved */
            uint16_t                d0      : 1;    /**< DNSSEC OK */
        };
    } flags;
    uint16_t                        rdlength;

    dns_rr_t                       *next;
};

struct _dns_rr_t {
    union {
        struct {
            DNS_RR
        };
        dns_rr_soa_t   soa;
        dns_rr_ns_t    ns;
        dns_rr_a_t     a;
        dns_rr_cname_t cname;
        dns_rr_ptr_t   ptr;
        dns_rr_opt_t   opt;
    };
};

dns_header_t   *dns_header_new      (void);
void            dns_header_free     (header_t *header);

dns_label_t    *dns_label_new       (void);
void            dns_label_free      (dns_label_t *label);

dns_query_t    *dns_query_new       (void);
void            dns_query_free      (dns_query_t *query);

dns_rr_t       *dns_rr_new          (void);
void            dns_rr_free         (dns_rr_t *resource_record);

void            dns_convert_to_domain(char *domain, const dns_label_t *label);
void            dns_convert_to_label_list(dns_label_t **label, const char *domain);

packet_len_t    dns_header_encode   (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);
header_t       *dns_header_decode   (netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset);

#endif

