
#include "packet/packet.h"
#include "log.h"

#include <string.h>
#include <inttypes.h>

#define DNS_STORAGE_INIT_SIZE           8
#define DNS_QUERY_FAILURE_EXIT
#define DNS_FAILURE_EXIT                dns_header_free((header_t *) dns); \
                                        return NULL
#define DNS_LABEL_NEW                   label = dns_label_new(); \
                                        if (!dns_header_decode_label(raw_packet, header_offset, field_offset, label)) { \
                                            dns_label_free(label); \
                                            return false; \
                                        }

static bool dns_header_decode_label (raw_packet_t *raw_packet, packet_offset_t header_offset, packet_offset_t *field_offset, dns_label_t *label);
static bool dns_header_decode_query (raw_packet_t *raw_packet, packet_offset_t header_offset, packet_offset_t *field_offset, uint16_t count, dns_query_t *query);
static bool dns_header_decode_rr    (raw_packet_t *raw_packet, packet_offset_t header_offset, packet_offset_t *field_offset, uint16_t count, dns_rr_t *rr);
//static dns_domain_name_t *dns_domain_name_new(void);

static dns_header_t             dns[DNS_STORAGE_INIT_SIZE];
static uint32_t                 idx[DNS_STORAGE_INIT_SIZE];

static header_class_t           klass = {
    .type               = PACKET_TYPE_DNS,
    .size               = sizeof(dns_header_t),
    .free               = dns_header_free
};

static header_storage_entry_t   entry = {
    .allocator          = (header_t *) dns,
    .allocator_size     = DNS_STORAGE_INIT_SIZE,
    .available_idxs     = idx,
    .available_size     = DNS_STORAGE_INIT_SIZE,
    .next               = NULL
};

static header_storage_t         storage = {
    .klass              = &klass,
    .head               = NULL,
    .init               = &entry
};

static dns_label_t              label[64];
static uint16_t                 label_idx = 0;

static dns_query_t              query[32];
static uint16_t                 query_idx = 0;

static dns_rr_t                 rr[32];
static uint16_t                 rr_idx = 0;

// static dns_resource_record_a_t      a[8];
// static uint16_t                     a_idx;
// static dns_resource_record_ns_t     ns[8];
// static uint16_t                     ns_idx;
// static dns_resource_record_cname_t  cname[8];
// static uint16_t                     cname_idx;
// static dns_resource_record_soa_t    soa[8];
// static uint16_t                     soa_idx;
// static dns_resource_record_ptr_t    ptr[8];
// static uint16_t                     ptr_idx;

/*****************************************************************************
 * Header
 */
dns_header_t *
dns_header_new(void)
{
    dns_header_t *header = (dns_header_t *) header_storage_new(&storage);
    
    LOG_PRINTLN(LOG_HEADER_DNS, LOG_DEBUG, ("DNS header new 0x%016" PRIxPTR, (unsigned long) header));
    
    return header;
}

void
dns_header_free(header_t *header)
{
    LOG_PRINTLN(LOG_HEADER_DNS, LOG_DEBUG, ("DNS header free 0x%016" PRIxPTR, (unsigned long) header));
    
    header_storage_free(header);
}

/*****************************************************************************
 * Label
 */
dns_label_t *
dns_label_new(void)
{
    return &label[label_idx++];
}

void
dns_label_free(dns_label_t *label)
{
    if (label->next != NULL) dns_label_free(label->next);
    
    /* TODO: free current label */
}

/**
 *
 * @param   field_offset        offset of the start of the label (len or pointer)
 *
 * TODO: check offset range and return false if out-of-range!
 */
static bool
dns_header_decode_label(raw_packet_t *raw_packet, packet_offset_t header_offset, packet_offset_t *field_offset, dns_label_t *label)
{
    bool            valid;
    uint8_t         len;
    uint16_t        pointer;
    
    valid           = true;

    do {

        /* len */
        len = raw_packet->data[*field_offset + DNS_LABEL_OFFSET_LEN];

        /* it's a pointer? */
        if ((len & DNS_LABEL_POINTER_MASK) == DNS_LABEL_POINTER_MASK) {

            /* fetch the whole pointer (16-bit) */
            uint8_to_uint16(&pointer,  &(raw_packet->data[*field_offset + DNS_QUERY_OFFSET_QTYPE]));

            /* mask pointer flag => only pointer value left */
            pointer &= ~(DNS_LABEL_POINTER_MASK << 8);

            /* add header offset */
            pointer += header_offset;

            /* decode label with dummy field offset */
            dns_header_decode_label(raw_packet, header_offset, &pointer, label);

            *field_offset  += DNS_LABEL_SIZE_POINTER;
            valid           = false;

        /* it's a length */
        } else if (len != 0) {

            label->len = len;

            memcpy(label->value,  &(raw_packet->data[*field_offset + DNS_LABEL_OFFSET_VALUE]), label->len);

            *field_offset  += DNS_LABEL_SIZE_LEN + label->len;
            label->next     = dns_label_new();
            label           = label->next;

        /* it's a zero */
        } else {
            *field_offset  += DNS_LABEL_SIZE_LEN;
            label->len      = 0;
            label->value[0] = 0;
            valid           = false;
        }
    } while (valid);

    return true;
}

/*****************************************************************************
 * Query
 */
dns_query_t *
dns_query_new(void)
{
    return &query[query_idx++];
}

void 
dns_query_free(dns_query_t *query)
{
    
}

static bool
dns_header_decode_query(raw_packet_t *raw_packet, packet_offset_t header_offset, packet_offset_t *field_offset, uint16_t count, dns_query_t *query)
{
    dns_label_t    *label;

    for (; count > 0; count--) {

        if (raw_packet->len < (*field_offset + DNS_QUERY_MIN_LEN)) {
            LOG_PRINTLN(LOG_HEADER_DNS, LOG_ERROR, ("decode DNS query: size too small (present=%" PRIoffset ", required=%" PRIoffset ", offset=%" PRIoffset "/%x)", raw_packet->len - *field_offset, DNS_QUERY_MIN_LEN, *field_offset, *field_offset));
            return false;
        }

        /* qname */
        label = dns_label_new();

        if (!dns_header_decode_label(raw_packet, header_offset, field_offset, label)) {
            dns_label_free(label);
            return false;
        }
        query->qname = label;

        /* qtype + qclass */
        uint8_to_uint16(&(query->qtype),  &(raw_packet->data[*field_offset + DNS_QUERY_OFFSET_QTYPE]));
        uint8_to_uint16(&(query->qclass), &(raw_packet->data[*field_offset + DNS_QUERY_OFFSET_QCLASS]));

        *field_offset += DNS_QUERY_SIZE;

        /* not the last query */
        if (count > 1) {
            query->next = dns_query_new();
            query       = query->next;
        }
    }

    return true;
}

/*****************************************************************************
 * Resource Record
 */
dns_rr_t *
dns_rr_new()
{
    /*
    switch (type) {
        case DNS_RR_TYPE_A:     return (dns_resource_record_t *) &a[a_idx++];
        case DNS_RR_TYPE_NS:    return (dns_resource_record_t *) &ns[ns_idx++];
        case DNS_RR_TYPE_CNAME: return (dns_resource_record_t *) &cname[cname_idx++];
        case DNS_RR_TYPE_SOA:   return (dns_resource_record_t *) &soa[soa_idx++];
        case DNS_RR_TYPE_PTR:   return (dns_resource_record_t *) &ptr[ptr_idx++];
        default:                return NULL;
    }
    */
    
    return &rr[rr_idx++];
}

void
dns_rr_free(dns_rr_t *rr)
{
    
}

static bool
dns_header_decode_rr(raw_packet_t *raw_packet, packet_offset_t header_offset, packet_offset_t *field_offset, uint16_t count, dns_rr_t *rr)
{
    dns_label_t    *label;

    for (; count > 0; count--) {

        if (raw_packet->len < (*field_offset + DNS_RR_MIN_LEN)) {
            LOG_PRINTLN(LOG_HEADER_DNS, LOG_ERROR, ("decode DNS resource record: size too small (present=%" PRIoffset ", required=%" PRIoffset ", offset=%" PRIoffset "/%x)", raw_packet->len, *field_offset + DNS_RR_MIN_LEN, *field_offset, *field_offset));
            return false;
        }

        /* name */
        DNS_LABEL_NEW
        rr->name = label;

        uint8_to_uint16(&(rr->type),     &(raw_packet->data[*field_offset + DNS_RR_OFFSET_TYPE]));        /**< Type */
        uint8_to_uint16(&(rr->klass),    &(raw_packet->data[*field_offset + DNS_RR_OFFSET_CLASS]));       /**< Class */
        uint8_to_uint32(&(rr->ttl),      &(raw_packet->data[*field_offset + DNS_RR_OFFSET_TTL]));         /**< TTL */
        uint8_to_uint16(&(rr->rdlength), &(raw_packet->data[*field_offset + DNS_RR_OFFSET_RDLENGTH]));    /**< RD Length */

        *field_offset += DNS_RR_SIZE;

        /* decode type */
        /* TODO: check offset range and return false if out-of-range! */
        switch (rr->type) {
            case DNS_TYPE_A:            memcpy(&(rr->a.ipv4_address), &(raw_packet->data[*field_offset]),  rr->rdlength);
                                        *field_offset += rr->rdlength;
                                        break;

            case DNS_TYPE_NS:           DNS_LABEL_NEW
                                        rr->ns.nsdname = label;
                                        break;

            case DNS_TYPE_CNAME:        DNS_LABEL_NEW
                                        rr->cname.cname = label;
                                        break;

            case DNS_TYPE_SOA:          DNS_LABEL_NEW
                                        rr->soa.mname = label;
                                        DNS_LABEL_NEW
                                        rr->soa.rname = label;

                                        uint8_to_uint32(&(rr->soa.serial),  &(raw_packet->data[*field_offset + DNS_RR_SOA_OFFSET_SERIAL]));
                                        uint8_to_uint32(&(rr->soa.refresh), &(raw_packet->data[*field_offset + DNS_RR_SOA_OFFSET_REFRESH]));
                                        uint8_to_uint32(&(rr->soa.retry),   &(raw_packet->data[*field_offset + DNS_RR_SOA_OFFSET_RETRY]));
                                        uint8_to_uint32(&(rr->soa.expire),  &(raw_packet->data[*field_offset + DNS_RR_SOA_OFFSET_EXPIRE]));
                                        uint8_to_uint32(&(rr->soa.minimum), &(raw_packet->data[*field_offset + DNS_RR_SOA_OFFSET_MINIMUM]));

                                        *field_offset += DNS_RR_SOA_SIZE;
                                        break;

            case DNS_TYPE_PTR:          DNS_LABEL_NEW
                                        rr->ptr.ptrdname = label;
                                        break;

            case DNS_TYPE_MX:           uint8_to_uint16(&(rr->mx.preference),  &(raw_packet->data[*field_offset + DNS_RR_MX_OFFSET_PREFERENCE]));
                                        *field_offset += DNS_RR_MX_SIZE;

                                        DNS_LABEL_NEW
                                        rr->mx.exchange = label;
                                        break;

            case DNS_TYPE_OPT:
            default:                    *field_offset += rr->rdlength;
                                        break;
        }

        /* not the last resource record */
        if (count > 1) {
            rr->next    = dns_rr_new();
            rr          = rr->next;
        }
    }

    return true;
}

/*****************************************************************************
 * Convert
 */

/**
 * Converts a list of labels into a domain string.
 * Both arguments have to be re-allocated.
 *
 * @param   domain          returns an already allocated character string
 * @param   label           converts a list of labels into a domain
 * @return                  
 */
void
dns_convert_to_domain(char *domain, const dns_label_t *label)
{
    uint32_t idx = 0;
    static const char root[] = "<Root>";
    
    if (label->value[0] != 0) {
        while (label->value[0] != 0) {
            strncpy(&(domain[idx]), (const char *) label->value, label->len);
            idx += label->len;

            if (label->next->value[0] != 0) {
                domain[idx] = '.';
                idx         += 1;
            }

            label = label->next;
        }
    } else {
        strncpy(&(domain[idx]), root, sizeof(root));
        idx += sizeof(root);
    }
    domain[idx] = '\0';
}


/**
 * Converts a domain string into a list of labels.
 * The domain string is re-allocated. The list of labels will be allocated
 * in the function itself.
 *
 * @param   label           returns a newly allocated label
 * @param   domain          converts a domain into a list of labels
 * @return                  
 */
void
dns_convert_to_label_list(dns_label_t **label, const char *domain)
{
    
}

/*****************************************************************************
 * Encode / Decode
 */
packet_len_t
dns_header_encode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    packet_len_t    len;
    len = 0;
    
    return len;
}

header_t *
dns_header_decode(netif_t *netif, packet_t *packet, raw_packet_t *raw_packet, packet_offset_t offset)
{
    dns_header_t       *dns = dns_header_new();
    packet_offset_t     field_offset;

    if (raw_packet->len < (offset + DNS_HEADER_LEN)) {
        LOG_PRINTLN(LOG_HEADER_DNS, LOG_ERROR, ("decode DNS header: size too small (present=%u, required=%u)", raw_packet->len - offset, DNS_HEADER_LEN));
        DNS_FAILURE_EXIT;
    }
    
    /* fetch header */
    uint8_to_uint16(&(dns->id),         &(raw_packet->data[offset + DNS_HEADER_OFFSET_ID]));
    uint8_to_uint16(&(dns->flags.raw),  &(raw_packet->data[offset + DNS_HEADER_OFFSET_FLAGS]));
    uint8_to_uint16(&(dns->qd_count),   &(raw_packet->data[offset + DNS_HEADER_OFFSET_QD_COUNT]));
    uint8_to_uint16(&(dns->an_count),   &(raw_packet->data[offset + DNS_HEADER_OFFSET_AN_COUNT]));
    uint8_to_uint16(&(dns->ns_count),   &(raw_packet->data[offset + DNS_HEADER_OFFSET_NS_COUNT]));
    uint8_to_uint16(&(dns->ar_count),   &(raw_packet->data[offset + DNS_HEADER_OFFSET_AR_COUNT]));
    
    field_offset = offset + DNS_HEADER_LEN;
    
    /* question section */
    if (dns->qd_count > 0) {
        dns->qd = dns_query_new();
        if (!dns_header_decode_query(raw_packet, offset, &field_offset, dns->qd_count, dns->qd)) {
            dns_query_free(dns->qd);
            DNS_FAILURE_EXIT;
        }
    }
    
    /* answer records section */
    if (dns->an_count > 0) {
        dns->an = dns_rr_new();
        if (!dns_header_decode_rr(raw_packet, offset, &field_offset, dns->an_count, dns->an)) {
            dns_rr_free(dns->an);
            DNS_FAILURE_EXIT;
        }
    }
    
    /* authority records section */
    if (dns->ns_count > 0) {
        dns->ns = dns_rr_new();
        if (!dns_header_decode_rr(raw_packet, offset, &field_offset, dns->ns_count, dns->ns)) {
            dns_rr_free(dns->ns);
            DNS_FAILURE_EXIT;
        }
    }
    
    /* additional records section */
    if (dns->ar_count > 0) {
        dns->ar = dns_rr_new();
        if (!dns_header_decode_rr(raw_packet, offset, &field_offset, dns->ar_count, dns->ar)) {
            dns_rr_free(dns->ar);
            DNS_FAILURE_EXIT;
        }
    }
    
    return (header_t *) dns;
}

