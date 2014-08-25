
#include "packet/packet.h"
#include "log.h"

#include <string.h>
#include <inttypes.h>

#define DNS_STORAGE_INIT_SIZE           8
#define DNS_FAILURE_EXIT                dns_header_free((header_t *) dns); \
                                        return NULL

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
    dns_header_t *dns = dns_header_new();
    
    if (raw_packet->len < (offset + DNS_HEADER_LEN)) {
        LOG_PRINTLN(LOG_HEADER_DNS, LOG_ERROR, ("decode DNS header: size too small (present=%u, required=%u)", raw_packet->len - offset, UDPV4_HEADER_LEN));
        DNS_FAILURE_EXIT;
    }
    
    /* fetch header */
    uint8_to_uint16(&(dns->id),         &(raw_packet->data[offset + DNS_HEADER_OFFSET_ID]));
    uint8_to_uint16(&(dns->flags.raw),  &(raw_packet->data[offset + DNS_HEADER_OFFSET_FLAGS]));
    uint8_to_uint16(&(dns->qd_count),   &(raw_packet->data[offset + DNS_HEADER_OFFSET_QD_COUNT]));
    uint8_to_uint16(&(dns->an_count),   &(raw_packet->data[offset + DNS_HEADER_OFFSET_AN_COUNT]));
    uint8_to_uint16(&(dns->ns_count),   &(raw_packet->data[offset + DNS_HEADER_OFFSET_NS_COUNT]));
    uint8_to_uint16(&(dns->ar_count),   &(raw_packet->data[offset + DNS_HEADER_OFFSET_AR_COUNT]));
    
    return (header_t *) dns;
}

