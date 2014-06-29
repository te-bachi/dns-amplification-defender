
#include "packet/packet.h"
#include "log.h"

#include <string.h>

#define DNS_FAILURE_EXIT    dns_header_free(dns); \
                            return NULL

//static dns_domain_name_t *dns_domain_name_new(void);

static dns_header_t dns_header;

dns_header_t *
dns_header_new(void)
{
    LOG_PRINTLN(LOG_HEADER_DNS, LOG_DEBUG, ("DNS header new"));
    
    memset(&dns_header, 0, sizeof(dns_header_t));
    return &dns_header;
}

void
dns_header_free(dns_header_t *dns_header)
{
    LOG_PRINTLN(LOG_HEADER_DNS, LOG_DEBUG, ("DNS header free"));
    
}

packet_len_t
dns_header_encode(dns_header_t *dns_header, raw_packet_t *raw_packet, packet_offset_t dns_offset)
{
    packet_len_t    len;
    len = 0;
    
    return len;
}

dns_header_t *
dns_header_decode(raw_packet_t *raw_packet, packet_offset_t dns_offset)
{
    dns_header_t *dns = dns_header_new();
    
    if (raw_packet->len < (dns_offset + DNS_HEADER_LEN)) {
        LOG_PRINTLN(LOG_HEADER_DNS, LOG_ERROR, ("decode DNS header: size too small (present=%u, required=%u)", raw_packet->len - dns_offset, UDPV4_HEADER_LEN));
        DNS_FAILURE_EXIT;
    }
    
    /* fetch header */
    uint8_to_uint16(&(dns->id),         &(raw_packet->data[dns_offset + DNS_HEADER_OFFSET_ID]));
    uint8_to_uint16(&(dns->flags.raw),  &(raw_packet->data[dns_offset + DNS_HEADER_OFFSET_FLAGS]));
    uint8_to_uint16(&(dns->qd_count),   &(raw_packet->data[dns_offset + DNS_HEADER_OFFSET_QD_COUNT]));
    uint8_to_uint16(&(dns->an_count),   &(raw_packet->data[dns_offset + DNS_HEADER_OFFSET_AN_COUNT]));
    uint8_to_uint16(&(dns->ns_count),   &(raw_packet->data[dns_offset + DNS_HEADER_OFFSET_NS_COUNT]));
    uint8_to_uint16(&(dns->ar_count),   &(raw_packet->data[dns_offset + DNS_HEADER_OFFSET_AR_COUNT]));
    
    return dns;
}

