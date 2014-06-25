
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
    return dns_header_new();
}

