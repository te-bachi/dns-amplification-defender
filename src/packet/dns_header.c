
#include "packet/packet.h"
#include "log.h"

#include <string.h>

//static dns_domain_name_t *dns_domain_name_new(void);

static dns_header_t dns_header;

dns_header_t *
dns_header_new(void)
{
    memset(&dns_header, 0, sizeof(dns_header_t));
    return &dns_header;
}

void
dns_header_free(dns_header_t *dns_header)
{
    
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
    return NULL;
}

