#include "log_network.h"
#include "packet/port.h"

#include <inttypes.h>

static void num2hexstr(uint32_t num, uint8_t *chr, size_t len);

/*** PACKETS + HEADERS  ******************************************************/

void
log_raw_packet(const raw_packet_t *raw_packet)
{
    uint32_t i;
    uint32_t j;

    LOG_PRINTF(LOG_STREAM, "raw packet (size = %u)\n", raw_packet->len);

    // for every character in the data-array
    for (i = 0; i < raw_packet->len ; i++) {

        // if one line of hex printing is complete...
        if (i != 0 && i % 16 == 0) {
            LOG_PRINTF(LOG_STREAM, "         ");

            for (j = i - 16; j < i; j++) {

                // if its a number or alphabet
                if (raw_packet->data[j] >= 32 && raw_packet->data[j] <= 128) {
                    LOG_PRINTF(LOG_STREAM, "%c", (unsigned char) raw_packet->data[j]);

                // otherwise print a dot
                } else {
                    LOG_PRINTF(LOG_STREAM, ".");
                }
            }
            LOG_PRINTF(LOG_STREAM, "\n");
        }

        if (i % 8 == 0) {
            if (i % 16 == 0) {
                LOG_PRINTF(LOG_STREAM, "   ");
           } else {
               LOG_PRINTF(LOG_STREAM, " ");
           }
        }
        LOG_PRINTF(LOG_STREAM, " %02" PRIX8, raw_packet->data[i]);

        // print the last spaces
        if (i == raw_packet->len - 1) {

            // extra spaces
            for ( j = 0; j < 15 - i % 16; j++) {
                LOG_PRINTF(LOG_STREAM, "   ");
            }

            // add extra space between the two 8-byte blocks
            if (15 - i % 16 >= 8) {
                LOG_PRINTF(LOG_STREAM, " ");
            }

            LOG_PRINTF(LOG_STREAM, "         ");

            for ( j = i - i % 16; j <= i; j++) {
                if (raw_packet->data[j] >= 32 && raw_packet->data[j] <= 128) {
                    LOG_PRINTF(LOG_STREAM, "%c", (unsigned char) raw_packet->data[j]);
                } else {
                    LOG_PRINTF(LOG_STREAM, ".");
                }
            }
            LOG_PRINTF(LOG_STREAM, "\n");
        }
    }
}

void
log_ethernet_header(const ethernet_header_t *ether_header)
{
    LOG_PRINTF(LOG_STREAM, "Ethernet\n");
    
    LOG_MAC(&(ether_header->dest), dest_str);
    LOG_MAC(&(ether_header->src),  src_str);
    
    LOG_PRINTF(LOG_STREAM, "   |-Destination MAC                    %s\n",                                    dest_str);
    LOG_PRINTF(LOG_STREAM, "   |-Source MAC                         %s\n",                                    src_str);
    
    if (ether_header->type == ETHERTYPE_VLAN) {
        LOG_PRINTF(LOG_STREAM, "   |-Tag Protocol Identifier (TPID)     %-15s (0x%04" PRIx16 ")\n",           log_ether_type(ether_header->type), ether_header->type);
        LOG_PRINTF(LOG_STREAM, "   |-VLAN                               0x%04" PRIx16 "\n",                   ether_header->vlan.tci);
        LOG_PRINTF(LOG_STREAM, "     |-Priority       (PCP)             0x%02" PRIx8 "            (%u)\n",    ether_header->vlan.pcp, ether_header->vlan.pcp);
        LOG_PRINTF(LOG_STREAM, "     |-Drop Indicator (DEI)             %-15s (0x%02x)\n",                    ether_header->vlan.dei ? "set" : "no set", ether_header->vlan.dei);
        LOG_PRINTF(LOG_STREAM, "     |-Identifier     (VID)             0x%04" PRIx16 "          (%u)\n",     ether_header->vlan.vid, ether_header->vlan.vid);
        LOG_PRINTF(LOG_STREAM, "     |-Type                             %-15s (0x%04" PRIx16 ")\n",           log_ether_type(ether_header->vlan.type), ether_header->vlan.type);
    } else {
        LOG_PRINTF(LOG_STREAM, "   |-Type                               %-15s (0x%04" PRIx16 ")\n",           log_ether_type(ether_header->type), ether_header->type);
    }
}

void
log_ipv4_header(const ipv4_header_t *ipv4_header)
{
    LOG_PRINTF(LOG_STREAM, "IPv4 Header\n");
    
    LOG_IPV4(&(ipv4_header->src),  src_str);
    LOG_IPV4(&(ipv4_header->dest), dest_str);
    
    LOG_PRINTF(LOG_STREAM, "   |-IP Version                         %"     PRIu8 "\n",                            ipv4_header->version);
    LOG_PRINTF(LOG_STREAM, "   |-IP Header Length                   %"     PRIu8 " dwords or %" PRIu8 " bytes\n", ipv4_header->ihl, ipv4_header->ihl * 4);
    LOG_PRINTF(LOG_STREAM, "   |-Differentiated Service             0x%02" PRIx8 "\n",                            ipv4_header->dscp);
    LOG_PRINTF(LOG_STREAM, "   |-IP Total Length                    %"     PRIu16 " bytes\n",                     ipv4_header->len);
    LOG_PRINTF(LOG_STREAM, "   |-Identification                     0x%04" PRIx16 "          (%" PRIu16 ")\n",    ipv4_header->id, ipv4_header->id);
    LOG_PRINTF(LOG_STREAM, "   |-Dont Fragment Field                %-15s (0x%02" PRIx8 ")\n",                    ipv4_header->dont_fragment ? "set" : "no set", ipv4_header->dont_fragment);
    LOG_PRINTF(LOG_STREAM, "   |-More Fragment Field                %-15s (0x%02" PRIx8 ")\n",                    ipv4_header->more_fragments ? "set" : "no set", ipv4_header->more_fragments);
    LOG_PRINTF(LOG_STREAM, "   |-Fragment Offset                    0x%04" PRIx16 "          (%u)\n",             ipv4_header->fragment_offset, ipv4_header->fragment_offset);
    LOG_PRINTF(LOG_STREAM, "   |-TTL                                %"     PRIu8 "\n",                            ipv4_header->ttl);
    LOG_PRINTF(LOG_STREAM, "   |-Protocol                           %-15s (%"     PRIu8 ")\n",                    log_ipv4_protocol(ipv4_header->protocol), ipv4_header->protocol);
    LOG_PRINTF(LOG_STREAM, "   |-Checksum                           0x%04" PRIx16 "          (%" PRIu16 ")\n",    ipv4_header->checksum, ipv4_header->checksum);
    LOG_PRINTF(LOG_STREAM, "   |-Source IP                          %-15s (0x%08" PRIx32 ")\n",                   src_str, ipv4_header->src.addr32);
    LOG_PRINTF(LOG_STREAM, "   |-Destination IP                     %-15s (0x%08" PRIx32 ")\n",                   dest_str, ipv4_header->dest.addr32);
}

void
log_udpv4_header(const udpv4_header_t *udpv4_header)
{
    LOG_PRINTF(LOG_STREAM, "UDPv4 Header\n");
    
    LOG_PRINTF(LOG_STREAM, "   |-Source Port                        %-15s (%" PRIu16 ")\n",               log_ip_port(udpv4_header->src_port), udpv4_header->src_port);
    LOG_PRINTF(LOG_STREAM, "   |-Destination Port                   %-15s (%" PRIu16 ")\n",               log_ip_port(udpv4_header->dest_port), udpv4_header->dest_port);
    LOG_PRINTF(LOG_STREAM, "   |-UDP Length                         %"        PRIu16 " Bytes\n",          udpv4_header->len);
    LOG_PRINTF(LOG_STREAM, "   |-UDP Checksum                       0x%04"    PRIx16 "          (%u)\n",  udpv4_header->checksum, udpv4_header->checksum);
}

/*** TO STRING ***************************************************************/

void
log_mac(const mac_address_t *mac, uint8_t *str)
{
    snprintf((char *) str, LOG_MAC_LEN, "%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8,
                                             mac->addr[0], mac->addr[1], mac->addr[2],
                                             mac->addr[3], mac->addr[4], mac->addr[5]);
}

void
log_ipv4(const ipv4_address_t *ipv4, uint8_t *str)
{
    snprintf((char *) str, LOG_IPV4_LEN, "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "", ipv4->addr[0],
                                                             ipv4->addr[1],
                                                             ipv4->addr[2],
                                                             ipv4->addr[3]);
}

void
log_ipv6(const ipv6_address_t *ipv6, uint8_t *str)
{
    static const uint8_t    WIDTH = 4;      /* 16-bit, WIDTH=1: 4-bit */
    uint16_t                i;
    uint16_t                j;
    uint8_t                 chr[WIDTH];
    uint16_t                len = 0;
    bool                    padding;
    
    /* iterate over 8 blocks */
    for (i = 0; i < IPV6_ADDRESS_HW_LEN; i++) {
        /* IPv6 block is zero */
        if (ipv6->addr16[i] == 0) {
            str[len++] = '0';
            
        /* IPv6 block is _NOT_ zero */
        } else {
            num2hexstr(ntohs(ipv6->addr16[i]), chr, WIDTH);
            padding = true;
            for (j = 0; j < WIDTH; j++) {
                /* don't use leading zeros */ 
                if (padding) {
                    if (chr[j] != '0') {
                        padding = false;
                    } else {
                        continue;
                    }
                }
                str[len++] = chr[j];
            }
        }
        str[len++] = ':';
    }
    str[--len] = '\0';
}

/**
 * Converts a 32-bit number (unsigned integer) to an ASCII character-arry
 * WITHOUT the NUL terminator
 *
 * @param num           32-bit number to be converted
 * @param chr           an already allocated reference to a fixed length character-array
 * @param len           length of the character-array
 */
static void
num2hexstr(uint32_t num, uint8_t *chr, size_t len)
{
    const static uint8_t HEXADECIMAL_LOWER[] = "0123456789abcdef";
    
    uint8_t    *reverse = &(chr[len]);
    
    while (len) {
        *--reverse = HEXADECIMAL_LOWER[num & 0x0f];
        num >>= 4;
        len--;
    }
}

const char*
log_ether_type(const uint16_t ether_type)
{
    switch (ether_type) {
        case ETHERTYPE_IPV4:        return "IPv4";
        case ETHERTYPE_IPV6:        return "IPv6";
        case ETHERTYPE_ARP:         return "ARP";
        case ETHERTYPE_VLAN:        return "VLAN";
        default:                    return "unknow";
    }
}

const char *
log_ipv4_protocol(const uint8_t ipv4_protocol)
{
    switch (ipv4_protocol) {
        case IPV4_PROTOCOL_TCP:     return "TCP";
        case IPV4_PROTOCOL_UDP:     return "UDP";
        case IPV4_PROTOCOL_ICMP:    return "ICMP";
        default:                    return "unknow";
    }
}

const char*
log_ip_port(const uint16_t port)
{
    switch (port) {
        case PORT_DNS:              return "DNS";
        default:                    return "unknow";
    }
}
