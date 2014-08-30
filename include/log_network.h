
#ifndef __LOG_NETWORK_H__
#define __LOG_NETWORK_H__

#include <stdint.h>
#include <stdarg.h>

#include "log.h"
#include "packet/packet.h"

/*** DEFINES ****************************************************************/

#define LOG_MAC_LEN                     17 + 1    /* MAC-address  string length, with NUL-character */
#define LOG_IPV4_LEN                    15 + 1    /* IPv4-address string length, with NUL-character */
#define LOG_IPV6_LEN                    41 + 1    /* IPv6-address string length, with NUL-character */

/*** MACROS *****************************************************************/

/* net address */
#define LOG_MAC(var, var_str)                          uint8_t var_str[LOG_MAC_LEN];              log_mac(var, var_str)
#define LOG_IPV4(var, var_str)                         uint8_t var_str[LOG_IPV4_LEN];             log_ipv4(var, var_str)
#define LOG_IPV6(var, var_str)                         uint8_t var_str[LOG_IPV6_LEN];             log_ipv6(var, var_str)

#define LOG_NETWORK_FUNCTION(function, category, level, packet, msg) \
    do { \
        if (log_enabled && level <= LOG_CATEGORY_LEVEL[category]) { \
            log_print_header(category, level); \
            log_println msg; \
            function(packet); \
        } \
    } while(0)

#define LOG_RAW_PACKET(category, level, packet, msg)        LOG_NETWORK_FUNCTION(log_raw_packet,         category, level, packet, msg)
#define LOG_PACKET(category, level, packet, msg)            LOG_NETWORK_FUNCTION(log_packet,             category, level, packet, msg)
#define LOG_ETHERNET_HEADER(category, level, packet, msg)   LOG_NETWORK_FUNCTION(log_ethernet_packet,    category, level, packet, msg)
#define LOG_IPV4_HEADER(category, level, packet, msg)       LOG_NETWORK_FUNCTION(log_ipv4_header,        category, level, packet, msg)
#define LOG_UDPV4_HEADER(category, level, packet, msg)      LOG_NETWORK_FUNCTION(log_udpv4_header,       category, level, packet, msg)
#define LOG_DNS_HEADER(category, level, packet, msg)        LOG_NETWORK_FUNCTION(log_dns_header,         category, level, packet, msg)

/*** DECLARATION ************************************************************/

/* packets + headers */
void        log_raw_packet          (const raw_packet_t             *raw_packet);
void        log_packet              (const packet_t                 *packet);
void        log_ethernet_header     (const ethernet_header_t        *ether_header);
void        log_ipv4_header         (const ipv4_header_t            *ipv4_header);
void        log_udpv4_header        (const udpv4_header_t           *udpv4_header);
void        log_dns_header          (const dns_header_t             *dns_header);

/* to string */
void        log_mac                 (const mac_address_t            *mac,   uint8_t *str);
void        log_ipv4                (const ipv4_address_t           *ipv4,  uint8_t *str);
void        log_ipv6                (const ipv6_address_t           *ipv6,  uint8_t *str);

const char *log_ether_type          (const uint16_t ether_type);
const char *log_ipv4_protocol       (const uint8_t ipv4_protocol);
const char *log_ipv6_protocol       (const uint8_t ipv6_protocol);
const char *log_ip_port             (const uint16_t port);
const char *log_dns_opcode          (const uint16_t opcode);
const char *log_dns_rcode           (const uint16_t rcode);
const char *log_dns_type            (const uint16_t type);
#endif

