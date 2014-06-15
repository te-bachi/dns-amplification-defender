#include "packet/net_address.h"

const mac_address_t      MAC_ADDRESS_NULL       = { .addr   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
const mac_address_t      MAC_ADDRESS_BROADCAST  = { .addr   = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };
const ipv4_address_t     IPV4_ADDRESS_NULL      = { { .addr   = { 0, 0, 0, 0 } } };
const ipv6_address_t     IPV6_ADDRESS_NULL      = { { .addr32 = { 0, 0, 0, 0 } } };

