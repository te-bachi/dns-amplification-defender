#ifndef __NET_ADDRESS_H__
#define __NET_ADDRESS_H__

#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

#define MAC_ADDRESS_LEN         6
#define MAC_ADDRESS_WW_LEN      2
#define IPV4_ADDRESS_LEN        4
#define IPV6_ADDRESS_LEN        16
#define IPV6_ADDRESS_HW_LEN     8
#define IPV6_ADDRESS_WW_LEN     4
#define IPV6_ADDRESS_DW_LEN     2

/* see ETH_FRAME_LEN in '/usr/include/linux/if_ether.h' */
#define ETH_MAX_FRAME_SIZE      4096                    /**< Max. bytes in frame without preamble, SFD but with FCS (=CRC) */

/** MAC address structure */
typedef struct _mac_address_t {
    uint8_t     addr[MAC_ADDRESS_LEN];                  /**< byte-wise 48-bit MAC address */
} mac_address_t;

/**
 * IPv4 address structure
 *  ______ ______ ______ ______
 * |      |      |      |      |
 * |  10  |  41  |   0  |   2  |
 * | 0x0a | 0x29 | 0x00 | 0x02 |
 * |______|______|______|______|
 *    [0]    [1]    [2]    [3]
 *
 *              [3] [2] [1] [0]
 *   addr32 = 0x 02  00  29  0a
 */
typedef struct _ipv4_address_t {
    union {
        uint8_t         addr[IPV4_ADDRESS_LEN];         /**< byte-wise 32-bit IPv4 address */
        uint32_t        addr32;                         /**< 32-bit (word) IPv4 address, caution with byte-order! */
    };
} ipv4_address_t;

/** IPv6 address structure */
typedef struct _ipv6_address_t {
    union {
        uint8_t         addr[IPV6_ADDRESS_LEN];         /**< byte-wise 128-bit IPv6 address */
        uint16_t        addr16[IPV6_ADDRESS_HW_LEN];    /**< 16-bit-wise (half-word) IPv6 address, caution with byte-order! */
        uint32_t        addr32[IPV6_ADDRESS_WW_LEN];    /**< 32-bit-wise (word) IPv6 address, caution with byte-order! */
        uint64_t        addr64[IPV6_ADDRESS_DW_LEN];    /**< 64-bit-wise (double-word) IPv6 address, caution with byte-order! */
    };
} ipv6_address_t;

extern const mac_address_t      MAC_ADDRESS_NULL;
extern const mac_address_t      MAC_ADDRESS_BROADCAST;
extern const ipv4_address_t     IPV4_ADDRESS_NULL;
extern const ipv6_address_t     IPV6_ADDRESS_NULL;

/**
 * Check equality of two MAC addresses
 *
 * @param   a               reference to a MAC address
 * @param   b               reference to a MAC address
 * @return                  true when MAC addresses match, false otherwise
 */
static inline bool
mac_address_equal(const mac_address_t *a, const mac_address_t *b)
{
    uint8_t idx;

    for (idx = 0; idx < MAC_ADDRESS_LEN; idx++) {
        if (a->addr[idx] != b->addr[idx]) {
            return false;
        }
    }

    return true;
}

/**
 * Check equality of two IPv4 addresses
 *
 * @param   a               reference to a IPv4 address
 * @param   b               reference to a IPv4 address
 * @return                  true when IPv4 addresses match, false otherwise
 */
static inline bool
ipv4_address_equal(const ipv4_address_t *a, const ipv4_address_t *b)
{
    return (a->addr32 == b->addr32) ? true : false;
}

/**
 * Compare two IPv4 addresses
 *
 * @param   a               reference to a IPv4 address
 * @param   b               reference to a IPv4 address
 * @return                  0 on equal, 1 when A is greater, -1 when B is greater
 */
static inline int8_t
ipv4_address_compare(const ipv4_address_t *a, const ipv4_address_t *b)
{
    for (uint32_t i = 0; i < IPV4_ADDRESS_LEN; i++) {
        if (a->addr[i] > b->addr[i]) return 1;
        if (a->addr[i] < b->addr[i]) return -1;
    }

    return 0;
}

/**
 * Check equality of two IPv6 addresses
 *
 * @param   a               reference to a IPv6 address
 * @param   b               reference to a IPv6 address
 * @return                  true when IPv6 addresses match, false otherwise
 */
static inline bool
ipv6_address_equal(const ipv6_address_t *a, const ipv6_address_t *b)
{
    uint8_t idx;

    for (idx = 0; idx < IPV6_ADDRESS_WW_LEN; idx++) {
        /* compare 32-bit numbers: when not-equal, a mismatch has been found => !success */
        if (a->addr32[idx] != b->addr32[idx]) {
            return false;
        }
    }

    return true;
}

/*****************************************************************************
 * INTEGER SPLIT/JOIN - splits or joins integers
 ****************************************************************************/

/* 16-bit */
static inline void
uint8_to_uint16(uint16_t *dest, const uint8_t src[2])
{
    *dest = ((((uint16_t) src[0]) <<  8) |
             (((uint16_t) src[1])));
}

static inline void
uint16_to_uint8(uint8_t dest[2], const uint16_t *src)
{
    dest[0] = ((*src) >> 8) & 0xff;
    dest[1] = ((*src) >> 0) & 0xff;
}

/* 32-bit */
static inline void
uint8_to_uint32(uint32_t *dest, const uint8_t src[4])
{
    *dest = ((((uint32_t) src[0]) << 24) |
             (((uint32_t) src[1]) << 16) |
             (((uint32_t) src[2]) <<  8) |
             (((uint32_t) src[3])));
}

static inline void
uint32_to_uint8(uint8_t dest[4], const uint32_t *src)
{
    dest[0] = ((*src) >> 24) & 0xff;
    dest[1] = ((*src) >> 16) & 0xff;
    dest[2] = ((*src) >>  8) & 0xff;
    dest[3] = ((*src) >>  0) & 0xff;
}

/* 48-bit (as 64-bit) */
static inline void
uint8_to_uint48(uint64_t *dest, const uint8_t src[6])
{
    *dest = ((((uint64_t) src[0]) << 40) |
             (((uint64_t) src[1]) << 32) |
             (((uint64_t) src[2]) << 24) |
             (((uint64_t) src[3]) << 16) |
             (((uint64_t) src[4]) <<  8) |
             (((uint64_t) src[5])));
}

static inline void
uint48_to_uint8(uint8_t dest[6], const uint64_t *src)
{
    dest[0] = ((*src) >> 40) & 0xff;
    dest[1] = ((*src) >> 32) & 0xff;
    dest[2] = ((*src) >> 24) & 0xff;
    dest[3] = ((*src) >> 16) & 0xff;
    dest[4] = ((*src) >>  8) & 0xff;
    dest[5] = ((*src) >>  0) & 0xff;
}

/* 64-bit (signed) */

/* Caution! Signed shift could be arithmetic- or logical-shift.
 * Cast to unsigned, then shift! */

static inline void
uint8_to_int64(int64_t *dest, const uint8_t src[7])
{
    *dest = (int64_t) ((((uint64_t) src[0]) << 56) |
                       (((uint64_t) src[1]) << 48) |
                       (((uint64_t) src[2]) << 40) |
                       (((uint64_t) src[3]) << 32) |
                       (((uint64_t) src[4]) << 24) |
                       (((uint64_t) src[5]) << 16) |
                       (((uint64_t) src[6]) <<  8) |
                       (((uint64_t) src[7])));
}

static inline void
int64_to_uint8(uint8_t dest[8], const int64_t *src)
{
    dest[0] = (((const uint64_t) (*src)) >> 56) & 0xff;
    dest[1] = (((const uint64_t) (*src)) >> 48) & 0xff;
    dest[2] = (((const uint64_t) (*src)) >> 40) & 0xff;
    dest[3] = (((const uint64_t) (*src)) >> 32) & 0xff;
    dest[4] = (((const uint64_t) (*src)) >> 24) & 0xff;
    dest[5] = (((const uint64_t) (*src)) >> 16) & 0xff;
    dest[6] = (((const uint64_t) (*src)) >>  8) & 0xff;
    dest[7] = (((const uint64_t) (*src)) >>  0) & 0xff;
}

/* 64-bit (unsigned) */

static inline void
uint8_to_uint64(uint64_t *dest, const uint8_t src[7])
{
    *dest = ((((uint64_t) src[0]) << 56) |
             (((uint64_t) src[1]) << 48) |
             (((uint64_t) src[2]) << 40) |
             (((uint64_t) src[3]) << 32) |
             (((uint64_t) src[4]) << 24) |
             (((uint64_t) src[5]) << 16) |
             (((uint64_t) src[6]) <<  8) |
             (((uint64_t) src[7])));
}

static inline void
uint64_to_uint8(uint8_t dest[8], const uint64_t *src)
{
    dest[0] = ((*src) >> 56) & 0xff;
    dest[1] = ((*src) >> 48) & 0xff;
    dest[2] = ((*src) >> 40) & 0xff;
    dest[3] = ((*src) >> 32) & 0xff;
    dest[4] = ((*src) >> 24) & 0xff;
    dest[5] = ((*src) >> 16) & 0xff;
    dest[6] = ((*src) >>  8) & 0xff;
    dest[7] = ((*src) >>  0) & 0xff;
}

#endif

