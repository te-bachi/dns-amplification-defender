
#include "packet/raw_packet.h"
#include "log.h"

static bool raw_packet_setup(raw_packet_t *raw_packet);
static void raw_packet_destructor(void *ptr);

static class_info_t class_info = {
    .size        = sizeof(raw_packet_t),
    .destructor  = raw_packet_destructor
};

raw_packet_t *
raw_packet_new(void)
{
    raw_packet_t *raw_packet;
    
    raw_packet = object_new(&class_info);
    
    if (!raw_packet_setup(raw_packet)) {
        return NULL;
    }
    
    return raw_packet;
}

bool
raw_packet_init(raw_packet_t *raw_packet)
{
    object_init(raw_packet, &class_info);
    return raw_packet_setup(raw_packet);
}

static bool
raw_packet_setup(raw_packet_t *raw_packet)
{
    return true;
}

static void
raw_packet_destructor(void *ptr)
{
    //
}

/*
 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
 * sequential 16 bit words to it, and at the end, fold back all the
 * carry bits from the top 16 bits into the lower 16 bits.
 */
uint16_t
raw_packet_calc_checksum(uint16_t *buffer, uint16_t len)
{
    const uint16_t  words = len / 2;
    uint32_t        sum;
    uint16_t        i;
    
    sum = 0;
    for (i = 0; i < words; i++) {
        sum = sum + *(buffer + i);
    }
    
    /* add carry */
    sum = (sum >> 16) + sum;
    
    /* truncate to 16 bits */
    return ntohs(~sum);
}
