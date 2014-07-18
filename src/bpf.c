
#include "bpf.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <net/bpf.h>
#include <net/if.h>

#include <unistd.h>

#include "log.h"

#include "packet/packet.h"
#include "packet/port.h"

#define BPF_DEVICE_MAX      99

static struct bpf_insn bpf_filter[] = {
    
            /* Make sure this is an IP packet... */
/*  1 */    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),                         /**< Copy absolute (BPF_ABS) half-word (BPF_H) value 12 to accumulator: packet offset, 6 Dest. MAC + 6 Src. MAC = 12 */
/*  2 */    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IPV4, 0, 8),      /**< Jump to offset if accumulator equals (BPF_JEQ) to constant (BPF_K) ETHERTYPE_IP:
                                                                             *   pc = 2, if true: offset 0, otherwise: offset 8 (pc += (A == k) ? jt : jf) */
            /* Make sure it's a UDP packet... */
/*  3 */    BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),                         /**< Copy absolute byte (BPF_B) value 23 to accumulator: packet offset */
/*  4 */    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPV4_PROTOCOL_UDP, 0, 6),   /**< Jump to offset if accumulator equals (BPF_JEQ) to constant (BPF_K) IPV4_PROTOCOL_UDP:
                                                                              *   pc = 4, if true: 4 + 0 = 4, otherwise: 4 + 6 = 10 */

            /* Make sure this isn't a fragment... */
/*  5 */    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 20),                         /**< Copy absolute half-word value 20 to accumulator: packet offset */
/*  6 */    BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 4, 0),             /**< Jump to offset if accumulator bitwise AND (BPF_JSET) to constant (BPF_K) BPF_JSET: */

            /* Get the IP header length... */
/*  7 */    BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 14),

            /* Make sure it's to the right port... */
/*  8 */    BPF_STMT(BPF_LD + BPF_H + BPF_IND, 16),
/*  9 */    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, PORT_DNS, 0, 1),

            /* If we passed all the tests, ask for the whole packet. */
/* 10 */    BPF_STMT(BPF_RET+BPF_K, (u_int)-1),

            /* Otherwise, drop it. */
/* 11 */    BPF_STMT(BPF_RET+BPF_K, 0)

};

static struct bpf_program bpf_program = {
    sizeof(bpf_filter) / sizeof(struct bpf_insn),
    (struct bpf_insn *) &bpf_filter
};

int
bpf_open(const char *iface, const unsigned int timeout, const unsigned int *buffer_len)
{
    int             bpf;
    int             i;
    const char      prefix[] = "/dev/bpf";
    char            bpf_dev[sizeof(prefix) + 2 + 1];
    struct ifreq    iface_bind;
    u_int           enable = 1;
    struct timeval  tv_timeout;
    
    /* try to open a bpf device after another */
    for (i = 0; i < BPF_DEVICE_MAX; i++) {
        snprintf(bpf_dev, sizeof(bpf_dev), "%s%d", prefix, i);
        
        LOG_PRINTLN(LOG_SOCKET_BPF, LOG_VERBOSE, ("Trying BPF device %s", bpf_dev));
        
        bpf = open(bpf_dev, O_RDWR);
        if (bpf == -1) {
            LOG_ERRNO(LOG_SOCKET_BPF, LOG_ERROR, errno, ("Could not open BPF device %s", bpf_dev)); 
            continue;
        }
        
        if (bpf >= 0) {
            break;
        }
    }
    
    if (bpf == -1) {
        LOG_PRINTLN(LOG_SOCKET_BPF, LOG_ERROR, ("No device found. Abort!"));
        return -1;
    }
    
    /* bpf successfully opened */
    LOG_PRINTLN(LOG_SOCKET_BPF, LOG_DEBUG, ("BPF device %s successfully opened: bpf=%d", bpf_dev, bpf));
    
    /* bind to interface */
    strlcpy(iface_bind.ifr_name, iface, IFNAMSIZ);
    if (ioctl(bpf, BIOCSETIF, &iface_bind) == -1) {
        LOG_ERRNO(LOG_SOCKET_BPF, LOG_ERROR, errno, ("Could not bind interface %s to BPF device", iface));
        return -1;
    }
    LOG_PRINTLN(LOG_SOCKET_BPF, LOG_DEBUG, ("Bind BPF device to interface %s", iface));
    
    /* Enable immediate mode */
    if (ioctl(bpf, BIOCIMMEDIATE, &enable) == -1) {
        LOG_ERRNO(LOG_SOCKET_BPF, LOG_ERROR, errno, ("Could not enable immediate mode"));
        return -1;
    }
    LOG_PRINTLN(LOG_SOCKET_BPF, LOG_DEBUG, ("Enable immediate mode"));
    
    /* Enable write link level source address as provided*/
    if (ioctl(bpf, BIOCGHDRCMPLT, &enable) == -1) {
        LOG_ERRNO(LOG_SOCKET_BPF, LOG_ERROR, errno, ("Could not enable write link level source address as provided"));
        return -1;
    }
    LOG_PRINTLN(LOG_SOCKET_BPF, LOG_DEBUG, ("Enable write link level source address as provided"));
    
    /* Get buffer length */
    if (ioctl(bpf, BIOCGBLEN, buffer_len) == -1) {
        LOG_ERRNO(LOG_SOCKET_BPF, LOG_ERROR, errno, ("Could not get buffer length"));
        return -1;
    }
    LOG_PRINTLN(LOG_SOCKET_BPF, LOG_DEBUG, ("Get buffer length: len=%u", *buffer_len));
    
    /* Set timeout */
    tv_timeout.tv_sec   = timeout;
    tv_timeout.tv_usec  = 0;
    
    if (ioctl(bpf, BIOCSRTIMEOUT, &tv_timeout) == -1) {
        LOG_ERRNO(LOG_SOCKET_BPF, LOG_ERROR, errno, ("Could not set timeout"));
        return -1;
    }
    LOG_PRINTLN(LOG_SOCKET_BPF, LOG_DEBUG, ("Set timeout to %us", timeout));
    
    /* Set filter */
    if (ioctl(bpf, BIOCSETF, (struct bpf_program *) &bpf_program) == -1) {
        LOG_ERRNO(LOG_SOCKET_BPF, LOG_ERROR, errno, ("Could not set filter"));
        return -1;
    }
    LOG_PRINTLN(LOG_SOCKET_BPF, LOG_DEBUG, ("Set filter"));
    
    return bpf;
}

bool
bpf_read(int bpf, raw_packet_t *raw_packet, const unsigned int buffer_len)
{
    uint8_t         buffer[buffer_len];
    ssize_t         bytes_read;
    struct bpf_hdr *bpf_header;
    
    bytes_read = read(bpf, buffer, buffer_len);
    if (bytes_read == -1) {
        LOG_ERRNO(LOG_SOCKET_BPF, LOG_WARNING, errno, ("Could not read")); 
    } else if (bytes_read > 0) {
        bpf_header = (struct bpf_hdr *) buffer;
        
        raw_packet->len = bytes_read - bpf_header->bh_hdrlen;
        memcpy(raw_packet->data, &(buffer[bpf_header->bh_hdrlen]), raw_packet->len);
        
        LOG_PRINTLN(LOG_SOCKET_BPF, LOG_INFO, ("received a packet, len=%d", raw_packet->len));
        
        return true;
    }
    
    return false;
}
