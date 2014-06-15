
#include "bpf.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/ioctl.h>

#include <net/bpf.h>
#include <net/if.h>


#define BPF_DEVICE_MAX      99

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
        bpf = open(bpf_dev, O_RDWR);
        if (bpf == -1 && errno != EBUSY) {
            fprintf(stderr, "ERROR: Could not open BPF device: %s\n", strerror(errno)); 
            return -1;
        }
    }
    /* bpf successfully opened */
    
    /* bind to interface */
    strlcpy(iface_bind.ifr_name, iface, IFNAMSIZ);
    if (ioctl(bpf, BIOCSETIF, &iface_bind) == -1) {
        fprintf(stderr, "ERROR: Could not bind interface %s to BPF device: %s\n", iface, strerror(errno));
        return -1;
    }
    
    /* Enable immediate mode */
    if (ioctl(bpf, BIOCIMMEDIATE, &enable) == -1) {
        fprintf(stderr, "ERROR: Could not enable immediate mode: %s\n", strerror(errno));
        return -1;
    }
    
    /* Enable write link level source address as provided*/
    if (ioctl(bpf, BIOCGHDRCMPLT, &enable) == -1) {
        fprintf(stderr, "ERROR: Could not enable write link level source address as provided: %s\n", strerror(errno));
        return -1;
    }
    
    /* Get buffer length */
    if (ioctl(bpf, BIOCGBLEN, buffer_len) == -1) {
        fprintf(stderr, "ERROR: Could not get buffer length: %s\n", strerror(errno));
        return -1;
    }
    
    /* Set timeout */
    tv_timeout.tv_sec   = timeout;
    tv_timeout.tv_usec  = 0;
    
    if (ioctl(bpf, BIOCSRTIMEOUT, &tv_timeout) == -1) {
        fprintf(stderr, "ERROR: Could not set timeout: %s\n", strerror(errno));
        return -1;
    }
    
    return bpf;
}
