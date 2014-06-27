
#ifndef __BPF_H__
#define __BPF_H__

#include "packet/raw_packet.h"
#include <stdbool.h>

int  bpf_open(const char *iface, const unsigned int timeout, const unsigned int *buffer_len);
bool bpf_read(int bpf, raw_packet_t *raw_packet, const unsigned int buffer_len);

#endif
