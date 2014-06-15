
#ifndef __BPF_H__
#define __BPF_H__

int bpf_open(const char *iface, const unsigned int timeout, const unsigned int *buffer_len);

#endif
