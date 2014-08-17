#ifndef __HEADER_STORAGE_H__
#define __HEADER_STORAGE_H__

#include "packet/packet.h"

typedef struct _header_storage_t header_storage_t;

/**
 * Every header has its own storage
 */
struct _header_storage_t {
    header_class_t     *klass;
    header_t           *assigned;
    uint32_t            assigned_size;
    header_t           *available;
    uint32_t            available_size;
    header_storage_t   *next;
};

header_t   *header_storage_assign(header_storage_t *storage);
void        header_storage_return(header_storage_t *storage, header_t *header);

#endif

