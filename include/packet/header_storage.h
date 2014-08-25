#ifndef __HEADER_STORAGE_H__
#define __HEADER_STORAGE_H__

typedef struct _header_storage_t        header_storage_t;
typedef struct _header_storage_entry_t  header_storage_entry_t;

#include "packet/packet.h"

struct _header_storage_entry_t {
    header_t               *allocator;          /**< headers itself (address of allocated memory) */
    uint32_t                allocator_size;     /**< how many headers have been allocated (static number) */
    uint32_t               *available_idxs;     /**< index array of available headers */
    uint32_t                available_size;     /**< how many headers are available (dynamic number) */
    header_storage_entry_t *next;
};

/**
 * Every header has its own storage
 * 
 * 
 */
struct _header_storage_t {
    header_class_t         *klass;
    
    /**
     * Storage can only be extended, not relocated, because headers could
     * be assigned and addresses are given out!
     */
    header_storage_entry_t *head;
    header_storage_entry_t *init;
};

header_t   *header_storage_new(header_storage_t *storage);
void        header_storage_free(header_t *header);

#endif

