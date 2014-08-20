#ifndef __HEADER_STORAGE_H__
#define __HEADER_STORAGE_H__

typedef struct _header_storage_t        header_storage_t;
typedef struct _header_storage_entry_t  header_storage_entry_t;

#include "packet/packet.h"

struct _header_storage_entry_t {
    header_t               *allocator;          /**< headers itself (address of allocated memory) */
    uint32_t                allocator_size;     /**< */
    uint32_t               *available_idxs;     /**< index array of available headers */
    uint32_t                available_size;
    header_storage_entry_t *next;
};

typedef void (*header_storage_init_fn)(header_storage_t *storage);


/**
 * Every header has its own storage
 * 
 * 
 */
struct _header_storage_t {
    header_class_t         *klass;
    header_storage_init_fn  init;
    
    /**
     * Storage can only be extended, not relocated, because headers could
     * be assigned and addresses are given out!
     */
    header_storage_entry_t *head;
};

header_t   *header_storage_new(header_storage_t *storage);
void        header_storage_free(header_t *header);

#endif

