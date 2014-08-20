#include "packet/header_storage.h"

header_t *
header_storage_new(header_storage_t *storage)
{
    header_storage_entry_t *entry;
    header_t               *header;
    bool                    found  = false;
    uint32_t                size;
    uint32_t                idx;
    uint32_t                available_idx;
    
    if (storage->head == NULL) {
        storage->init(storage);
    }
    
    entry = storage->head;
    
    do {
        /* is there place left in the n-th entry? */
        if (entry->available_size > 0) {
            available_idx                           = entry->available_idxs[entry->available_size - 1];     /**< roll up from behind */
            header                                  = &(entry->allocator[idx]);
            found                                   = true;
            entry->available_size--;
        /* no place left! */
        } else {
            /* another entry points to it? */
            if (entry->next != NULL) {
                /* look at the next entry in the list */
                entry                               = entry->next;
            } else {
                /* double the size */
                size                                = 2 * entry->allocator_size;
                
                /* allocate a new entry */
                entry->next                         = malloc(sizeof(header_storage_entry_t));
                entry->next->allocator              = malloc(size * storage->klass->size);
                entry->next->allocator_size         = size;
                entry->next->available_idxs         = malloc(size * sizeof(uint32_t));
                entry->next->available_size         = size;
                entry->next->next                   = NULL;
                
                /* assign new entry */
                entry                               = entry->next;
                
                /* set class, entry (way back to creator) and array index for every header */
                for (idx = 0; idx < size; idx++) {
                    entry->allocator[idx].entry     = entry;
                    entry->allocator[idx].idx       = idx;
                }
            }
        }
    } while (!found);
    
    return header;
}

void
header_storage_free(header_t *header)
{
    header_storage_entry_t *entry;
    
    entry = header->entry;
    entry->available_idxs[entry->available_size] = header->idx;
    entry->available_size++;
}
