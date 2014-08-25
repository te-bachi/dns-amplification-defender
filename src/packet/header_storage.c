#include "packet/header_storage.h"
#include "log.h"

#include <inttypes.h>

static void header_storage_assign(header_storage_t *storage, header_storage_entry_t *entry, uint32_t size);

header_t *
header_storage_new(header_storage_t *storage)
{
    header_storage_entry_t *entry;
    header_t               *header;
    bool                    found  = false;
    uint32_t                size;
    uint32_t                idx;
    
    if (storage->head == NULL) {
        storage->head = storage->init;
        header_storage_assign(storage, storage->head, storage->head->allocator_size);
    }
    
    entry = storage->head;
    
    do {
        /* is there place left in the n-th entry? */
        if (entry->available_size > 0) {
            idx                                     = entry->available_idxs[entry->available_size - 1];     /**< roll up from behind */
            header                                  = (header_t *) (((uint8_t *) entry->allocator) + (idx * storage->klass->size));
            header->prev                            = NULL;
            header->next                            = NULL;
            
            LOG_PRINTLN(LOG_HEADER_STORAGE, LOG_DEBUG, ("found header storage entry = 0x%016" PRIxPTR ", header = 0x%016" PRIxPTR ", index = %" PRIu32, (unsigned long) entry, (unsigned long) header, idx));
            
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
                
                entry->next                         = malloc(sizeof(header_storage_entry_t));   /**< allocate a storage entry */
                entry->next->allocator              = malloc(size * storage->klass->size);      /**< allocate an array of headers */
                entry->next->allocator_size         = size;
                entry->next->available_idxs         = malloc(size * sizeof(uint32_t));          /**< allocate an array of indexes */
                entry->next->available_size         = size;
                entry->next->next                   = NULL;
                
                /* assign new entry */
                entry                               = entry->next;
                
                LOG_PRINTLN(LOG_HEADER_STORAGE, LOG_DEBUG, ("allocate header storage entry = 0x%016" PRIxPTR ", size = %" PRIu32, (unsigned long) entry, size));
                
                header_storage_assign(storage, entry, size);
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
    
    LOG_PRINTLN(LOG_HEADER_STORAGE, LOG_DEBUG, ("free header = 0x%016" PRIxPTR ", index = %" PRIu32 ", header storage entry = 0x%016" PRIxPTR ", available size = %" PRIu32, (unsigned long) header, header->idx, (unsigned long) entry, entry->available_size));
    
    entry->available_idxs[entry->available_size] = header->idx;
    entry->available_size++;
}

/**
 * set class, entry (way back to creator) and array index for every header
 */
static void
header_storage_assign(header_storage_t *storage, header_storage_entry_t *entry, uint32_t size)
{ 
    uint32_t                idx;
    header_t               *header;
    
    /* iterate over the array of headers (= entry->allocator) */
    for (idx = 0; idx < size; idx++) {
        
        /* like entry->allocator[idx], but the C language    |       first header       index   size of class
           doesn't know the size of an element             <--                                                 */
        header                          = (header_t *) (((uint8_t *) entry->allocator) + (idx * storage->klass->size));
        header->klass                   = storage->klass;
        header->entry                   = entry;
        header->idx                     = idx;
        entry->available_idxs[idx]      = idx;
        
        LOG_PRINTLN(LOG_HEADER_STORAGE, LOG_DEBUG, ("assign header = 0x%016" PRIxPTR ", index = %" PRIu32, (unsigned long) header, idx));
    }
}

