#include "packet/header_storage.h"

header_t *
header_storage_assign(header_storage_t *storage)
{
    header_t   *header = NULL;
    bool        found  = false;
    
    do {
        /* is there place left in the n-th storage? */
        if (storage->available_size > 0) {
           
        /* no place left! */
        } else {
            /* another storage points to it? */
            if (storage->next != NULL) {
                /* look at the next storage in the list */
                storage = storage->next;
            } else {
                /* allocate a new storage */
                storage->next                   = malloc(sizeof(header_storage_t));
                storage->next->klass            = storage->klass;
                storage->next->assigned         = NULL;
                storage->next->assigned_size    = 0;
                /* double the size */
                storage->next->available        = malloc(2 * storage->assigned_size * storage->klass->size);
                storage->next->available_size   = 2 * storage->assigned_size;
                storage->next->next             = NULL;
            }
        }
    } while (!found);
    
    memset(header, 0, storage->klass->size);
    header->klass = storage->klass;
    return header;
}

void
header_storage_return(header_storage_t *storage, header_t *header)
{
    
}
