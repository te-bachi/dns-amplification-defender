#include "object.h"

#include <string.h>

/****************************************************************************
 * object_new
 *
 * @param ptr
 * @param class
 ***************************************************************************/
void *
object_new(class_info_t *class_info)
{
    if (!(class_info->mem_alloc)) {
        return NULL;
    }
    
    // allocate memory WITHOUT setting memory region to zero
    object_t *this = class_info->mem_alloc(class_info->size);
    
    // init instance and set memory region to zero
    object_init(this, class_info);
    
    this->is_on_heap = true;
    return this;
}

/****************************************************************************
 * object_init
 *
 * The parameter 'this' has type 'void *' to not get cast-warnings
 *
 * @param ptr
 * @param class
 ***************************************************************************/
void
object_init(void *ptr, class_info_t *class_info)
{
    object_t *this = ptr;
    
    // set memory region to zero
    memset(ptr, 0, class_info->size);
    
    // set class and reference count
    this->class_info = class_info;
    this->ref_count  = 1;
}


/****************************************************************************
 * object_clear
 *
 * @param ptr
 * @return 
 ***************************************************************************/
void
object_clear(void *ptr)
{
    object_t *this = ptr;
    
    // set memory region to zero only after object-declaration
    memset(ptr + sizeof(object_t), 0, this->class_info->size - sizeof(object_t));
}

/****************************************************************************
 * object_retain
 *
 * @param ptr
 * @return 
 ***************************************************************************/
void *
object_retain(void *ptr)
{
    object_t *this = ptr;
    if (!this) {
        return ptr;
    }
    
    this->ref_count++;
    
    return ptr;
}

/****************************************************************************
 * object_release
 *
 * @param ptr
 ***************************************************************************/
void
object_release(void *ptr)
{
    object_t *this = ptr;
    if (!this) {
        return;
    }
    
    this->ref_count--;
    if (this->ref_count == 0) {
        if (this->class_info->destructor) {
            this->class_info->destructor(ptr);
        }
        if (this->is_on_heap && this->class_info->mem_free) {
            this->class_info->mem_free(this);
        }
    }
}

