
#ifndef __OBJECT_H__
#define __OBJECT_H__

#ifdef __GNUC__

typedef struct class_info_t     class_info_t;
typedef struct object_t         object_t;

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define OBJECT(obj) ((object_t *) obj)

// destructor
typedef void (*destructor_fn)(void *ptr);
typedef void *(*mem_alloc_fn)(size_t size);
typedef void (*mem_free_fn)(void *ptr);

// class info
struct class_info_t {
    const char             *name;           // class name
    size_t                  size;           // size of object
    destructor_fn           destructor;     // destructor
    mem_alloc_fn            mem_alloc;      // memory allocation function
    mem_free_fn             mem_free;       // memory free function
};

// object
struct object_t {
    class_info_t           *class_info;     // class info of this object
    size_t                  ref_count;      // reference-counter, starting by 1
    bool                    is_on_heap;     // is this object on the heap (malloc)
};

// creating
void *object_new(class_info_t *class_info);
void object_init(void *ptr, class_info_t *class_info);
void object_clear(void *ptr);

// Retaining and releasing
void *object_retain(void *ptr);
void object_release(void *ptr);

#define membersizeof(type, member) sizeof(((type *)0)->member)

#define ASSERT_CONCAT_(a, b)    a##b
#define ASSERT_CONCAT(a, b)     ASSERT_CONCAT_(a, b)
#define ct_assert(e)            enum { ASSERT_CONCAT(assert_line_, __LINE__) = 1/(!!(e)) }

#else

#error Only use GCC

#endif

#endif

