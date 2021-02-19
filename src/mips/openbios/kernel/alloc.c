/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#include "openbios/kernel/alloc.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*

The retail BIOS allocation code is confusing, and I've spotted a few bugs
while trying to reverse it. I'm going to reuse a memory allocator of my
own for the time being, and if it causes troubles, we'll see about
redoing it in a way that's closer to the retail code.

The retail code is duplicated to distinguish between user and kernel heaps.
The only difference are the few globals being used. The user versions are
located in the ROM, while the kernel versions are located in RAM.

Our version here will be completely located in RAM, and has a single
implementation, with a parameter to switch between kernel and user heaps.

 */

static void *user_heap_start = NULL;
static void *user_heap_end = NULL;
static void *kern_heap_start = NULL;
static void *kern_heap_end = NULL;

static void *user_heap_base = NULL;
static void *user_heap_bottom = NULL;
static void *kern_heap_base = NULL;
static void *kern_heap_bottom = NULL;

typedef struct _heap_t {
    void *ptr;
    size_t size;
    struct _heap_t *prev, *next;
} heap_t;

static heap_t *user_head = NULL, *user_tail = NULL;
static heap_t *kern_head = NULL, *kern_tail = NULL;

enum heap { HEAP_USER, HEAP_KERNEL };

static __attribute__((section(".ramtext"))) void *sbrk(ptrdiff_t incr, enum heap heap) {
    void *prev_heap_end, *next_heap_end, *ret;

    if (heap == HEAP_USER) {
        prev_heap_end = user_heap_bottom ? user_heap_bottom : user_heap_start;
    } else {
        prev_heap_end = kern_heap_bottom ? kern_heap_bottom : kern_heap_start;
    }

    /* Align to always be on 8-byte boundaries */
    next_heap_end = (void *)((((uintptr_t)prev_heap_end + incr) + 7) & ~7);

    /* Check if this allocation would exceed the end of the ram */
    if (next_heap_end > (heap == HEAP_USER ? user_heap_end : kern_heap_end)) {
        ret = NULL;
    } else {
        if (heap == HEAP_USER) {
            user_heap_bottom = next_heap_end;
        } else {
            kern_heap_bottom = next_heap_end;
        }
        ret = (void *)prev_heap_end;
    }

    return ret;
}

static __attribute__((section(".ramtext"))) heap_t *find_fit(heap_t *head, size_t size) {
    heap_t *prev = head;
    uintptr_t prev_top, next_bot;

    while (prev) {
        if (prev->next) {
            prev_top = (uintptr_t)prev->ptr + prev->size;
            next_bot = (uintptr_t)prev->next - prev_top;
            if (next_bot >= size) return prev;
        }
        prev = prev->next;
    }

    return prev;
}

static __attribute__((section(".ramtext"))) void *multi_malloc(size_t size, enum heap heap) {
    void *ptr = NULL, *heap_ptr;
    heap_t *new, *prev;

    size = (size + sizeof(heap_t) + 7) & ~7;

    // Nothing's initialized yet ? Let's just initialize the bottom of our heap,
    // flag it as allocated.
    if (heap == HEAP_USER ? !user_head : !kern_head) {
        if (heap == HEAP_USER ? !user_heap_base : !kern_heap_base) {
            void *heap_base = sbrk(0, heap);
            if (heap == HEAP_USER) {
                user_heap_base = heap_base;
            } else {
                kern_heap_base = heap_base;
            }
        }
        heap_ptr = sbrk(size, heap);

        if (!heap_ptr) return NULL;

        ptr = (void *)((uintptr_t)heap_ptr + sizeof(heap_t));
        heap_t *head;
        if (heap == HEAP_USER) {
            head = user_head = (heap_t *)heap_ptr;
        } else {
            head = kern_head = (heap_t *)heap_ptr;
        }
        head->ptr = ptr;
        head->size = size - sizeof(heap_t);
        head->prev = NULL;
        head->next = NULL;
        if (heap == HEAP_USER) {
            user_tail = head;
        } else {
            kern_tail = head;
        }
        return ptr;
    }

    // We *may* have the bottom of our heap that has shifted, because of a free.
    // So let's check first if we have free space there, because I'm nervous
    // about having an incomplete data structure.
    void *heap_base = heap ? user_heap_base : kern_heap_base;
    heap_t *head = heap ? user_head : kern_head;
    if (((uintptr_t)heap_base + size) < (uintptr_t)head) {
        new = (heap_t *)heap_base;
        ptr = (void *)((uintptr_t) new + sizeof(heap_t));

        new->ptr = ptr;
        new->size = size - sizeof(heap_t);
        new->prev = NULL;
        new->next = head;
        head->prev = new;
        head = new;
        return ptr;
    }

    // No luck at the beginning of the heap, let's walk the heap to find a fit.
    prev = find_fit(head, size);
    if (prev) {
        new = (heap_t *)((uintptr_t)prev->ptr + prev->size);
        ptr = (void *)((uintptr_t) new + sizeof(heap_t));

        new->ptr = ptr;
        new->size = size - sizeof(heap_t);
        new->prev = prev;
        new->next = prev->next;
        new->next->prev = new;
        prev->next = new;
        return ptr;
    }

    // Time to extend the size of the heap.
    heap_ptr = sbrk(size, heap);
    if (!heap_ptr) return NULL;

    ptr = (void *)((uintptr_t)heap_ptr + sizeof(heap_t));
    new = (heap_t *)heap_ptr;
    new->ptr = ptr;
    new->size = size - sizeof(heap_t);
    new->prev = heap == HEAP_USER ? user_tail : kern_tail;
    new->next = NULL;
    if (heap == HEAP_USER) {
        user_tail->next = new;
        user_tail = new;
    } else {
        kern_tail->next = new;
        kern_tail = new;
    }
    return ptr;
}

static __attribute__((section(".ramtext"))) void multi_free(void *ptr, enum heap heap) {
    heap_t *cur;
    void *top;
    size_t size;

    heap_t *head = heap == HEAP_USER ? user_head : kern_head;

    if (!ptr || !head) return;

    // First block; bumping head ahead.
    if (ptr == head->ptr) {
        size = head->size + (size_t)(head->ptr - (void *)head);
        head = head->next;

        if (head) {
            head->prev = NULL;
        } else {
            if (heap == HEAP_USER) {
                user_tail = NULL;
            } else {
                kern_tail = NULL;
            }
            sbrk(-size, heap);
        }

        return;
    }

    // Finding the proper block
    cur = head;
    for (cur = head; ptr != cur->ptr; cur = cur->next)
        if (!cur->next) return;

    if (cur->next) {
        // In the middle, just unlink it
        cur->next->prev = cur->prev;
    } else {
        // At the end, shrink heap
        if (heap == HEAP_USER) {
            user_tail = cur->prev;
        } else {
            kern_tail = cur->prev;
        }
        top = sbrk(0, heap);
        size = (top - cur->prev->ptr) - cur->prev->size;
        sbrk(-size, heap);
    }

    cur->prev->next = cur->next;
}

static __attribute__((section(".ramtext"))) void *multi_realloc(void *ptr, size_t size, enum heap heap) {
    heap_t *prev;
    void *new = NULL;

    if (!size && ptr) {
        multi_free(ptr, heap);
        return NULL;
    }

    if (!ptr) return multi_malloc(size, heap);

    size = (size + sizeof(heap_t) + 7) & ~7;

    prev = (heap_t *)((uintptr_t)ptr - sizeof(heap_t));

    // New memory block shorter ?
    if (prev->size >= size) {
        prev->size = size;
        if (!prev->next) sbrk(ptr + size - sbrk(0, heap), heap);

        return ptr;
    }

    // New memory block larger
    // Is it the last one ?
    if (!prev->next) {
        new = sbrk(size - prev->size, heap);
        if (!new) return NULL;

        prev->size = size;
        return ptr;
    }

    // Do we have free memory after it ?
    if ((prev->next->ptr - ptr) > size) {
        prev->size = size;
        return ptr;
    }

    // No luck.
    new = multi_malloc(size, heap);
    if (!new) return NULL;

    uint32_t *src = (uint32_t *)ptr;
    uint32_t *dst = (uint32_t *)new;
    size = prev->size / 4;
    for (size_t i = 0; i < size; i++) *dst++ = *src++;
    multi_free(ptr, heap);
    return new;
}

__attribute__((section(".ramtext"))) void *user_malloc(size_t size) { return multi_malloc(size, HEAP_USER); }
__attribute__((section(".ramtext"))) void user_free(void *ptr) { multi_free(ptr, HEAP_USER); }
__attribute__((section(".ramtext"))) void *user_realloc(void *ptr, size_t size) {
    return multi_realloc(ptr, size, HEAP_USER);
}
__attribute__((section(".ramtext"))) void user_initheap(void *base, size_t size) {
    user_heap_start = base;
    user_heap_end = ((char *)base) + size;

    user_heap_base = NULL;
    user_heap_bottom = NULL;
    user_head = NULL;
    user_tail = NULL;
}

__attribute__((section(".ramtext"))) void *kern_malloc(size_t size) { return multi_malloc(size, HEAP_KERNEL); }
__attribute__((section(".ramtext"))) void kern_free(void *ptr) { multi_free(ptr, HEAP_KERNEL); }
__attribute__((section(".ramtext"))) void *kern_realloc(void *ptr, size_t size) {
    return multi_realloc(ptr, size, HEAP_KERNEL);
}
__attribute__((section(".ramtext"))) void kern_initheap(void *base, size_t size) {
    kern_heap_start = base;
    kern_heap_end = ((char *)base) + size;

    kern_heap_base = NULL;
    kern_heap_bottom = NULL;
    kern_head = NULL;
    kern_tail = NULL;
}
