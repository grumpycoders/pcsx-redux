/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

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

#include <stddef.h>
#include <stdint.h>

#include "psyqo/alloc.h"

extern uintptr_t __heap_start;
extern uintptr_t __stack_start;

static void *heap_end = NULL;

static void *sbrk(ptrdiff_t incr) {
    void *prev_heap_end, *next_heap_end, *ret;
    void *stack_min = (void *)&__stack_start;

    prev_heap_end = heap_end ? heap_end : (void *)&__heap_start;

    /* Align to always be on 8-byte boundaries */
    next_heap_end = (void *)((((uintptr_t)prev_heap_end + incr) + 7) & ~7);

    /* Check if this allocation would exceed the end of the ram - would probably get into the stack first however */
    if (next_heap_end > stack_min) {
        ret = NULL;
    } else {
        heap_end = next_heap_end;
        ret = (void *)prev_heap_end;
    }

    return ret;
}

typedef struct _heap_t {
    void *ptr;
    size_t size;
    struct _heap_t *prev, *next;
} heap_t;

static void *heap_base = NULL;
static heap_t *head = NULL, *tail = NULL;

static heap_t *find_fit(heap_t *head, size_t size) {
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

void *psyqo_malloc(size_t size) {
    void *ptr = NULL, *heap_ptr;
    heap_t *new, *prev;

    size = (size + sizeof(heap_t) + 7) & ~7;

    // Nothing's initialized yet ? Let's just initialize the bottom of our heap,
    // flag it as allocated.
    if (!head) {
        if (!heap_base) heap_base = sbrk(0);
        heap_ptr = sbrk(size);

        if (!heap_ptr) return NULL;

        ptr = (void *)((uintptr_t)heap_ptr + sizeof(heap_t));
        head = (heap_t *)heap_ptr;
        head->ptr = ptr;
        head->size = size - sizeof(heap_t);
        head->prev = NULL;
        head->next = NULL;
        tail = head;
        return ptr;
    }

    // We *may* have the bottom of our heap that has shifted, because of a free.
    // So let's check first if we have free space there, because I'm nervous
    // about having an incomplete data structure.
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
    heap_ptr = sbrk(size);
    if (!heap_ptr) return NULL;

    ptr = (void *)((uintptr_t)heap_ptr + sizeof(heap_t));
    new = (heap_t *)heap_ptr;
    new->ptr = ptr;
    new->size = size - sizeof(heap_t);
    new->prev = tail;
    new->next = NULL;
    tail->next = new;
    tail = new;
    return ptr;
}

void *psyqo_realloc(void *ptr, size_t size) {
    heap_t *prev;
    void *new = NULL;

    if (!size && ptr) {
        psyqo_free(ptr);
        return NULL;
    }

    if (!ptr) return psyqo_malloc(size);

    size = (size + sizeof(heap_t) + 7) & ~7;

    prev = (heap_t *)((uintptr_t)ptr - sizeof(heap_t));

    // New memory block shorter ?
    if (prev->size >= size) {
        prev->size = size;
        if (!prev->next) sbrk(ptr + size - sbrk(0));

        return ptr;
    }

    // New memory block larger
    // Is it the last one ?
    if (!prev->next) {
        new = sbrk(size - prev->size);
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
    new = psyqo_malloc(size);
    if (!new) return NULL;

    __builtin_memcpy(new, ptr, prev->size);
    psyqo_free(ptr);
    return new;
}

void psyqo_free(void *ptr) {
    heap_t *cur;
    void *top;
    size_t size;

    if (!ptr || !head) return;

    // First block; bumping head ahead.
    if (ptr == head->ptr) {
        size = head->size + (size_t)(head->ptr - (void *)head);
        head = head->next;

        if (head) {
            head->prev = NULL;
        } else {
            tail = NULL;
            sbrk(-size);
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
        tail = cur->prev;
        top = sbrk(0);
        size = (top - cur->prev->ptr) - cur->prev->size;
        sbrk(-size);
    }

    cur->prev->next = cur->next;
}

void *__builtin_new(size_t size) { return psyqo_malloc(size); }
void __builtin_delete(void *ptr) { psyqo_free(ptr); }
// void * operator new(unsigned int);
void *_Znwj(unsigned int size) { return psyqo_malloc(size); }
// void * operator new[](unsigned int);
void *_Znaj(unsigned int size) { return psyqo_malloc(size); }
// void operator delete(void*);
void _ZdlPv(void *ptr) { psyqo_free(ptr); }
// void operator delete[](void*);
void _ZdaPv(void *ptr) { psyqo_free(ptr); }
// void operator delete(void*, unsigned int);
void _ZdlPvj(void *ptr, unsigned int size) { psyqo_free(ptr); }
// void operator delete[](void*, unsigned int);
void _ZdaPvj(void *ptr, unsigned int size) { psyqo_free(ptr); }

void *psyqo_heap_start() { return heap_base; }
void *psyqo_heap_end() { return heap_end; }
