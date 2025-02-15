/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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

// See alloc.c in the psyqo project for more details on this allocator.

#define ALIGN_MASK ((2 * sizeof(void *)) - 1)
#define ALIGN_TO(x) (((uintptr_t)(x) + ALIGN_MASK) & ~ALIGN_MASK)

typedef struct empty_block_ {
    struct empty_block_ *next;
    size_t size;
} empty_block;

typedef struct allocated_block_ {
    uintptr_t dummy;
    size_t size;
} allocated_block;

_Static_assert(sizeof(empty_block) == (2 * sizeof(void *)), "empty_block is of the wrong size");
_Static_assert(sizeof(allocated_block) == (2 * sizeof(void *)), "allocated_block is of the wrong size");

static empty_block *user_heap_head = NULL;
static empty_block *kern_heap_head = NULL;

static empty_block marker = { .next = NULL, .size = 0 };

enum heap { HEAP_USER, HEAP_KERNEL };

static __attribute__((section(".ramtext"))) void *multi_malloc(size_t size_, const enum heap heap) {
    empty_block *curr = heap == HEAP_USER ? user_heap_head : kern_heap_head;
    empty_block *prev = NULL;
    empty_block *best_fit = NULL;
    empty_block *best_fit_prev = NULL;

    size_t size = ALIGN_TO(size_ + sizeof(allocated_block));

    size_t curr_size = 0;
    while ((curr_size != size) && (curr != &marker)) {
        curr_size = curr->size;
        if (curr_size >= size) {
            if ((best_fit == NULL) || (curr_size < best_fit->size)) {
                best_fit = curr;
                best_fit_prev = prev;
            }
        }
        prev = curr;
        curr = curr->next;
    }

    if (best_fit == NULL) {
        return NULL;
    }

    size_t best_fit_size = best_fit->size;
    allocated_block *ptr = (allocated_block *)best_fit;

    if (best_fit_size == size) {
        if (best_fit_prev == NULL) {
            if (heap == HEAP_USER) {
                user_heap_head = best_fit->next;
            } else {
                kern_heap_head = best_fit->next;
            }
        } else {
            best_fit_prev->next = best_fit->next;
        }
    } else {
        empty_block *new_block = (empty_block *)((char *)best_fit + size);
        new_block->next = best_fit->next;
        new_block->size = best_fit_size - size;
        if (best_fit_prev == NULL) {
            if (heap == HEAP_USER) {
                user_heap_head = new_block;
            } else {
                kern_heap_head = new_block;
            }
        } else {
            best_fit_prev->next = new_block;
        }
    }

    ptr->size = size;
    ptr++;
    return ptr;
}

static __attribute__((section(".ramtext"))) void multi_free(void *ptr_, const enum heap heap) {
    if (ptr_ == NULL) {
        return;
    }

    empty_block *block = (empty_block *)ptr_;
    block--;
    size_t size = block->size;
    empty_block * const head = heap == HEAP_USER ? user_heap_head : kern_heap_head;

    if (head == &marker) {
        if (heap == HEAP_USER) {
            user_heap_head = block;
        } else {
            kern_heap_head = block;
        }
        block->next = &marker;
        return;
    }

    if (head == NULL) {
        return;
    }

    if (head > block) {
        if (((char *)block + size) == (char *)head) {
            block->size = head->size + size;
            block->next = head->next;
        } else {
            block->next = head;
        }
        if (heap == HEAP_USER) {
            user_heap_head = block;
        } else {
            kern_heap_head = block;
        }
        return;
    }

    empty_block *curr = head;
    empty_block *next = NULL;
    while ((next = curr->next) != &marker) {
        if (next <= block) {
            curr = next;
            continue;
        }
        if (((char *)curr + curr->size) == (char *)block) {
            curr->size += size;
            if (((char *)curr + curr->size) == (char *)next) {
                curr->size += next->size;
                curr->next = next->next;
            }
        } else if (((char *)block + size) == (char *)next) {
            block->next = next->next;
            block->size = size + next->size;
            curr->next = block;
        } else {
            block->next = next;
            curr->next = block;
        }
        return;
    }

    if (((char *)curr + curr->size) == (char *)block) {
        curr->size += size;
    } else {
        block->next = &marker;
        curr->next = block;
    }
}

static __attribute__((section(".ramtext"))) void *multi_realloc(void *ptr_, size_t size_, const enum heap heap) {
    if (ptr_ == NULL) {
        return multi_malloc(size_, heap);
    }

    if (size_ == 0) {
        multi_free(ptr_, heap);
        return NULL;
    }

    size_t size = ALIGN_TO(size_ + sizeof(empty_block));
    empty_block *block = (empty_block *)ptr_;
    size_t old_size = (--block)->size;

    if (size == old_size) {
        return ptr_;
    }

    empty_block * const head = heap == HEAP_USER ? user_heap_head : kern_heap_head;
    if (head == &marker) {
        if (size < old_size) {
            empty_block *new_block = (empty_block *)((char *)block + size);
            new_block->next = &marker;
            new_block->size = old_size - size;
            if (heap == HEAP_USER) {
                user_heap_head = new_block;
            } else {
                kern_heap_head = new_block;
            }
            block->size = size;
            return ptr_;
        }
        return NULL;
    }

    if (block < head) {
        if (size < old_size) {
            empty_block *new_block = (empty_block *)((char *)block + size);
            if (head == (empty_block *)((char *)block + size)) {
                new_block->next = head->next;
                new_block->size = head->size + (old_size - size);
            } else {
                new_block->next = head;
                new_block->size = old_size - size;
            }
            if (heap == HEAP_USER) {
                user_heap_head = new_block;
            } else {
                kern_heap_head = new_block;
            }
            block->size = size;
            return ptr_;
        }
        if (((char *)block + old_size) == (char *)head) {
            size_t delta = size - old_size;
            if (head->size >= delta) {
                // If it has exactly the right amount of space, we can just remove
                // the first block from the list.
                if (head->size == delta) {
                    if (heap == HEAP_USER) {
                        user_heap_head = head->next;
                    } else {
                        kern_heap_head = head->next;
                    }
                } else {
                    // Otherwise, we need to create a new empty block after what we are re-allocating.
                    empty_block *new_block = (empty_block *)((char *)block + size);
                    new_block->next = head;
                    new_block->size = delta;
                    if (heap == HEAP_USER) {
                        user_heap_head = new_block;
                    } else {
                        kern_heap_head = new_block;
                    }
                }
                block->size = size;
                return ptr_;
            }
        }
    } else {
        empty_block *curr = head;
        empty_block *next = NULL;
        while ((next = curr->next) != NULL) {
            if ((next <= block) && (next != &marker)) {
                curr = next;
            } else {
                break;
            }
        }

        if (size < old_size) {
            empty_block *new_block = (empty_block *)((char *)block + size);
            if ((next != &marker) && (((char *)block + size) == (char *)next)) {
                new_block->next = next->next;
                new_block->size = old_size - size + next->size;
            } else {
                new_block->next = next;
                new_block->size = old_size - size;
            }
            curr->next = new_block;
            block->size = size;
            return ptr_;
        }

        size_t delta = size - old_size;
        if ((next != &marker) && (((char *)block + old_size) == (char *)next) && (next->size >= delta)) {
            if (next->size == delta) {
                curr->next = next->next;
            } else {
                empty_block *new_block = (empty_block *)((char *)block + size);
                new_block->next = next->next;
                new_block->size = next->size - delta;
                curr->next = new_block;
            }
            block->size = size;
            return ptr_;
        }
    }

    void *new_ptr = multi_malloc(size_, heap);
    if (new_ptr == NULL) {
        return NULL;
    }
    uint32_t * src = (uint32_t *)ptr_;
    uint32_t * dst = (uint32_t *)new_ptr;
    uint32_t size_to_copy = old_size - sizeof(empty_block);
    while (size_to_copy > 0) {
        *dst++ = *src++;
        size_to_copy -= sizeof(uint32_t);
    }
    multi_free(ptr_, heap);
    return new_ptr;
}

__attribute__((section(".ramtext"))) void *user_malloc(size_t size) { return multi_malloc(size, HEAP_USER); }
__attribute__((section(".ramtext"))) void user_free(void *ptr) { multi_free(ptr, HEAP_USER); }
__attribute__((section(".ramtext"))) void *user_realloc(void *ptr, size_t size) {
    return multi_realloc(ptr, size, HEAP_USER);
}
__attribute__((section(".ramtext"))) void user_initheap(void *base, size_t size) {
    user_heap_head = (empty_block*)ALIGN_TO(base);
    user_heap_head->next = &marker;
    user_heap_head->size = ALIGN_TO(size - sizeof(empty_block));
}

__attribute__((section(".ramtext"))) void *kern_malloc(size_t size) { return multi_malloc(size, HEAP_KERNEL); }
__attribute__((section(".ramtext"))) void kern_free(void *ptr) { multi_free(ptr, HEAP_KERNEL); }
__attribute__((section(".ramtext"))) void *kern_realloc(void *ptr, size_t size) {
    return multi_realloc(ptr, size, HEAP_KERNEL);
}
__attribute__((section(".ramtext"))) void kern_initheap(void *base, size_t size) {
    kern_heap_head = (empty_block*)ALIGN_TO(base);
    kern_heap_head->next = &marker;
    kern_heap_head->size = ALIGN_TO(size - sizeof(empty_block));
}
