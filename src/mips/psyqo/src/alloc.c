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

#include "psyqo/alloc.h"

#include <stddef.h>
#include <stdint.h>

#include "common/hardware/pcsxhw.h"
#include "psyqo/xprintf.h"

// TL;DR: this is a simple memory allocator that uses a linked list of
// empty blocks to keep track of the free memory. Allocated blocks
// are not tracked, but have a header that contains the size of the block.
// Memory is always aligned to 8 bytes on 32-bit platforms, and 16 bytes on
// 64-bit platforms. The allocator is not thread-safe, and is not
// re-entrant. It is not designed to be used in a multi-threaded environment.
// The allocator is designed to be used in a way where memory fragmentation
// is minimal, and where the heap is not resized. The more memory is
// fragmented, the slower the allocator will be. Last but not least, the
// memory allocator respects the posix malloc/free/realloc interface, in
// particular:
// 1. Allocating 0 bytes will return a valid pointer, which can be freed.
// 2. Re-allocating a pointer to a smaller size is always guaranteed to
//    succeed and to return the same pointer.
// 3. Re-allocating a pointer to 0 bytes will behave as if free was called.
// 4. Re-allocating a NULL pointer will behave like a call to malloc.

// Align to 8 bytes on 32-bit platforms,
// and 16 bytes on 64-bit platforms.
#define ALIGN_MASK ((2 * sizeof(void *)) - 1)
#define ALIGN_TO(x) (((uintptr_t)(x) + ALIGN_MASK) & ~ALIGN_MASK)

extern char __heap_start;
extern char __stack_start;

// We keep track of the empty spaces in the heap, because
// it is fungible. Allocated blocks aren't tracked, and
// they are made so:
// 1. Their sizes is always stored before the allocated block.
// 2. They are always big enough to hold one of these empty blocks.

// Note that all of the memory is aligned to one of these blocks.
// Which means that there's always enough space for one of these
// blocks between two allocated blocks, if they are not adjacent.
typedef struct empty_block_ {
    struct empty_block_ *next;
    // The size of the block, in bytes, including this header,
    // meaning any empty_block should always have a size of
    // at least 2 * sizeof(void *), except for the end-of-list
    // marker, which is 0.
    size_t size;
} empty_block;

// This is the header of an allocated block. It ought to be
// mapped to the empty_block header exactly. We keep it
// as a separate type to make sure we don't accidentally
// mix them up, and for readability.
typedef struct allocated_block_ {
    uintptr_t dummy;
    // The size of the block, in bytes, including this header.
    size_t size;
} allocated_block;

// In theory, empty_block should be at exactly as big as
// alignment requirement. Let's assert that.
_Static_assert(sizeof(empty_block) == (2 * sizeof(void *)), "empty_block is of the wrong size");
// The same goes with allocated_block.
_Static_assert(sizeof(allocated_block) == (2 * sizeof(void *)), "allocated_block is of the wrong size");

// We keep track of the head of the list of empty blocks here.
// It is initialized to NULL at compile-time, and will be initialized
// when the first allocation is made.
static empty_block *head = NULL;
static allocated_block *bottom = NULL;
static allocated_block *top = NULL;
// The marker is here to make sure that the list is always terminated,
// so when we completely fill the heap, we don't end up with a NULL pointer
// back to the head. It will never fit any allocation, and will always
// be the last block in the list.
static empty_block marker;

// Enable this to debug the allocator very thoroughly. May be used to
// detect memory corruption, and other issues.
#ifdef ALLOC_DEBUG
#define dprintf printf
static void print_block(const empty_block *block) {
    if (block == NULL) {
        printf("NULL\n");
    } else if (block == &marker) {
        printf("marker\n");
    } else if (block->next == &marker) {
        printf("block: %p, size: %u, next: marker\n", block, block->size);
    } else {
        printf("block: %p, size: %u, next: %p\n", block, block->size, block->next);
    }
}

static int check_subintegrity(const allocated_block *first, const allocated_block *top, size_t size_start,
                              size_t hypothetical_size) {
    if (first == top) {
        return 0;
    }
    printf("Integrity check: checking sublist from %p to %p, size_start = %u, hypothetical_size: %u\n", first, top,
           size_start, hypothetical_size);
    const allocated_block *curr = first;
    size_t size = size_start;
    while (curr < top) {
        size += curr->size;
        printf("Integrity check: checking allocated block at %p (size: %u) - current total = %u\n", curr, curr->size,
               size);
        if (curr->size == 0) {
            printf("Integrity check failed: curr->size is 0\n");
            pcsx_debugbreak();
            return 1;
        }
        if (curr->size < sizeof(allocated_block)) {
            printf("Integrity check failed: curr->size is too small\n");
            pcsx_debugbreak();
            return 1;
        }
        if (curr->size % (sizeof(void *) * 2) != 0) {
            printf("Integrity check failed: curr->size is not aligned\n");
            pcsx_debugbreak();
            return 1;
        }
        if (size > hypothetical_size) {
            printf("Integrity check failed: size > hypothetical_size\n");
            pcsx_debugbreak();
            return 1;
        }
        curr = (allocated_block *)((char *)curr + curr->size);
    }
    if (size != hypothetical_size) {
        printf("Integrity check failed: size != hypothetical_size\n");
        print_block((empty_block *)first);
        pcsx_debugbreak();
        return 1;
    }
    return 0;
}

static void check_integrity() {
    empty_block *curr = head;
    if (head != (empty_block *)bottom) {
        allocated_block *last = head == &marker ? top : (allocated_block *)head;
        if (check_subintegrity(bottom, last, 0, (last - bottom) * sizeof(empty_block))) return;
    }
    while (curr != &marker) {
        printf("Integrity check: checking ");
        print_block(curr);
        if (curr->next == NULL) {
            printf("Integrity check failed: curr->next is NULL\n");
            print_block(curr);
            pcsx_debugbreak();
            return;
        }
        if (curr->next == curr) {
            printf("Integrity check failed: curr->next is curr\n");
            print_block(curr);
            pcsx_debugbreak();
            return;
        }
        if (curr->size == 0) {
            printf("Integrity check failed: curr->size is 0\n");
            print_block(curr);
            pcsx_debugbreak();
            return;
        }
        if (curr->size < sizeof(empty_block)) {
            printf("Integrity check failed: curr->size is too small\n");
            print_block(curr);
            pcsx_debugbreak();
            return;
        }
        if ((uintptr_t)curr->next % sizeof(void *) != 0) {
            printf("Integrity check failed: curr->next is not aligned\n");
            print_block(curr);
            pcsx_debugbreak();
            return;
        }
        if (curr->size % (sizeof(void *) * 2) != 0) {
            printf("Integrity check failed: curr->size is not aligned\n");
            print_block(curr);
            pcsx_debugbreak();
            return;
        }
        if ((curr > curr->next) && (curr->next != &marker)) {
            printf("Integrity check failed: curr > curr->next\n");
            print_block(curr);
            pcsx_debugbreak();
            return;
        }
        allocated_block *last = curr->next == &marker ? top : (allocated_block *)curr->next;
        allocated_block *ptr = (allocated_block *)((char *)curr + curr->size);
        size_t start_size = curr->size;
        size_t hypothetical = ((empty_block *)last - curr) * sizeof(empty_block);
        if (check_subintegrity(ptr, last, start_size, hypothetical)) return;
        curr = curr->next;
    }
    printf("Integrity check passed\n");
}
#else
#define dprintf(...)
#define print_block(x)
#define check_integrity()
#endif

#ifdef USE_PCSXMSAN
void *psyqo_malloc(size_t size) { return pcsx_msanAlloc(size); }
void psyqo_free(void *ptr) { pcsx_msanFree(ptr); }
void *psyqo_realloc(void *ptr, size_t size) { return pcsx_msanRealloc(ptr, size); }
#else
void *psyqo_malloc(size_t size_) {
    dprintf("psyqo_malloc(%u)\n", size_);
    empty_block *curr = head;
    empty_block *prev = NULL;
    empty_block *best_fit = NULL;
    empty_block *best_fit_prev = NULL;

    // Empty allocations don't really exist here, meaning we will always
    // return a valid pointer. We want to store the size of the allocation
    // before the pointer, in an allocated_block.
    size_t size = ALIGN_TO(size_ + sizeof(allocated_block));
    dprintf("psyqo_malloc(%u) -> %u\n", size_, size);

    // If head is NULL, it means we need to initialize the heap. This means
    // computing the size of the heap, according to the stack pointer.
    if (curr == NULL) {
        marker.next = NULL;
        marker.size = 0;
        curr = head = (empty_block *)ALIGN_TO((void *)&__heap_start);
        bottom = (allocated_block *)curr;
        curr->next = &marker;
        // We need to compute the size of the heap, according to the stack pointer.
        // Its size needs to be aligned to the empty_block size.
        curr->size = ALIGN_TO(((size_t)&__stack_start) - ((size_t)curr) - sizeof(empty_block));
        top = (allocated_block *)((char *)curr + curr->size);
    }

    // Walk the full list of empty blocks, and find the best fit,
    // keeping track of the previous block. The previous block
    // may be NULL if the best fit is the first block. In this context,
    // best fit means the smallest block that is still big enough.
    size_t curr_size = 0;
    while ((curr_size != size) && (curr != &marker)) {
        dprintf("psyqo_malloc: curr: ");
        print_block(curr);
        curr_size = curr->size;
        // Is the current block even fitting?
        if (curr_size >= size) {
            // Yes - is it a new best fit?
            if ((best_fit == NULL) || (curr_size < best_fit->size)) {
                best_fit = curr;
                best_fit_prev = prev;
                dprintf("psyqo_malloc: new best fit: ");
                print_block(best_fit);
            }
        }
        prev = curr;
        curr = curr->next;
    }

    // If we didn't find a fitting block, return NULL. This is
    // the case when the heap is full, and we've ran out of memory.
    if (best_fit == NULL) {
        dprintf("psyqo_malloc(%u) failed\n", size_);
        return NULL;
    }

    size_t best_fit_size = best_fit->size;

    // At this point, we have the best fit block. The best fit
    // block will become the returned pointer. We will mangle
    // it a bit, right before returning it, but make it now
    // for readability.
    allocated_block *ptr = (allocated_block *)best_fit;

    // At this point, we need to update the linked list. There are
    // two paths:
    // 1. If the current block is exactly the size we need, we can just
    //    remove it from the list, and link the previous block to the next one.
    //    Note that due to the granularity of the empty blocks, this is always
    //    possible, and we don't have to worry about blocks which may not be
    //    big enough to hold an empty block.
    // 2. If the current block is bigger than we need, we need to create
    //    a new empty block after what we are allocating.
    if (best_fit_size == size) {
        // Case 1: Remove the block from the list.
        if (best_fit_prev == NULL) {
            head = best_fit->next;
        } else {
            best_fit_prev->next = best_fit->next;
        }
    } else {
        // Case 2: Create a new empty block after what we are allocating.
        empty_block *new_block = (empty_block *)((char *)best_fit + size);
        new_block->next = best_fit->next;
        new_block->size = best_fit_size - size;
        if (best_fit_prev == NULL) {
            head = new_block;
        } else {
            best_fit_prev->next = new_block;
        }
    }

    // Store the size of the allocation before the pointer.
    ptr->size = size;
    ptr++;

    dprintf("psyqo_malloc(%u) -> %p\n", size_, ptr);
    check_integrity();
    return ptr;
}

void psyqo_free(void *ptr_) {
    dprintf("psyqo_free(%p)\n", ptr_);
    // Freeing NULL is a no-op.
    if (ptr_ == NULL) {
        return;
    }

    empty_block *block = (empty_block *)ptr_;
    block--;
    size_t size = block->size;

    // Is head pointing to our marker? If that's the case, the
    // heap was totally full. So freeing this block means
    // simply re-creating the head.
    if (head == &marker) {
        head = block;
        block->next = &marker;
        // This should be a no-op, since the size is stored
        // at the same place as the size of the empty block.
        // head->size = size;
        check_integrity();
        return;
    }

    // If the head is NULL, this means the user is trying to free
    // a block that was never allocated. This is undefined behavior,
    // but we will just ignore it, because it's an easy one, and
    // it'll be a pain to debug due to the comparison below.
    if (head == NULL) {
        return;
    }

    // If the head is after the block we're freeing, we can just
    // insert it at the head of the list.
    if (head > block) {
        // Now, we need to check if the next block is adjacent to
        // the block we're freeing. If it is, we can merge them.
        if (((char *)block + size) == (char *)head) {
            block->size = head->size + size;
            block->next = head->next;
        } else {
            // Otherwise, we just insert the block at the head of the list.
            block->next = head;
            // Same as above, this is a no-op.
            // block->size = size;
        }
        head = block;
        check_integrity();
        return;
    }

    // At this point, we know that the head is before the block we're
    // freeing. So we need to walk the list until we find the block
    // that is right before the block we're freeing.
    empty_block *curr = head;
    empty_block *next = NULL;
    dprintf("psyqo_free: head: %p\n", head);
    while ((next = curr->next) != &marker) {
        dprintf("psyqo_free: curr: ");
        print_block(curr);
        dprintf("psyqo_free: next: ");
        print_block(next);
        // Is the next block after the block we're freeing?
        if (next <= block) {
            // Nope, we're not there yet.
            curr = next;
            continue;
        }

        // Yes? Insert the block before the next block.

        // At this point, there are three cases and a half.
        // 1. The current block is adjacent to the block we're freeing.
        //    In this case, we merge the current block with the block we're freeing,
        //    and we need to check if the next block is adjacent to the block we're freeing
        //    too, to merge all three blocks.
        // 2. The next block is adjacent to the block we're freeing.
        //    In this case, we merge the next block with the block we're freeing.
        // 3. The block we're freeing is in the middle of the list.
        //    In this case, we just insert the block before the next block.

        // Case 1: The current block is adjacent to the block we're freeing.
        if (((char *)curr + curr->size) == (char *)block) {
            curr->size += size;
            // Now, we need to check if the next block is adjacent to
            // the block we're freeing. If it is, we can merge them.
            if (((char *)curr + curr->size) == (char *)next) {
                curr->size += next->size;
                curr->next = next->next;
            }
            // Case 2: The next block is adjacent to the block we're freeing.
        } else if (((char *)block + size) == (char *)next) {
            block->next = next->next;
            block->size = size + next->size;
            curr->next = block;
        } else {
            // Case 3: The block we're freeing is in the middle of the list.
            block->next = next;
            // Same as above, this is a no-op.
            // block->size = size;
            curr->next = block;
        }
        check_integrity();
        return;
    }

    // If we end up here, it means we reached the end of the list,
    // and the block we're freeing is after the last block.
    // At this point, the pointer curr is pointing to the last block.
    // We need to check if the last block is adjacent to the block we're freeing.
    // If it is, we can merge them.
    if (((char *)curr + curr->size) == (char *)block) {
        curr->size += size;
    } else {
        // If the last block is not adjacent to the block we're freeing,
        // we can just insert the block at the end of the list.
        block->next = &marker;
        // Same as above, this is a no-op.
        // block->size = size;
        curr->next = block;
    }
    check_integrity();
}

void *psyqo_realloc(void *ptr_, size_t size_) {
    dprintf("psyqo_realloc(%p, %u)\n", ptr_, size_);
    // If the pointer is NULL, we can just call malloc.
    if (ptr_ == NULL) {
        dprintf("psyqo_realloc(%p, %u) -> malloc\n", ptr_, size_);
        return psyqo_malloc(size_);
    }

    // If the size is 0, we can just call free.
    if (size_ == 0) {
        dprintf("psyqo_realloc(%p, %u) -> free\n", ptr_, size_);
        psyqo_free(ptr_);
        return NULL;
    }

    size_t size = ALIGN_TO(size_ + sizeof(empty_block));
    dprintf("psyqo_realloc(%p, %u) -> %u\n", ptr_, size_, size);
    // Get the current size of the block.
    empty_block *block = (empty_block *)ptr_;
    size_t old_size = (--block)->size;

    // If the new size is the same as the old size, we can just return the pointer.
    if (size == old_size) {
        dprintf("psyqo_realloc(%p, %u) -> same\n", ptr_, size_);
        return ptr_;
    }

    // Is our memory already completely full?
    if (head == &marker) {
        // If we're shrinking the allocation, then we can
        // create a new empty block after what we are re-allocating,
        // and re-create our list.
        if (size < old_size) {
            empty_block *new_block = (empty_block *)((char *)block + size);
            new_block->next = &marker;
            new_block->size = old_size - size;
            head = new_block;
            block->size = size;
            dprintf("psyqo_realloc(%p, %u) -> %p\n", ptr_, size_, ptr_);
            check_integrity();
            return ptr_;
        }
        // Otherwise, we're out of luck, and we need to error out
        // with a NULL pointer signalling we're out of memory.
        return NULL;
    }

    // Special case: is the allocated block before the head?
    if (block < head) {
        // Are we shrinking?
        if (size < old_size) {
            // If we are, we can just create a new empty block after what we are re-allocating.
            empty_block *new_block = (empty_block *)((char *)block + size);
            // Is it adjacent to our head?
            if (head == (empty_block *)((char *)block + size)) {
                // Yes, we can merge them.
                new_block->next = head->next;
                new_block->size = head->size + (old_size - size);
            } else {
                // No, we need to create a new empty block after what we are re-allocating.
                new_block->next = head;
                new_block->size = old_size - size;
            }
            head = new_block;
            block->size = size;
            dprintf("psyqo_realloc(%p, %u) -> %p\n", ptr_, size_, ptr_);
            check_integrity();
            return ptr_;
        }
        // We are growing. Is the first block adjacent to the block we're re-allocating?
        // If the first block is adjacent to the block we're re-allocating,
        // and it has enough space to hold the new size, we can just grow
        // the allocation.
        if (((char *)block + old_size) == (char *)head) {
            size_t delta = size - old_size;
            if (head->size >= delta) {
                // If it has exactly the right amount of space, we can just remove
                // the first block from the list.
                if (head->size == delta) {
                    head = head->next;
                } else {
                    // Otherwise, we need to create a new empty block after what we are re-allocating.
                    empty_block *new_block = (empty_block *)((char *)block + size);
                    new_block->next = head;
                    new_block->size = delta;
                    head = new_block;
                }
                block->size = size;
                dprintf("psyqo_realloc(%p, %u) -> %p\n", ptr_, size_, ptr_);
                check_integrity();
                return ptr_;
            }
        }
    } else {
        // We need to locate where in the list the pointer is. To do this,
        // we need to walk the list until we find the block that is right before
        // the block we're re-allocating.
        empty_block *curr = head;
        empty_block *next = NULL;
        while ((next = curr->next) != NULL) {
            dprintf("psyqo_realloc: curr: ");
            print_block(curr);
            // Is the next block after the block we're re-allocating?
            if ((next <= block) && (next != &marker)) {
                // Nope, we're not there yet.
                curr = next;
            } else {
                break;
            }
        }

        // Here, curr points to the empty block before the block we're re-allocating,
        // and next points to the empty block after the block we're re-allocating, or
        // to marker if we're at the end of the list.

        // Are we shrinking the allocation?
        if (size < old_size) {
            // We're going to create a new block at the end of what we are re-allocating.
            empty_block *new_block = (empty_block *)((char *)block + size);
            // Is the next block adjacent to the block we're re-allocating?
            if ((next != &marker) && (((char *)block + size) == (char *)next)) {
                // Yes, we can merge them.
                new_block->next = next->next;
                new_block->size = old_size - size + next->size;
            } else {
                // No. Create a new empty block after what we are re-allocating.
                new_block->next = next;
                new_block->size = old_size - size;
            }
            curr->next = new_block;
            block->size = size;
            dprintf("psyqo_realloc(%p, %u) -> %p\n", ptr_, size_, ptr_);
            check_integrity();
            return ptr_;
        }

        // If we're growing the allocation, we need to check if the next block
        // is adjacent to the block we're re-allocating, and if it has enough
        // space to hold the new size.

        size_t delta = size - old_size;
        if ((next != &marker) && (((char *)block + old_size) == (char *)next) && (next->size >= delta)) {
            // If it does, we can just grow the allocation.
            // Do we have exactly the right amount of space available?
            if (next->size == delta) {
                // Yes? Then we can just remove the next block from the list.
                curr->next = next->next;
            } else {
                // No? Then we need to create a new block after what we are re-allocating.
                empty_block *new_block = (empty_block *)((char *)block + size);
                new_block->next = next->next;
                new_block->size = next->size - delta;
                curr->next = new_block;
            }
            block->size = size;
            dprintf("psyqo_realloc(%p, %u) -> %p\n", ptr_, size_, ptr_);
            check_integrity();
            return ptr_;
        }

        // Technically at this point, we have one last recourse before going for
        // allocating memory elsewhere: we could try to probe if the block before
        // the block we're re-allocating is adjacent to it, and if it is, we could
        // try to merge it if it has enough space. This would require walking the
        // list again, or use double-linked lists, and it requires memmove. Pain.
        // So let's just ignore this case.
    }

    void *new_ptr = psyqo_malloc(size_);
    if (new_ptr == NULL) {
        dprintf("psyqo_realloc(%p, %u) -> NULL\n", ptr_, size_);
        return NULL;
    }
    __builtin_memcpy(new_ptr, ptr_, old_size - sizeof(empty_block));
    psyqo_free(ptr_);
    dprintf("psyqo_realloc(%p, %u) -> %p\n", ptr_, size_, new_ptr);
    return new_ptr;
}
#endif

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

void *psyqo_heap_start() { return bottom; }
void *psyqo_heap_end() { return top; }
