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

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocates memory from the heap.
 *
 * @details This function behaves as you'd expect from typical malloc.
 * Allocating 0 bytes will return a valid pointer, which can be freed.
 * Guarantees to align the memory to 8 bytes.
 *
 * @param size The amount of bytes to allocate.
 * @return void* The memory allocated.
 */
void *psyqo_malloc(size_t size);

/**
 * @brief Re-allocates memory from the heap.
 *
 * @details This function behaves as you'd expect from typical realloc.
 * Allocating 0 bytes with a NULL pointer will return a valid pointer,
 * which can be freed. Allocating 0 bytes with a valid pointer will
 * behave as if free was called. Re-allocating a pointer to a smaller
 * size is always guaranteed to succeed and to return the same pointer.
 * Re-allocating a pointer to a larger size may fail, in which case,
 * it will return NULL. Passing a NULL pointer will behave like a call
 * to malloc.
 *
 * @param ptr The pointer to the memory to re-allocate.
 * @param size The amount of bytes to allocate.
 * @return void* The memory allocated.
 */
void *psyqo_realloc(void *ptr, size_t size);

/**
 * @brief Frees memory from the heap.
 *
 * @details This function behaves as you'd expect from typical free.
 * Calling this function with a NULL pointer is a no-op.
 *
 * @param ptr The pointer to the memory to free.
 */
void psyqo_free(void *ptr);

/**
 * @brief Returns the pointer to the beginning of the heap.
 *
 * @details This function will return the pointer to the beginning of the
 * heap. The heap works lazily, and this function may return a NULL
 * pointer, but once it returns a non-NULL pointer, it will always return
 * the same pointer.
 *
 * @return void* The beginning of the heap.
 */
void *psyqo_heap_start();

/**
 * @brief Returns the pointer to the end of the heap.
 *
 * @details This function will return the pointer to the end of the
 * heap. The heap works lazily, and this function may return a NULL
 * pointer. The heap can grow and shrink depending on usage. Computing
 * the current size of the heap is done by subtracting the start
 * pointer from the end pointer. Note this wouldn't account for memory
 * fragmentation.
 *
 * @return void* The end of the heap.
 */
void *psyqo_heap_end();

#ifdef __cplusplus
}
#endif
