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

#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Decompress a block of lz4 compressed data.
 *
 * @details This function decompresses a block of lz4 compressed data. The
 * source pointer should point to the start of the compressed data, and
 * sourceEnd should point to the end of the compressed data. The dest
 * pointer should point to a buffer that is large enough to hold the
 * decompressed data, as the function does not perform any bounds checking.
 * The function can decompress data in place, and the way the compression
 * works allows for all of the compressed data to be at the end of the
 * same buffer used to store the decompressed data. In this case, the
 * whole of the compressed data will be completely overwritten by the
 * decompressed data.
 *
 * @note The function does not check for the validity of the
 * compressed data. If the data is corrupted, this will likely result
 * in a crash or an infinite loop. The caller is responsible for
 * ensuring that the data is valid and that the destination buffer
 * is large enough to hold the decompressed data.
 *
 * @param source The pointer to the start of the compressed data.
 * @param sourceEnd The pointer to the end of the compressed data.
 * @param dest The pointer to the destination buffer where the
 * decompressed data will be stored.
 */
void lz4_decompress_block(const void* source, const void* sourceEnd, void* dest);
