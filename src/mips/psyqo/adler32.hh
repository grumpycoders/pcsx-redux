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

#include <stdint.h>

namespace psyqo {

/**
 * @brief Computes the adler32 checksum of a buffer.
 *
 * @details This is a very fast checksum algorithm, but it is not cryptographically
 * secure. It can be used to detect data corruption. It is possible to chunk large
 * buffers by chaining the checksum of the previous chunk with the checksum of the
 * next using the `sum` parameter. As an example, here is how to compute the
 * checksum of a 1MB buffer fragmented over 1024 chunks of 1024 bytes:
 * @code {.language-id=cpp}
 * uint32_t checksum = adler32(nullptr, 0);
 * for (unsigned i = 0; i < 1024; i++) {
 *     checksum = adler32(buffer + i * 1024, 1024, checksum);
 * }
 * @endcode
 *
 * @param[in] buffer The buffer to checksum.
 * @param[in] size The size of the buffer in bytes.
 * @param[in] sum The previous sum to continue the checksum for.
 * @return The adler32 checksum of the buffer.
 */
uint32_t adler32(uint8_t* buffer, unsigned length, uint32_t sum = 1);

/**
 * @brief Computes the adler32 checksum of a buffer, only reading bytes.
 *
 * @details This is a variant of the `adler32` function, which works exclusively
 * on bytes.
 *
 * @param[in] buffer The buffer to checksum.
 * @param[in] size The size of the buffer in bytes.
 * @param[in] sum The previous sum to continue the checksum for.
 * @return The adler32 checksum of the buffer.
 */
uint32_t adler32_bytes(uint8_t* buffer, unsigned length, uint32_t sum = 1);

/**
 * @brief Computes the adler32 checksum of a buffer, optimized for words.
 *
 * @details This is a variant of the `adler32` function, which works exclusively
 * on words. It is faster than the byte-oriented version, but the buffer needs to
 * be aligned to a word boundary. It is possible to mix the two versions by
 * using the `sum` parameter as explained in the documentation of the byte-oriented
 * version.
 *
 * @param[in] buffer The buffer to checksum.
 * @param[in] size The size of the buffer in words.
 * @param[in] sum The previous sum to continue the checksum for.
 * @return The adler32 checksum of the buffer.
 */
uint32_t adler32_words(uint32_t* buffer, unsigned length, uint32_t sum = 1);

}  // namespace psyqo
