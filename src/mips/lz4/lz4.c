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

#include <stddef.h>
#include <stdint.h>

// See https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md
// We are not taking too much care about the fault tolerance of the
// decompression code. While the LZ4 format is not very complex, it
// has a few failure modes that we are not handling. This means that
// if the data is corrupted, this will likely result in a crash or an
// infinite loop.
void lz4_decompress_block(const void* source_, const void* sourceEnd_, void* dest_) {
    uint8_t* source = (uint8_t*)source_;
    uint8_t* sourceEnd = (uint8_t*)sourceEnd_;
    uint8_t* dest = (uint8_t*)dest_;
    uint8_t token;
    int state = 0;

    do {
        size_t len;
        size_t offset;
        // Decompression flips flops between copying literal bytes and
        // copying back references. The first byte of the block is a
        // token that indicates the length of the literal bytes and
        // the length of the back reference. We always start with
        // copying literal bytes, which is indicated by state == 0.
        if (state == 0) {
            // The top 4 bits of the token indicate the length of the
            // literal bytes.
            token = *source++;
            len = token >> 4;
        } else {
            // In the second state, the lower 4 bits of the token
            // indicate the length of the back reference. The offset
            // is a 16-bit value that is stored in the next two bytes
            // of the stream.
            offset = source[0] | (source[1] << 8);
            source += 2;
            len = token & 0x0f;
        }
        // The length is always stored using a variable-length encoding,
        // which is what comes next. If the length is 15, we need to
        // read more bytes until we get a value that is not 255.
        if (len == 0x0f) {
            uint8_t b;
            do {
                b = *source++;
                len += b;
            } while (b == 255);
        }
        uint8_t* ptr;
        if (state == 0) {
            // When copying literal bytes, just copy the bytes
            // directly from the source to the destination.
            ptr = source;
        } else {
            // When copying back references, we need to copy the
            // bytes from the destination buffer. Also, the minimum
            // length of the back reference is 4 bytes, so we need
            // to bump the length by 4.
            ptr = dest - offset;
            len += 4;
        }
        // Do the actual copying of the bytes. It doesn't matter
        // whether we are copying literal bytes or back references,
        // the code is the same.
        uint8_t* ptrEnd = ptr + len;
        while (ptr != ptrEnd) {
            *dest++ = *ptr++;
        }
        if (state == 0) {
            // When copying literal bytes, we need to update the
            // source pointer to point to the next byte after the
            // literal bytes.
            source = ptr;
        }
        // We flip the state before we go to the next iteration.
        state ^= 1;
        // The lz4 format doesn't have a way to indicate the end of the
        // stream, so we need to check if we are at the end of the
        // source buffer.
    } while (source < sourceEnd);
}
