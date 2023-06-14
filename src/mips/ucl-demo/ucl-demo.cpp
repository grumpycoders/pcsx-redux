/*

MIT License

Copyright (c) 2023 PCSX-Redux authors

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

#include "common/hardware/pcsxhw.h"
#include "common/kernel/pcdrv.h"
#include "common/syscalls/syscalls.h"
#include "psyqo/adler32.hh"
#include "ucl-demo/n2e-d.h"

// The header for our compressed file format example.
struct N2EDHeader {
    uint32_t magic;
    uint32_t decompsize;
    uint32_t compsize;
    uint32_t adler;
};

// We will decompress and use the files from this buffer. Of course, this doesn't have to be this way.
// Using memory allocation functions will work just fine, as long as the extra 16-bytes of space are
// allocated for the UCL library to decompress in-place. Doing the following sequence of operations
// for each asset to load ought to work just fine and create a neat and tucked memory layout:
//
// uint8_t * decompressed = malloc(header.decompsize + 16);
// uint8_t * compressed = decompressed + header.decompsize - header.compsize + 16;
// read(fd, compressed, header.compsize);
// n2e_decompress(compressed, buffer);
// decompressed = realloc(decompressed, header.decompsize);
static uint8_t buffer[1024 * 1024];

// Safely stopping.
static void stop(int code) {
    pcsx_exit(code);
    for (;;) {
        pcsx_debugbreak();
    }
}

int main() {
    // Most of this here is going to be boilerplate to load the demo.bin file from PCdrv.
    int r = PCinit();
    if (r != 0) {
        ramsyscall_printf("Failed to initialize PC driver: %d\n", r);
        stop(1);
    }

    int fd = PCopen("demo.bin", 0, 0);
    if (fd < 0) {
        ramsyscall_printf("Failed to open demo.bin file: %d\n", fd);
        stop(1);
    }

    struct N2EDHeader header;
    r = PCread(fd, &header, sizeof(header));
    if (r != sizeof(header)) {
        ramsyscall_printf("Failed to read file header: %d\n", r);
        stop(1);
    }

    if (header.magic != 0x4e324501) {
        ramsyscall_printf("Invalid file magic: %08X\n", header.magic);
        stop(1);
    }

    if (header.decompsize > sizeof(buffer)) {
        ramsyscall_printf("File is too big: %08X\n", header.decompsize);
        stop(1);
    }

    // We will read the compressed data directly into the buffer, skipping the header, but
    // tucking it at the end of the decompressed data + 16 bytes, in order to showcase how
    // to decompress data in-place. The UCL library technically requires the compressed data
    // to overlap the decompressed data by 16 bytes, in order to be able to safely decompress
    // in-place. In practice, it only requires about 4 bytes, but we will use 16 bytes here
    // as documented in the UCL library.
    uint8_t * compressed = buffer + header.decompsize - header.compsize + 16;

    r = PCread(fd, compressed, header.compsize);
    if (r != header.compsize) {
        ramsyscall_printf("Failed to read file data: %d\n", r);
        stop(1);
    }

    r = PCclose(fd);
    if (r != 0) {
        ramsyscall_printf("Failed to close file: %d\n", r);
        stop(1);
    }

    // Decompress the data in-place. After this, the decompressed data will be at the start of
    // the buffer, and the compressed data will have been overwritten. If using memory allocation
    // instead of a fixed buffer, this would be a good time to realloc() the buffer to the
    // decompressed size.
    n2e_decompress(compressed, buffer);

    // This is really only for the demo, to show that the decompressed data is correct. Paranoid
    // users may want to keep this in their own code, but it's not really necessary.
    uint32_t adler = psyqo::adler32(buffer, header.decompsize);

    if (adler != header.adler) {
        ramsyscall_printf("CRC mismatch: %08X != %08X\n", adler, header.adler);
        stop(1);
    }

    ramsyscall_printf("Success!\n");
    stop(0);
}
