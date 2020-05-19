/*

MIT License

Copyright (c) 2020 PCSX-Redux authors

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

#include "common/compiler/stdint.h"
#include "common/syscalls/syscalls.h"
#include "openbios/fileio/fileio.h"
#include "openbios/kernel/globals.h"
#include "openbios/kernel/threads.h"

int initThreads(int blocksCount, int count) {
    psxprintf("TCB\t0x%02x\n", count);
    int blockSize = blocksCount * sizeof(struct Thread *);
    struct Thread ** blocks = syscall_kmalloc(blockSize);
    if (!blocks) return 0;

    int arraySize = count * sizeof(struct Thread);
    struct Thread * array = syscall_kmalloc(arraySize);
    if (!array) return 0;

    struct Thread ** blockPtr = blocks;
    while (blockPtr < blocks + blocksCount) *blockPtr++ = NULL;
    struct Thread * threadPtr = array;
    while (threadPtr < array + count) threadPtr++->flags = 0x1000;
    array[0].flags = 0x4000;
    *blocks = array;

    __globals.blocks = blocks;
    __globals.threads = array;

    return blockSize + arraySize;
}
