/*

MIT License

Copyright (c) 2019 PCSX-Redux authors

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

#include "common/hardware/sio1.h"

#include "common/hardware/hwregs.h"

void sio1_init() {
    // enable TX and RX, and nothing else
    SIO1_CTRL = 5;
    // 01001110
    // Baudrate Reload Factor: MUL16 (2)
    // Character length: 8 (3)
    // Parity Disabled
    // Parity Type: irrelevant
    // Stop bit length: 1 (1)
    //  --> 8N1
    SIO1_MODE = 0x4e;
    SIO1_BAUD = 2073600 / 115200;
}

void sio1_putc(uint8_t byte) {
    while ((SIO1_STAT & 1) == 0)
        ;
    SIO1_DATA = byte;
}
