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

#pragma once

#include <stdint.h>

struct SIOPort {
    uint8_t fifo;
    uint8_t preview[3];
    uint16_t stat;
    uint16_t padding;
    uint16_t mode;
    uint16_t ctrl;
    uint16_t reserved;
    uint16_t baudRate;
};

#define SIOS ((volatile struct SIOPort *)0x1f801040)

enum {
    SIO_CTRL_TXEN = (1 << 0),       // Transmit Enable
    SIO_CTRL_DTR = (1 << 1),        // Data Terminal Ready, aka Select (output)
    SIO_CTRL_RXE = (1 << 2),        // Receive Enable
    SIO_CTRL_SBRK = (1 << 3),       // Send Break character
    SIO_CTRL_ERRRES = (1 << 4),     // Error Reset
    SIO_CTRL_RTS = (1 << 5),        // Request to Send (output)
    SIO_CTRL_IR = (1 << 6),         // Internal Reset, resets most SIO registers
    SIO_CTRL_RXIRQMODE = (1 << 8),  // Receive IRQ Mode (0..3 = IRQ when RX FIFO contains 1,2,4,8 bytes)
    SIO_CTRL_TXIRQEN = (1 << 10),   // Transmit IRQ Enable
    SIO_CTRL_RXIRQEN = (1 << 11),   // Receive IRQ Enable
    SIO_CTRL_ACKIRQEN = (1 << 12),  // Acknowledge IRQ Enable
    SIO_CTRL_PORTSEL = (1 << 13),   // Port Select
};

enum {
    SIO_STAT_TXRDY = (1 << 0),    // TX buffer is empty
    SIO_STAT_RXRDY = (1 << 1),    // RX buffer has data
    SIO_STAT_TXEMPTY = (1 << 2),  // No data in TX buffer
    SIO_STAT_PE = (1 << 3),       // Parity Error
    SIO_STAT_OE = (1 << 4),       // Overrun Error
    SIO_STAT_FE = (1 << 5),       // Framing Error
    SIO_STAT_SYNDET = (1 << 6),   // Sync Detect
    SIO_STAT_ACK = (1 << 7),      // ACK signal level (input)
    SIO_STAT_CTS = (1 << 8),      // Clear to Send (output), unused on SIO0
    SIO_STAT_IRQ = (1 << 9),      // Interrupt Request
};