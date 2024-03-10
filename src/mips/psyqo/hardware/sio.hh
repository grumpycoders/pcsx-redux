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

#pragma once

#include <stdint.h>

#include "psyqo/hardware/hwregs.hh"

namespace psyqo::Hardware::SIO {
enum Control : uint16_t {
    CTRL_TXEN = (1 << 0),       // Transmit Enable
    CTRL_DTR = (1 << 1),        // Data Terminal Ready, aka Select (output)
    CTRL_RXE = (1 << 2),        // Receive Enable
    CTRL_SBRK = (1 << 3),       // Send Break character
    CTRL_ERRRES = (1 << 4),     // Error Reset
    CTRL_RTS = (1 << 5),        // Request to Send (output)
    CTRL_IR = (1 << 6),         // Internal Reset, resets most SIO registers
    CTRL_RXIRQMODE = (1 << 8),  // Receive IRQ Mode (0..3 = IRQ when RX FIFO contains 1,2,4,8 bytes)
    CTRL_TXIRQEN = (1 << 10),   // Transmit IRQ Enable
    CTRL_RXIRQEN = (1 << 11),   // Receive IRQ Enable
    CTRL_ACKIRQEN = (1 << 12),  // Acknowledge IRQ Enable
    CTRL_PORTSEL = (1 << 13),   // Port Select
};

enum Status : uint32_t {
    STAT_TXRDY = (1 << 0),    // TX buffer is empty
    STAT_RXRDY = (1 << 1),    // RX buffer has data
    STAT_TXEMPTY = (1 << 2),  // No data in TX buffer
    STAT_PE = (1 << 3),       // Parity Error
    STAT_OE = (1 << 4),       // Overrun Error
    STAT_FE = (1 << 5),       // Framing Error
    STAT_SYNDET = (1 << 6),   // Sync Detect
    STAT_ACK = (1 << 7),      // ACK signal level (input)
    STAT_CTS = (1 << 8),      // Clear to Send (output), unused on SIO0
    STAT_IRQ = (1 << 9),      // Interrupt Request
};

extern psyqo::Hardware::Register<0x0040, uint8_t, psyqo::Hardware::WriteQueue::Bypass> Data;
extern psyqo::Hardware::Register<0x0044, uint32_t, psyqo::Hardware::WriteQueue::Bypass> Stat;
extern psyqo::Hardware::Register<0x0048, uint16_t, psyqo::Hardware::WriteQueue::Bypass> Mode;
extern psyqo::Hardware::Register<0x004a, uint16_t, psyqo::Hardware::WriteQueue::Bypass> Ctrl;
extern psyqo::Hardware::Register<0x004e, uint16_t, psyqo::Hardware::WriteQueue::Bypass> Baud;
}  // namespace psyqo::Hardware::SIO