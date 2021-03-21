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

enum event_class {
    EVENT_VBLANK = 0xf0000001,  // IRQ0
    EVENT_GPU = 0xf0000002,     // IRQ1
    EVENT_CDROM = 0xf0000003,   // IRQ2
    EVENT_DMA = 0xf0000004,     // IRQ3
    EVENT_RTC0 = 0xf0000005,    // IRQ4 - Timer 0
    EVENT_RTC1 = 0xf0000006,    // IRQ5 - Timer 1 or 2
    //  0xf0000007 - unused, should be Timer 2
    EVENT_CONTROLLER = 0xf0000008,  // IRQ7
    EVENT_SPU = 0xf0000009,         // IRQ9
    EVENT_PIO = 0xf000000a,         // IRQ10
    EVENT_SIO = 0xf000000b,         // IRQ8
    EVENT_CARD = 0xf0000011,
    EVENT_BU = 0xf4000001,
};

enum event_mode {
    EVENT_MODE_CALLBACK = 0x1000,
    EVENT_MODE_NO_CALLBACK = 0x2000,
};

enum event_flag {
    EVENT_FLAG_FREE = 0x0000,
    EVENT_FLAG_DISABLED = 0x1000,
    EVENT_FLAG_ENABLED = 0x2000,
    EVENT_FLAG_PENDING = 0x4000,
};
