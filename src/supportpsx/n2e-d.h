/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

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

namespace n2e_d {

// see the file n2e-d.S for the source of this code
// its source is a bit too complex for the compile-time encoder

static constexpr uint32_t code[] = {
    0x03e0c825, 0x00007025, 0x1000002b, 0x240a0001, 0x04110038, 0x000b5840, 0x04110036, 0x01625821, 0x14400005,
    0x256bffff, 0x04110032, 0x000b5840, 0x1000fff7, 0x01625821, 0x2569ffff, 0x15200025, 0x000b5a00, 0x0411002b,
    0x00000000, 0x04110029, 0x30490001, 0x1520000e, 0x244b0003, 0x14400009, 0x240b0001, 0x04110023, 0x000b5840,
    0x04110021, 0x01625821, 0x1040fffb, 0x00000000, 0x10000004, 0x256b0005, 0x0411001b, 0x00000000, 0x244b0005,
    0x2d490501, 0x01695823, 0x00aa6823, 0x91a90000, 0x25ad0001, 0xa0a90000, 0x00000000, 0x256bffff, 0x1560fffa,
    0x24a50001, 0x0411000e, 0x240b0001, 0x1040ffd3, 0x00806825, 0x1000fff4, 0x24840001, 0x03200008, 0x24840001,
    0x9089ffff, 0x256bfe01, 0x01691021, 0x1040fffa, 0x24490001, 0x1000ffd7, 0x00095042, 0x15c00004, 0x25ceffff,
    0x88880000, 0x24840001, 0x25ce0008, 0x000817c2, 0x03e00008, 0x00084040,
};

}  // namespace n2e_d
