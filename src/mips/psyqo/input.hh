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

#pragma once

#include <EASTL/functional.h>
#include <stdint.h>

namespace psyqo {

class Input {
  public:
    enum Pad { Pad1, Pad2 };
    enum Button {
        Select = 0,
        L3 = 1,
        R3 = 2,
        Start = 3,
        Up = 4,
        Right = 5,
        Down = 6,
        Left = 7,
        L2 = 8,
        R2 = 9,
        L1 = 10,
        R1 = 11,
        Triangle = 12,
        Circle = 13,
        Cross = 14,
        Square = 15,
    };
    void initialize();
    bool isPadConnected(Pad pad) const { return m_padData[pad][0] == 0x4100; }
    bool isButtonPressed(Pad pad, Button button) const { return (m_padData[pad][1] & (1 << button)) == 0; }

  private:
    uint16_t m_padData[2][0x11];
};

}  // namespace psyqo
