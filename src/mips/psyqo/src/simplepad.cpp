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

#include "psyqo/simplepad.hh"

#include "common/syscalls/syscalls.h"
#include "psyqo/kernel.hh"

void psyqo::SimplePad::initialize() {
    syscall_initPad(m_padData[0], sizeof(m_padData[0]), m_padData[1], sizeof(m_padData[1]));
    syscall_startPad();
    __builtin_memset(m_padData[0], 0xff, sizeof(m_padData[0]));
    __builtin_memset(m_padData[1], 0xff, sizeof(m_padData[1]));
    Kernel::Internal::addOnFrame([this]() {
        if (!m_callback) return;

        processChanges(Pad1);
        processChanges(Pad2);
    });
}

void psyqo::SimplePad::processChanges(Pad pad) {
    bool padConnected = isPadConnected(pad);
    bool wasConnected = m_connected[pad];
    if (wasConnected && !padConnected) {
        m_callback(Event{Event::PadDisconnected, pad});
    } else if (!wasConnected && padConnected) {
        m_callback(Event{Event::PadConnected, pad});
    }
    m_connected[pad] = padConnected;

    uint32_t mask = 1;
    uint32_t padData = m_padData[pad][1];
    uint32_t buttons = m_buttons[pad];
    for (int i = 0; i < 16; i++, mask <<= 1) {
        bool buttonPressed = (padData & mask) == 0;
        bool wasButtonPressed = (buttons & mask) == 0;
        if (buttonPressed && !wasButtonPressed) {
            m_callback(Event{Event::ButtonPressed, pad, Button(i)});
        } else if (!buttonPressed && wasButtonPressed) {
            m_callback(Event{Event::ButtonReleased, pad, Button(i)});
        }
    }
    m_buttons[pad] = padData;
}
