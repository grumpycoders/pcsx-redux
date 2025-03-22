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

#include "psyqo/advancedpad.hh"

#include "common/syscalls/syscalls.h"
#include "psyqo/hardware/cpu.hh"
#include "psyqo/hardware/sio.hh"
#include "psyqo/kernel.hh"
#include "psyqo/utility-polyfill.h"

using namespace psyqo::Hardware;

void psyqo::AdvancedPad::initialize(PollingMode mode) {
    // Init Pads
    __builtin_memset(m_padData, 0xff, sizeof(m_padData));
    m_portsToProbeByVSync = mode == PollingMode::Normal ? 1 : 2;

    SIO::Ctrl = SIO::Control::CTRL_IR;
    SIO::Baud = 0x88;  // 250kHz
    SIO::Mode = 0xd;   // MUL1, 8bit, no parity, normal polarity
    SIO::Ctrl = 0;

    Kernel::Internal::addOnFrame([this]() {
        readPad();

        if (!m_callback) return;

        processChanges(Pad::Pad1a);
        processChanges(Pad::Pad1b);
        processChanges(Pad::Pad1c);
        processChanges(Pad::Pad1d);
        processChanges(Pad::Pad2a);
        processChanges(Pad::Pad2b);
        processChanges(Pad::Pad2c);
        processChanges(Pad::Pad2d);
    });
}

void psyqo::AdvancedPad::configurePort(uint8_t port) {
    SIO::Ctrl = (port * SIO::Control::CTRL_PORTSEL) | SIO::Control::CTRL_DTR;
    SIO::Baud = 0x88;  // 250kHz
    flushRxBuffer();
    SIO::Ctrl |= (SIO::Control::CTRL_TXEN | SIO::Control::CTRL_ACKIRQEN);
    busyLoop(100);  // Required delay for pad stability. 100 cycles gives about 23us before the first clock pulse
}

inline void psyqo::AdvancedPad::flushRxBuffer() {
    while (SIO::Stat & SIO::Status::STAT_RXRDY) {
        SIO::Data.throwAway();  // throwaway read
    }
}

uint8_t psyqo::AdvancedPad::outputDefault(unsigned ticks) {
    uint8_t dataOut = 0x00;
    switch (ticks) {
        case 0:
        case 2:
            dataOut = 0x01;
            break;
        case 1:
            dataOut = 0x42;
            break;
    }

    return dataOut;
}

uint8_t psyqo::AdvancedPad::outputMultitap(unsigned ticks) {
    uint8_t dataOut = 0x00;

    switch (ticks) {
        case 0:  // Pad select
        case 2:  // Buffered transfer
            dataOut = 0x01;
            break;

        case 1:   // Initial read command
        case 3:   // Read pad A
        case 11:  // Read pad B
        case 19:  // Read pad C
        case 27:  // Read pad D
            dataOut = 0x42;
            break;
    }

    switch (ticks) {
        case 2:                // Burst speed for idhi
        case 11:               // Burst speed for Pads B-D
            SIO::Baud = 0x22;  // 1MHz
            break;

        case 3:                // Return to normal speed for Pad A
            SIO::Baud = 0x88;  // 250kHz
            break;
    }

    return dataOut;
}

void psyqo::AdvancedPad::processChanges(Pad pad) {
    const unsigned padIndex = toUnderlying(pad);
    bool padConnected = isPadConnected(pad);
    bool wasConnected = m_connected[padIndex];
    if (wasConnected && !padConnected) {
        m_callback(Event{Event::PadDisconnected, pad});
    } else if (!wasConnected && padConnected) {
        m_callback(Event{Event::PadConnected, pad});
    }
    m_connected[padIndex] = padConnected;
    if (!padConnected) return;

    // Note: Data is only 16-bits, but leave these as uint32_t, for codegen
    uint32_t mask = 1;
    uint32_t padData = m_padData[padIndex].buttons;
    uint32_t buttons = m_buttons[padIndex];
    for (int i = 0; i < 16; i++, mask <<= 1) {
        bool buttonPressed = (padData & mask) == 0;
        bool wasButtonPressed = (buttons & mask) == 0;
        if (buttonPressed && !wasButtonPressed) {
            m_callback(Event{Event::ButtonPressed, pad, Button(i)});
        } else if (!buttonPressed && wasButtonPressed) {
            m_callback(Event{Event::ButtonReleased, pad, Button(i)});
        }
    }
    m_buttons[padIndex] = padData;
}

inline uint8_t psyqo::AdvancedPad::transceive(uint8_t dataOut) {
    SIO::Ctrl |= SIO::Control::CTRL_ERRRES;  // Clear error
    CPU::IReg.clear(CPU::IRQ::Controller);   // Clear IRQ

    SIO::Data = dataOut;

    // Wait for transceive to complete and data to populate FIFO
    while (!(SIO::Stat & SIO::Status::STAT_RXRDY));

    // Pull data from FIFO
    return SIO::Data;
}

void psyqo::AdvancedPad::readPad() {
    uint8_t dataIn, dataOut;
    uint8_t portDevType[2] = {PadType::None, PadType::None};

    static constexpr unsigned padDataWidth = sizeof(PadData);
    const unsigned portsToProbeByVSync = m_portsToProbeByVSync;
    uint8_t port = m_portToProbe;

    for (unsigned i = 0; i < portsToProbeByVSync; i++) {
        configurePort(port);

        uint8_t *padData = reinterpret_cast<uint8_t *>(&m_padData[port * 4].packed[0]);
        __builtin_memset(padData, 0xff, sizeof(m_padData[0]));

        for (unsigned ticks = 0, maxTicks = 5; ticks < maxTicks; ticks++) {
            if (portDevType[port] == PadType::Multitap) {
                dataOut = outputMultitap(ticks);
            } else {
                dataOut = outputDefault(ticks);
            }
            dataIn = transceive(dataOut);
            // To-do: Check SIO status for errors, abort if necessary

            // Set port type and total number of half-words to read
            if (ticks == 2) {
                if (dataIn == 0x5a || dataIn == 0x00) {  // Verify idhi byte
                    // To-do: Implement config mode
                    // If the LED was previously forced off, as is the case with xloader, the pad will return 0x00 for
                    // idhi. The pad will reset after a few seconds of no activity, but we can't wait that long. For
                    // now, we can just ignore this and treat it as a normal pad

                    // Set number of half-words to read
                    maxTicks = portDevType[port] & 0x0f;
                    if (!maxTicks) {
                        maxTicks = 0x10;
                    }
                    maxTicks = (maxTicks * 2) + ticks + 1;

                    padData[0] = 0;
                } else {
                    // Derp? Unknown device type or bad data, stop reading
                    maxTicks = ticks;
                    padData[0] = 0xff;
                    padData[1] = PadType::None;
                }
            }

            if (portDevType[port] == PadType::Multitap) {  // Process data for Multitap device
                const unsigned padIndex = ticks >= 11 ? (ticks - 3) / 8 : 0;

                switch (ticks) {
                        // Unreachable
                        // case 0:
                        // case 1:
                        // break;

                    case 2:
                        // Discard data
                        break;

                    case 4:   // Pad A
                    case 12:  // Pad B
                    case 20:  // Pad C
                    case 28:  // Pad D
                        // 0 = connected
                        padData[(padDataWidth * padIndex) + 0] = dataIn != 0x5a;
                        break;

                    case 3:   // Pad A idlo
                    case 11:  // Pad B idlo
                    case 19:  // Pad C idlo
                    case 27:  // Pad D idlo
                        padData[(padDataWidth * padIndex) + 1] = dataIn;
                        break;

                    default:
                        padData[(padDataWidth * padIndex) + ((ticks - 3) % 8)] = dataIn;
                }
            } else {  // Process data for single device
                switch (ticks) {
                    case 0:  // Discard data
                        break;

                    case 1:
                        portDevType[port] = dataIn;
                        if (dataIn != PadType::Multitap) {
                            padData[1] = dataIn;
                        }
                        break;

                    case 2:
                        padData[0] = dataIn != 0x5a;
                        break;

                    default:
                        padData[ticks - 1] = dataIn;
                }
            }

            // Wait for ACK except on last tick
            if (ticks < (maxTicks - 1)) {
                if (!waitForAck()) {
                    // Timeout waiting for ACK
                    portDevType[port] = PadType::None;
                    for (int padIndex = 0; padIndex < 4; padIndex++) {
                        padData[(padDataWidth * padIndex)] = 0x01;
                    }
                    break;
                }

                while (SIO::Stat & SIO::Status::STAT_ACK);  // Wait for ACK to return to high
            }
        }  // tick loop

        // End transmission
        SIO::Ctrl = 0;
        port ^= 1;
    }  // port loop
    m_portToProbe = port;
}

inline bool psyqo::AdvancedPad::waitForAck() {
    int cyclesWaited = 0;
    static constexpr int ackTimeout = 0x137;  // 137h = ~105us

    while (!(CPU::IReg.isSet(CPU::IRQ::Controller)) && ++cyclesWaited < ackTimeout);

    if (cyclesWaited >= ackTimeout) {
        // Timeout waiting for ACK
        return false;
    }

    return true;
}
