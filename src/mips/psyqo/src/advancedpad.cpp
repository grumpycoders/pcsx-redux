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

#include "psyqo/advancedpad.hh"

#include "common/syscalls/syscalls.h"
#include "psyqo/hardware/cpu.hh"
#include "psyqo/hardware/sio.hh"
#include "psyqo/kernel.hh"

using namespace psyqo::Hardware;

void psyqo::AdvancedPad::initialize() {
    // Stop the kernel from processing pad(and card) events
    syscall_stopPad();

    for (int i = 0; i < 8; i++) {
        __builtin_memset(m_padData[i], 0xff, sizeof(m_padData[i]));
    }

    // Init Pad
    syscall_memset(m_padData[0], 0xff, sizeof(m_padData[0]));

    SIO::Ctrl = SIO::Control::CTRL_IR;
    SIO::Baud = 0x88;  // 250kHz
    SIO::Mode = 0xd;   // MUL1, 8bit, no parity, normal polarity
    SIO::Ctrl = 0;

    using namespace timer_literals;

    Kernel::Internal::addOnFrame([this]() {
        readPad();

        if (!m_callback) return;

        processChanges(Pad1a);
        processChanges(Pad1b);
        processChanges(Pad1c);
        processChanges(Pad1d);
        processChanges(Pad2a);
        processChanges(Pad2b);
        processChanges(Pad2c);
        processChanges(Pad2d);
    });
}

inline void psyqo::AdvancedPad::flushRxBuffer() {
    while (SIO::Stat & SIO::Status::STAT_RXRDY) {
        SIO::Data;  // throwaway read
    }
}

constexpr uint8_t psyqo::AdvancedPad::output_analog(uint8_t ticks) {
    uint8_t data_out = 0xff;

    switch (ticks) {}

    return data_out;
}

constexpr uint8_t psyqo::AdvancedPad::output_default(uint8_t ticks) {
    uint8_t data_out = 0x00;
    switch (ticks) {
        case 0:
        case 2:
            data_out = 0x01;
            break;
        case 1:
            data_out = 0x42;
            break;
    }

    return data_out;
}

constexpr uint8_t psyqo::AdvancedPad::output_multitap(uint8_t ticks) {
    uint8_t data_out = 0x00;

    switch (ticks) {
        case 0:  // Pad select
        case 2:  // Buffered transfer
            data_out = 0x01;
            break;

        case 1:   // Initial read command
        case 3:   // Read pad A
        case 11:  // Read pad B
        case 19:  // Read pad C
        case 27:  // Read pad D
            data_out = 0x42;
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

    return data_out;
}

void psyqo::AdvancedPad::processChanges(Pad pad) {
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

inline uint8_t psyqo::AdvancedPad::transceive(uint8_t data_out) {
    SIO::Data = data_out;

    // Wait for transceive to complete and data to populate FIFO
    while (!(SIO::Stat & SIO::Status::STAT_RXRDY))
        ;

    // Pull data from FIFO
    return SIO::Data;
}

void psyqo::AdvancedPad::readPad() {
    uint8_t data_in, data_out;
    uint8_t port_dev_type[2] = {PadType::None, PadType::None};

    syscall_memset(m_padData, 0xff, sizeof(m_padData));

    uint8_t *pad_data;
    static constexpr unsigned pad_data_width = 8;

    for (uint16_t port = 0; port < 2; port++) {
        // Select enable on current port
        SIO::Ctrl = (port << 13) | SIO::Control::CTRL_DTR;

        // Set baud 250kHz
        SIO::Baud = 0x88;

        flushRxBuffer();

        // Enable transmit and IRQ on ACK
        SIO::Ctrl |= (SIO::Control::CTRL_TXEN | SIO::Control::CTRL_ACKIRQEN);

        // Pads get finicky if we don't wait a bit here
        busyLoop(100);

        pad_data = reinterpret_cast<uint8_t *>(&m_padData[port * 4][0]);
        for (unsigned int ticks = 0, max_ticks = 5; ticks < max_ticks; ticks++) {
            SIO::Ctrl |= SIO::Control::CTRL_ERRRES;  // Clear error
            CPU::IReg.clear(CPU::IRQ::Controller);   // Clear IRQ

            if (port_dev_type[port] == PadType::Multitap) {
                data_out = output_multitap(ticks);
            } else {
                data_out = output_default(ticks);
            }
            data_in = transceive(data_out);

            if (ticks == 2) {
                if (data_in == 0x5a) {
                    // Set number of half-words to read
                    max_ticks = port_dev_type[port] & 0x0f;
                    if (!max_ticks) {
                        max_ticks = 0x10;
                    }
                    max_ticks = (max_ticks * 2) + ticks + 1;

                    pad_data[0] = 0;
                } else {
                    // Derp? Unknown device type or bad data, stop reading
                    max_ticks = ticks;
                    pad_data[0] = 0xff;
                }
            }

            if (port_dev_type[port] == PadType::Multitap) {
                unsigned pad_index = ticks >= 11 ? (ticks - 3) / 8 : 0;

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
                        pad_data[(pad_data_width * pad_index) + 0] = !(data_in == 0x5a);
                        break;

                    case 3:   // Pad A idlo
                    case 11:  // Pad B idlo
                    case 19:  // Pad C idlo
                    case 27:  // Pad D idlo
                        pad_data[(pad_data_width * pad_index) + 1] = data_in;
                        break;

                    default:
                        pad_data[(pad_data_width * pad_index) + ((ticks - 3) % 8)] = data_in;
                }
            } else {
                switch (ticks) {
                    case 0:  // Discard data
                        break;

                    case 1:
                        port_dev_type[port] = data_in;
                        if (data_in != PadType::Multitap) {
                            pad_data[1] = data_in;
                        }
                        break;

                    case 2:
                        pad_data[0] = !(data_in == 0x5a);
                        break;

                    default:
                        pad_data[ticks - 1] = data_in;
                }
            }

            if (ticks < (max_ticks - 1)) {
                if (!waitForAck()) {
                    // Timeout waiting for ACK
                    port_dev_type[port] = PadType::None;
                    for (int pad_index = 0; pad_index < 4; pad_index++) {
                        pad_data[(pad_data_width * pad_index)] = 0x01;
                    }
                    break;
                }

                while (SIO::Stat & SIO::Status::STAT_ACK)
                    ;  // Wait for ACK to return to high
            }
        }  // tick loop

        // End transmission
        SIO::Ctrl = 0;
    }  // port loop
}

inline bool psyqo::AdvancedPad::waitForAck() {
    int cyclesWaited = 0;
    static constexpr int max_ack_wait = 0x137;  // ~105us

    while (!(CPU::IReg & (static_cast<uint32_t>(CPU::IRQ::Controller))) && ++cyclesWaited < max_ack_wait)
        ;

    if (cyclesWaited >= max_ack_wait) {
        // Timeout waiting for ACK
        return false;
    }

    return true;
}