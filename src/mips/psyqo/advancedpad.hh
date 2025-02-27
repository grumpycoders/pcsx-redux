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

#pragma once

#include <EASTL/functional.h>
#include <stdint.h>

#include "psyqo/utility-polyfill.h"

namespace psyqo {

/**
 * @brief An advanced class to access the pads.
 *
 * @details This class is meant to be used as a singleton, probably in
 * the `Application` derived class. It does not use the BIOS'
 * PAD interface. Instead, it uses the SIO interface directly, and
 * can therefore support more device types including multitaps.
 */

class AdvancedPad {
  public:
    enum class Pad : unsigned { Pad1a, Pad1b, Pad1c, Pad1d, Pad2a, Pad2b, Pad2c, Pad2d };

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

    enum PadType : uint8_t {
        Mouse = 0x12,           // (two button mouse)
        NegCon = 0x23,          // (steering twist/wheel/paddle)
        KonamiLightgun = 0x31,  // (IRQ10-type)
        DigitalPad = 0x41,      // (or analog pad/stick in digital mode; LED=Off)
        AnalogStick = 0x53,     // (or analog pad in "flight mode"; LED=Green)
        NamcoLightGun = 0x63,   // (Cinch-type)
        AnalogPad = 0x73,       // (in normal analog mode; LED=Red)
        Multitap = 0x80,        // (multiplayer adaptor) (when activated)
        JogCon = 0xe3,          // (steering dial)
        FishingCon = 0xe5,      // (fishing rod)
        ConfigMode = 0xf3,      // (when in config mode; see rumble command 43h)
        None = 0xff             // (no controller connected, pins floating High-Z)
    };

    struct Event {
        enum { PadConnected, PadDisconnected, ButtonPressed, ButtonReleased } type;
        Pad pad;
        Button button;
    };

    /**
     * @brief Initializes the pads.
     *
     * @details This method should be called once at the beginning of
     * the program, preferably from the `Application::prepare` method.
     * The `mode` parameter can be used to indicate whether the ports
     * should be polled one at a time, or both at once. The default is
     * `PollingMode::Normal`, which will poll one port per frame. The
     * `PollingMode::Fast` mode will poll all ports at once each frame,
     * which can reduce input lag, but will also increase the CPU usage.
     *
     * @param mode The polling mode to use.
     */
    enum class PollingMode { Normal, Fast };
    void initialize(PollingMode mode = PollingMode::Normal);

    /**
     * @brief Sets the event callback function.
     *
     * @details The event callback will be called for each pad-related event,
     * such as pad connection / disconnection, or button press / release.
     * The callback will only be called between frames.
     *
     * Scenes that are calling `setOnEvent` during their `start` method should
     * call `setOnEvent` again in their `teardown` method with the `nullptr`
     * value in order to unregister the event callback cleanly.
     *
     * Only one callback can be registered at a time, so setting a new
     * callback will simply remove the previous one.
     *
     * Careful about what is called from the callback: pushing or popping scenes
     * might call into `setOnEvent` as a result, and could end up corrupting
     * memory as a result of the callback being deleted while being executed.
     */
    void setOnEvent(eastl::function<void(Event)>&& callback) { m_callback = eastl::move(callback); }

    /**
     * @brief Returns the state of a pad.
     *
     * @details Returns the state of a pad. The state is a boolean value
     * that is `true` if the pad is connected, and `false` otherwise.
     *
     * @param pad The pad to query.
     * @return A boolean value indicating whether the pad is connected.
     */
    bool isPadConnected(Pad pad) const { return m_padData[toUnderlying(pad)].connected == 0; }

    /**
     * @brief Returns the state of a button.
     *
     * @details Returns the state of a button. The state is a boolean value
     * that is `true` if the button is pressed, and `false` otherwise.
     *
     * @param pad The pad to query.
     * @param button The button to query.
     * @return A boolean value indicating whether the button is pressed.
     */
    bool isButtonPressed(Pad pad, Button button) const {
        return (m_padData[toUnderlying(pad)].buttons & (1 << button)) == 0;
    }

    /**
     * @brief Returns the state of an Analog Input.
     *
     * @details See the specific Analog Input functions for details.
     * Indices greater than 3 will return 0.
     * index 0: For analog pads: RightJoyX (00h=Left, 80h=Center, FFh=Right), mouse: X-axis
     * index 1: For analog pads: RightJoyY (00h=Up, 80h=Center, FFh=Down), mouse: Y-axis
     * index 2: For analog pads: LeftJoyX (00h=Left, 80h=Center, FFh=Right)
     * index 3: For analog pads: LeftJoyY (00h=Up, 80h=Center, FFh=Down)
     *
     * @param pad The pad to query.
     * @param index The index of the Analog Input(adc#).
     * @return The state of the Analog Input as an unsigned 8-bit value(0-255).
     */
    uint8_t getAdc(Pad pad, unsigned int index) const {
        const unsigned padIndex = toUnderlying(pad);

        return index <= 7 ? m_padData[padIndex].adc[index] : 0;
    }

    /**
     * @brief Returns raw pad data as an unsigned 16-bit value.
     *
     * @details A low level call which returns the halfword value for the requested index of the given pad index.
     * It is recommended to use the higher level functions instead.
     * index 0: pad type << 8 | connected(0 = connected, ffh = disconnected)
     * index 1: button state
     * index 2: analog input 1 << 8 | analog input 0
     * index 3: analog input 3 << 8 | analog input 2
     * The index is modulo 4, so it will wrap around if it is greater than 3.
     *
     *
     * @param pad The pad to query.
     * @param index The index of the halfword.
     * @return The value of the halfword.
     */

    uint16_t getHalfword(Pad pad, unsigned int index) const { return m_padData[toUnderlying(pad)].packed[index % 4]; }

    /**
     * @brief Returns the type of the pad.
     *
     * @details Known pad types are defined in the PadType enum, returns 0xff if no pad is connected.
     * PadType::Multitap is for internal use only, and should not be returned.
     * Pad connection status should be checked with isPadConnected.
     *
     * @param pad The pad to query.
     * @return The type of the pad.
     */
    uint8_t getPadType(Pad pad) const { return m_padData[toUnderlying(pad)].padType; }

  private:
    enum Command : uint8_t {
        PadSelect = 0x01,
        ReadPad = 0x42,  // 'B' Read Buttons AND analog inputs
        // Config mode commands
        ToggleConfigMode = 0x43,      // 'C' Enter/Exit Configuration Mode
        SetLED = 0x44,                // 'D' Set LED State (analog mode on/off)
        GetLED = 0x45,                // 'E' Get LED State (and whatever values)
        GetMotorInfo = 0x46,          // 'F' Allegedly get info about a motor
        GetMotorList = 0x47,          // 'G' Allegedly get list of motors
        GetMotorState = 0x48,         // 'H' Allegedly get motor state
        GetSupportedModes = 0x4c,     // 'L' Allegedly get supported modes
        ConfigRequestFormat = 0x4d,   // 'M' Allegedly configure poll request format
        ConfigResponseFormat = 0x4f,  // 'O' Allegedly configure poll response format
    };

    void busyLoop(unsigned delay) {
        unsigned cycles = 0;
        while (++cycles < delay) asm("");
    };

    void configurePort(uint8_t port);

    void flushRxBuffer();
    uint8_t outputDefault(unsigned ticks);
    uint8_t outputMultitap(unsigned ticks);
    void processChanges(Pad pad);
    void readPad();
    uint8_t transceive(uint8_t dataOut);
    bool waitForAck();  // true if ack received, false if timeout

    union PadData {
        struct {
            uint8_t connected;
            uint8_t padType;
            uint16_t buttons;
            uint8_t adc[8];
        };
        uint16_t packed[6];
    };

    PadData m_padData[8];
    eastl::function<void(Event)> m_callback;
    bool m_connected[8] = {false, false, false, false, false, false, false, false};
    uint16_t m_buttons[8] = {
        0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    };
    uint8_t m_portToProbe = 0;
    uint8_t m_portsToProbeByVSync = 0;
};

// prefix increment operator
inline psyqo::AdvancedPad::Pad& operator++(psyqo::AdvancedPad::Pad& pad) {
    return pad = static_cast<psyqo::AdvancedPad::Pad>((toUnderlying(pad) + 1) & 7);
}

// postfix increment operator
inline psyqo::AdvancedPad::Pad operator++(psyqo::AdvancedPad::Pad& pad, int) {
    psyqo::AdvancedPad::Pad copy(pad);
    pad = static_cast<psyqo::AdvancedPad::Pad>((toUnderlying(pad) + 1) & 7);
    return copy;
}

// prefix decrement operator
inline psyqo::AdvancedPad::Pad& operator--(psyqo::AdvancedPad::Pad& pad) {
    return pad = static_cast<psyqo::AdvancedPad::Pad>((toUnderlying(pad) - 1) & 7);
}

// postfix decrement operator
inline psyqo::AdvancedPad::Pad operator--(psyqo::AdvancedPad::Pad& pad, int) {
    psyqo::AdvancedPad::Pad copy(pad);
    pad = static_cast<psyqo::AdvancedPad::Pad>((toUnderlying(pad) - 1) & 7);
    return copy;
}

}  // namespace psyqo
