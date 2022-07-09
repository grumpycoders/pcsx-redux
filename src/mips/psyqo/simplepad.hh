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

/**
 * @brief A simple class to access the pads.
 *
 * @details This class is meant to be used as a singleton, probably in
 * the `Application` derived class. It is a simple thunk to the BIOS'
 * PAD interface, and has the same caveats, namely that it should be
 * initialized prior using the BIOS' memory card functions, and that
 * polling will alternate between the two pads at each frame when two
 * pads are connected, which can introduce input lags.
 */

class SimplePad {
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

    struct Event {
        enum { PadConnected, PadDisconnected, ButtonPressed, ButtonReleased } type;
        Pad pad;
        Button button;
    };

    /**
     * @brief Initializes the pads.
     *
     * @details This will initialize the pads polling by calling the BIOS'
     * interface. This means this method cannot be called from the `prepare`
     * method of the `Application` class, but rather from the `start` method
     * of the root `Scene` object. Also, there can be interference with
     * the BIOS' memory card functions, so this method is explicit to be
     * called in the right order.
     */
    void initialize();

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
    bool isPadConnected(Pad pad) const { return (m_padData[pad][0] & 0xff) == 0; }

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
    bool isButtonPressed(Pad pad, Button button) const { return (m_padData[pad][1] & (1 << button)) == 0; }

  private:
    void processChanges(Pad pad);

    uint16_t m_padData[2][0x11];
    eastl::function<void(Event)> m_callback;
    bool m_connected[2] = {false, false};
    uint16_t m_buttons[2] = {0xffff, 0xffff};
};

}  // namespace psyqo
