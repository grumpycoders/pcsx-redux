/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#pragma once

#include <GLFW/glfw3.h>
#include <stdint.h>

#include "core/psxemulator.h"
#include "core/system.h"
#include "imgui.h"
#include "json.hpp"

struct PadData;
using json = nlohmann::json;

namespace PCSX {
class Pads {
  public:
    enum Port { Port1, Port2 };
    enum class InputType { Auto, Controller, Keyboard };
    enum class PadType {
        Digital = 0,
        Analog,
        Negcon,
        Mouse,
        Gun,
        Guncon
    };

    Pads();
    void init();
    void shutdown() {}
    uint8_t startPoll(Port);
    uint8_t poll(uint8_t, Port);

    json getCfg();
    void setCfg(const json &j);
    void setDefaults();
    bool configure();
    bool m_showCfg = false;

    void scanGamepads();

  private:
    EventBus::Listener m_listener;
    int m_gamepadsMap[16] = {0};

    static const int GLFW_GAMEPAD_BUTTON_LEFT_TRIGGER = GLFW_GAMEPAD_BUTTON_LAST + 1;
    static const int GLFW_GAMEPAD_BUTTON_RIGHT_TRIGGER = GLFW_GAMEPAD_BUTTON_LAST + 2;
    static const int GLFW_GAMEPAD_BUTTON_INVALID = GLFW_GAMEPAD_BUTTON_LAST + 3;

    // settings block
    // Pad keyboard bindings
    typedef Setting<int, TYPESTRING("Keyboard_PadUp"), GLFW_KEY_UP> Keyboard_PadUp;
    typedef Setting<int, TYPESTRING("Keyboard_PadRight"), GLFW_KEY_RIGHT> Keyboard_PadRight;
    typedef Setting<int, TYPESTRING("Keyboard_PadDown"), GLFW_KEY_DOWN> Keyboard_PadDown;
    typedef Setting<int, TYPESTRING("Keyboard_PadLeft"), GLFW_KEY_LEFT> Keyboard_PadLeft;
    typedef Setting<int, TYPESTRING("Keyboard_PadCross"), GLFW_KEY_X> Keyboard_PadCross;
    typedef Setting<int, TYPESTRING("Keyboard_PadTriangle"), GLFW_KEY_S> Keyboard_PadTriangle;
    typedef Setting<int, TYPESTRING("Keyboard_PadSquare"), GLFW_KEY_Z> Keyboard_PadSquare;
    typedef Setting<int, TYPESTRING("Keyboard_PadCircle"), GLFW_KEY_D> Keyboard_PadCircle;
    typedef Setting<int, TYPESTRING("Keyboard_PadSelect"), GLFW_KEY_BACKSPACE> Keyboard_PadSelect;
    typedef Setting<int, TYPESTRING("Keyboard_PadSstart"), GLFW_KEY_ENTER> Keyboard_PadStart;
    typedef Setting<int, TYPESTRING("Keyboard_PadL1"), GLFW_KEY_Q> Keyboard_PadL1;
    typedef Setting<int, TYPESTRING("Keyboard_PadL2"), GLFW_KEY_A> Keyboard_PadL2;
    typedef Setting<int, TYPESTRING("Keyboard_PadR1"), GLFW_KEY_R> Keyboard_PadR1;
    typedef Setting<int, TYPESTRING("Keyboard_PadR2"), GLFW_KEY_F> Keyboard_PadR2;

    // Pad controller bindings
    typedef Setting<int, TYPESTRING("Controller_PadUp"), GLFW_GAMEPAD_BUTTON_DPAD_UP> Controller_PadUp;
    typedef Setting<int, TYPESTRING("Controller_PadRight"), GLFW_GAMEPAD_BUTTON_DPAD_RIGHT> Controller_PadRight;
    typedef Setting<int, TYPESTRING("Controller_PadDown"), GLFW_GAMEPAD_BUTTON_DPAD_DOWN> Controller_PadDown;
    typedef Setting<int, TYPESTRING("Controller_PadLeft"), GLFW_GAMEPAD_BUTTON_DPAD_LEFT> Controller_PadLeft;
    typedef Setting<int, TYPESTRING("Controller_PadCross"), GLFW_GAMEPAD_BUTTON_CROSS> Controller_PadCross;
    typedef Setting<int, TYPESTRING("Controller_PadTriangle"), GLFW_GAMEPAD_BUTTON_TRIANGLE> Controller_PadTriangle;
    typedef Setting<int, TYPESTRING("Controller_PadSquare"), GLFW_GAMEPAD_BUTTON_SQUARE> Controller_PadSquare;
    typedef Setting<int, TYPESTRING("Controller_PadCircle"), GLFW_GAMEPAD_BUTTON_CIRCLE> Controller_PadCircle;
    typedef Setting<int, TYPESTRING("Controller_PadSelect"), GLFW_GAMEPAD_BUTTON_BACK> Controller_PadSelect;
    typedef Setting<int, TYPESTRING("Controller_PadSstart"), GLFW_GAMEPAD_BUTTON_START> Controller_PadStart;
    typedef Setting<int, TYPESTRING("Controller_PadL1"), GLFW_GAMEPAD_BUTTON_LEFT_BUMPER> Controller_PadL1;
    typedef Setting<int, TYPESTRING("Controller_PadL2"), GLFW_GAMEPAD_BUTTON_LEFT_TRIGGER> Controller_PadL2;
    typedef Setting<int, TYPESTRING("Controller_PadR1"), GLFW_GAMEPAD_BUTTON_RIGHT_BUMPER> Controller_PadR1;
    typedef Setting<int, TYPESTRING("Controller_PadR2"), GLFW_GAMEPAD_BUTTON_RIGHT_TRIGGER> Controller_PadR2;

    typedef Setting<InputType, TYPESTRING("PadType"), InputType::Auto> SettingInputType;
    // These typestrings are kind of odd, but it's best not to change so as not to break old config files
    typedef Setting<PadType, TYPESTRING("DeviceType"), PadType::Digital> SettingDeviceType;
    typedef Setting<int, TYPESTRING("ID")> SettingControllerID;

    typedef Setting<bool, TYPESTRING("Connected")> SettingConnected;

    typedef Settings<Keyboard_PadUp, Keyboard_PadRight, Keyboard_PadDown, Keyboard_PadLeft, Keyboard_PadCross,
                     Keyboard_PadTriangle, Keyboard_PadSquare, Keyboard_PadCircle, Keyboard_PadSelect,
                     Keyboard_PadStart, Keyboard_PadL1, Keyboard_PadL2, Keyboard_PadR1, Keyboard_PadR2,
                     Controller_PadUp, Controller_PadRight, Controller_PadDown, Controller_PadLeft, Controller_PadCross,
                     Controller_PadTriangle, Controller_PadSquare, Controller_PadCircle, Controller_PadSelect,
                     Controller_PadStart, Controller_PadL1, Controller_PadL2, Controller_PadR1, Controller_PadR2,
                     SettingInputType, SettingDeviceType, SettingControllerID, SettingConnected>
        PadSettings;

    struct Pad {
        void readPort(PadData& pad);
        uint8_t startPoll(const PadData& pad);
        uint8_t poll(uint8_t);
        void getButtons(PadData& pad);
        bool isControllerButtonPressed(int button, GLFWgamepadstate *state);

        json getCfg();
        void setCfg(const json &j);
        void setDefaults(bool firstController);
        void map();

        bool configure();
        void keyboardEvent(const Events::Keyboard &);
        int &getButtonFromGUIIndex(int buttonIndex);

        int m_scancodes[16];
        int m_padMapping[16];
        PadType m_type;

        int m_padID = 0;
        int m_buttonToWait = -1;
        bool m_changed = false;

        PadSettings m_settings;

        uint8_t m_buf[256];
        int m_bufcount, m_bufc;

        uint8_t m_stdpar[10] = {0x00, 0x41, 0x5a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        uint8_t m_mousepar[8] = {0x00, 0x12, 0x5a, 0xff, 0xff, 0xff, 0xff};
        uint8_t m_analogpar[9] = {0x00, 0xff, 0x5a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    };

    Pad m_pads[2];
    unsigned m_selectedPadForConfig = 0;

#if 0

    void mapScancodes();           // load keyboard bindings
    void configButton(int index);  // pick the button to config

  public:
    static bool configuringButton;     // are we configuring a button in the GUI?
    static int configuredButtonIndex;  // Which button are we configuring in the GUI?
    static bool save;                  // do we need to save?

#endif
};

}  // namespace PCSX
