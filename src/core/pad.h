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

#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>

#include <array>
#include <cstdint>

#include "core/psxemulator.h"
#include "core/system.h"
#include "imgui.h"
#include "json.hpp"

struct PadData;
using json = nlohmann::json;

namespace PCSX {

class GUI;

enum {
    PAD_STATE_IDLE = 0,
    PAD_STATE_READ_COMMAND = 1,
    PAD_STATE_READ_DATA = 2,
};

class Pads {
  public:
    enum class Port { Port1 = 0, Port2 };
    enum class InputType { Auto, Controller, Keyboard };
    enum class PadType { Digital = 0, Analog, Mouse, Negcon, Gun, Guncon };

    Pads();
    void init();
    void shutdown() {}
    uint8_t startPoll(Port port);
    uint8_t poll(uint8_t value, Port port, uint32_t &padState);

    json getCfg();
    void setCfg(const json &j);
    void setDefaults();
    bool configure(GUI *gui);
    bool m_showCfg = false;

    void scanGamepads();
    void reset();

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
    typedef Setting<int, TYPESTRING("Keyboard_PadL3"), GLFW_KEY_W> Keyboard_PadL3;
    typedef Setting<int, TYPESTRING("Keyboard_PadR1"), GLFW_KEY_R> Keyboard_PadR1;
    typedef Setting<int, TYPESTRING("Keyboard_PadR2"), GLFW_KEY_F> Keyboard_PadR2;
    typedef Setting<int, TYPESTRING("Keyboard_PadR3"), GLFW_KEY_T> Keyboard_PadR3;
    typedef Setting<int, TYPESTRING("Keyboard_AnalogMode"), GLFW_KEY_UNKNOWN> Keyboard_AnalogMode;

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
    typedef Setting<int, TYPESTRING("Controller_PadL3"), GLFW_GAMEPAD_BUTTON_LEFT_THUMB> Controller_PadL3;
    typedef Setting<int, TYPESTRING("Controller_PadR1"), GLFW_GAMEPAD_BUTTON_RIGHT_BUMPER> Controller_PadR1;
    typedef Setting<int, TYPESTRING("Controller_PadR2"), GLFW_GAMEPAD_BUTTON_RIGHT_TRIGGER> Controller_PadR2;
    typedef Setting<int, TYPESTRING("Controller_PadR3"), GLFW_GAMEPAD_BUTTON_RIGHT_THUMB> Controller_PadR3;

    typedef Setting<InputType, TYPESTRING("PadType"), InputType::Auto> SettingInputType;
    // These typestrings are kind of odd, but it's best not to change so as not to break old config files
    typedef Setting<PadType, TYPESTRING("DeviceType"), PadType::Digital> SettingDeviceType;
    typedef Setting<int, TYPESTRING("ID")> SettingControllerID;

    typedef Setting<bool, TYPESTRING("Connected")> SettingConnected;
    // Default sensitivity = 5/10 = 0.5
    typedef SettingFloat<TYPESTRING("MouseSensitivityX"), 5, 10> SettingMouseSensitivityX;
    typedef SettingFloat<TYPESTRING("MouseSensitivityY"), 5, 10> SettingMouseSensitivityY;

    typedef Settings<
        Keyboard_PadUp, Keyboard_PadRight, Keyboard_PadDown, Keyboard_PadLeft, Keyboard_PadCross, Keyboard_PadTriangle,
        Keyboard_PadSquare, Keyboard_PadCircle, Keyboard_PadSelect, Keyboard_PadStart, Keyboard_PadL1, Keyboard_PadL2,
        Keyboard_PadL3, Keyboard_PadR1, Keyboard_PadR2, Keyboard_PadR3, Keyboard_AnalogMode, Controller_PadUp,
        Controller_PadRight, Controller_PadDown, Controller_PadLeft, Controller_PadCross, Controller_PadTriangle,
        Controller_PadSquare, Controller_PadCircle, Controller_PadSelect, Controller_PadStart, Controller_PadL1,
        Controller_PadL2, Controller_PadL3, Controller_PadR1, Controller_PadR2, Controller_PadR3, SettingInputType,
        SettingDeviceType, SettingControllerID, SettingConnected, SettingMouseSensitivityX, SettingMouseSensitivityY>
        PadSettings;

    struct PadData {
        // status of buttons - every controller fills this field
        uint16_t buttonStatus;

        // Analog stick values in range (0 - 255) where 128 = center
        uint8_t rightJoyX, rightJoyY, leftJoyX, leftJoyY;
    };

    enum class PadCommands : uint8_t {
        Idle = 0x00,
        Read = 0x42,
        SetConfigMode = 0x43,
        SetAnalogMode = 0x44,
        GetAnalogMode = 0x45,
        Unknown46 = 0x46,
        Unknown47 = 0x47,
        Unknown4C = 0x4C,
        UnlockRumble = 0x4D
    };

    struct Pad {
        uint8_t startPoll();
        uint8_t read();
        uint8_t poll(uint8_t value, uint32_t &padState);
        uint8_t doDualshockCommand(uint32_t &padState);
        void getButtons();
        bool isControllerButtonPressed(int button, GLFWgamepadstate *state);

        json getCfg();
        void setCfg(const json &j);
        void setDefaults(bool firstController);
        void map();
        void reset();

        bool configure();
        void keyboardEvent(const Events::Keyboard &);
        int &getButtonFromGUIIndex(int buttonIndex);

        int m_scancodes[16];
        int m_padMapping[16];
        PadType m_type;
        PadData m_data;

        int m_padID = 0;
        int m_buttonToWait = -1;
        bool m_changed = false;

        bool m_configMode = false;
        bool m_analogMode = false;

        PadSettings m_settings;

        uint8_t m_buf[256];
        int m_bufferLen = 0, m_currentByte = 0;
        uint8_t m_cmd = magic_enum::enum_integer(PadCommands::Idle);

        uint8_t m_stdpar[8] = {0x41, 0x5a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        uint8_t m_mousepar[6] = {0x12, 0x5a, 0xff, 0xff, 0xff, 0xff};
        uint8_t m_analogpar[8] = {0x73, 0x5a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    };

    std::array<Pad, 2> m_pads;
    unsigned m_selectedPadForConfig = 0;
};

}  // namespace PCSX
