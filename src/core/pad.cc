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

#define _USE_MATH_DEFINES
#include "core/pad.h"

#include <memory.h>

#include <algorithm>
#include <cmath>

#include "core/system.h"
#include "fmt/format.h"
#include "gui/gui.h"
#include "imgui.h"
#include "magic_enum/include/magic_enum.hpp"
#include "support/file.h"

static PCSX::Pads* s_pads = nullptr;

void PCSX::Pads::init() {
    scanGamepads();
    s_pads = this;
    glfwSetJoystickCallback([](int jid, int event) {
        s_pads->scanGamepads();
        s_pads->map();
    });
    g_system->findResource(
        [](const std::filesystem::path& filename) -> bool {
            IO<File> database(new PosixFile(filename));
            if (database->failed()) {
                return false;
            }

            size_t dbsize = database->size();
            auto dbStr = database->readString(dbsize);

            int ret = glfwUpdateGamepadMappings(dbStr.c_str());

            return ret;
        },
        "gamecontrollerdb.txt", "resources", std::filesystem::path("third_party") / "SDL_GameControllerDB");
    reset();
    map();
}

void PCSX::Pads::shutdown() {
    glfwSetJoystickCallback(nullptr);
    s_pads = nullptr;
}

PCSX::Pads::Pads() : m_listener(g_system->m_eventBus) {
    m_listener.listen<Events::Keyboard>([this](const auto& event) {
        if (m_showCfg) {
            m_pads[m_selectedPadForConfig].keyboardEvent(event);
        }
    });
}

void PCSX::Pads::scanGamepads() {
    static_assert((1 + GLFW_JOYSTICK_LAST - GLFW_JOYSTICK_1) <= sizeof(m_gamepadsMap) / sizeof(m_gamepadsMap[0]));
    for (auto& m : m_gamepadsMap) {
        m = -1;
    }
    unsigned index = 0;
    for (int i = GLFW_JOYSTICK_1; i < GLFW_JOYSTICK_LAST; i++) {
        if (glfwJoystickPresent(i) && glfwJoystickIsGamepad(i)) {
            m_gamepadsMap[index++] = i;
        }
    }
}

void PCSX::Pads::reset() {
    m_pads[0].reset();
    m_pads[1].reset();
}

void PCSX::Pads::Pad::reset() {
    m_analogMode = false;
    m_configMode = false;
    m_cmd = magic_enum::enum_integer(PadCommands::Idle);
    m_bufferLen = 0;
    m_currentByte = 0;
    m_data.buttonStatus = 0xffff;
    m_data.overrides = 0xffff;
}

void PCSX::Pads::map() {
    m_pads[0].map();
    m_pads[1].map();
}

void PCSX::Pads::Pad::map() {
    m_padID = g_emulator->m_pads->m_gamepadsMap[m_settings.get<SettingControllerID>()];
    m_type = m_settings.get<SettingDeviceType>();

    // L3/R3 are only avalable on analog controllers
    if (m_type == PadType::Analog) {
        m_scancodes[1] = m_settings.get<Keyboard_PadL3>();     // L3
        m_scancodes[2] = m_settings.get<Keyboard_PadR3>();     // R3
        m_padMapping[1] = m_settings.get<Controller_PadL3>();  // L3
        m_padMapping[2] = m_settings.get<Controller_PadR3>();  // R3
    } else {
        m_scancodes[1] = 255;
        m_scancodes[2] = 255;
        m_padMapping[1] = GLFW_GAMEPAD_BUTTON_INVALID;
        m_padMapping[2] = GLFW_GAMEPAD_BUTTON_INVALID;
    }

    // keyboard mappings
    m_scancodes[0] = m_settings.get<Keyboard_PadSelect>();     // SELECT
    m_scancodes[3] = m_settings.get<Keyboard_PadStart>();      // START
    m_scancodes[4] = m_settings.get<Keyboard_PadUp>();         // UP
    m_scancodes[5] = m_settings.get<Keyboard_PadRight>();      // RIGHT
    m_scancodes[6] = m_settings.get<Keyboard_PadDown>();       // DOWN
    m_scancodes[7] = m_settings.get<Keyboard_PadLeft>();       // LEFT
    m_scancodes[8] = m_settings.get<Keyboard_PadL2>();         // L2
    m_scancodes[9] = m_settings.get<Keyboard_PadR2>();         // R2
    m_scancodes[10] = m_settings.get<Keyboard_PadL1>();        // L1
    m_scancodes[11] = m_settings.get<Keyboard_PadR1>();        // R1
    m_scancodes[12] = m_settings.get<Keyboard_PadTriangle>();  // TRIANGLE
    m_scancodes[13] = m_settings.get<Keyboard_PadCircle>();    // CIRCLE
    m_scancodes[14] = m_settings.get<Keyboard_PadCross>();     // CROSS
    m_scancodes[15] = m_settings.get<Keyboard_PadSquare>();    // SQUARE

    // gamepad mappings
    m_padMapping[0] = m_settings.get<Controller_PadSelect>();     // SELECT
    m_padMapping[3] = m_settings.get<Controller_PadStart>();      // START
    m_padMapping[4] = m_settings.get<Controller_PadUp>();         // UP
    m_padMapping[5] = m_settings.get<Controller_PadRight>();      // RIGHT
    m_padMapping[6] = m_settings.get<Controller_PadDown>();       // DOWN
    m_padMapping[7] = m_settings.get<Controller_PadLeft>();       // LEFT
    m_padMapping[8] = m_settings.get<Controller_PadL2>();         // L2
    m_padMapping[9] = m_settings.get<Controller_PadR2>();         // R2
    m_padMapping[10] = m_settings.get<Controller_PadL1>();        // L1
    m_padMapping[11] = m_settings.get<Controller_PadR1>();        // R1
    m_padMapping[12] = m_settings.get<Controller_PadTriangle>();  // TRIANGLE
    m_padMapping[13] = m_settings.get<Controller_PadCircle>();    // CIRCLE
    m_padMapping[14] = m_settings.get<Controller_PadCross>();     // CROSS
    m_padMapping[15] = m_settings.get<Controller_PadSquare>();    // SQUARE
}

static constexpr float THRESHOLD = 0.85f;

// Certain buttons on controllers are actually axis that can be pressed, half-pressed, etc.
bool PCSX::Pads::Pad::isControllerButtonPressed(int button, GLFWgamepadstate* state) {
    int mapped = m_padMapping[button];
    switch (mapped) {
        case GLFW_GAMEPAD_BUTTON_LEFT_TRIGGER:
            return state->axes[GLFW_GAMEPAD_AXIS_LEFT_TRIGGER] >= THRESHOLD;
        case GLFW_GAMEPAD_BUTTON_RIGHT_TRIGGER:
            return state->axes[GLFW_GAMEPAD_AXIS_RIGHT_TRIGGER] >= THRESHOLD;
        case GLFW_GAMEPAD_BUTTON_INVALID:
            return false;
        default:
            return state->buttons[mapped];
    }
}

static constexpr float π(float fraction = 1.0f) { return fraction * M_PI; }

void PCSX::Pads::Pad::getButtons() {
    PadData& pad = m_data;
    if (!m_settings.get<SettingConnected>()) {
        pad.buttonStatus = 0xffff;
        pad.leftJoyX = pad.rightJoyX = pad.leftJoyY = pad.rightJoyY = 0x80;
        return;
    }

    GLFWgamepadstate state;
    int hasPad = GLFW_FALSE;
    const auto& inputType = m_settings.get<SettingInputType>();

    auto getKeyboardButtons = [this]() -> uint16_t {
        const bool* keys = ImGui::GetIO().KeysDown;
        uint16_t result = 0;
        for (unsigned i = 0; i < 16; i++) result |= (keys[m_scancodes[i]]) << i;
        return result ^ 0xffff;  // Controls are inverted, so 0 = pressed
    };

    if (inputType == InputType::Keyboard) {
        pad.buttonStatus = getKeyboardButtons();
        pad.leftJoyX = pad.rightJoyX = pad.leftJoyY = pad.rightJoyY = 0x80;
        return;
    }

    if (m_padID >= 0) {
        int glfwID = g_emulator->m_pads->m_gamepadsMap[m_padID];
        if ((glfwID >= GLFW_JOYSTICK_1) && (glfwID <= GLFW_JOYSTICK_LAST)) {
            hasPad = glfwGetGamepadState(glfwID, &state);
            if (!hasPad) {
                const char* guid = glfwGetJoystickGUID(glfwID);
                g_system->printf("Gamepad error: GUID %s likely has no database mapping, disabling pad\n", guid);
                m_padID = -1;
            }
        }
    }

    if (!hasPad) {
        if (inputType == InputType::Auto) {
            pad.buttonStatus = getKeyboardButtons();
        } else {
            pad.buttonStatus = 0xffff;
        }

        pad.leftJoyX = pad.rightJoyX = pad.leftJoyY = pad.rightJoyY = 0x80;
        return;
    }

    bool buttons[16];
    for (unsigned i = 0; i < 16; i++) {
        buttons[i] = isControllerButtonPressed(i, &state);
    }

    // For digital gamepads, make the PS1 dpad controllable with our gamepad's left analog stick
    if (m_type == PadType::Digital) {
        float x = state.axes[GLFW_GAMEPAD_AXIS_LEFT_X];
        float y = -state.axes[GLFW_GAMEPAD_AXIS_LEFT_Y];
        float ds = x * x + y * y;
        if (ds >= THRESHOLD * THRESHOLD) {
            float d = std::sqrt(ds);
            x /= d;
            y /= d;
            float a = 0;
            if ((x * x) > (y * y)) {
                a = std::acos(x);
                if (y < 0) a = π(2.0f) - a;
            } else {
                a = std::asin(y);
                if (x < 0) {
                    a = π() - a;
                } else if (y < 0) {
                    a = π(2.0f) + a;
                }
            }
            if ((a < π(2.5f / 8.0f)) || (a >= π(13.5f / 8.0f))) {
                // right
                buttons[5] = true;
            }
            if ((π(1.5f / 8.0f) <= a) && (a < π(6.5f / 8.0f))) {
                // up
                buttons[4] = true;
            }
            if ((π(5.5f / 8.0f) <= a) && (a < π(10.5f / 8.0f))) {
                // left
                buttons[7] = true;
            }
            if ((π(9.5f / 8.0f) <= a) && (a < π(14.5f / 8.0f))) {
                // down
                buttons[6] = true;
            }
        }
    } else if (m_type == PadType::Analog) {
        // Normalize an axis from (-1, 1) to (0, 255) with 128 = center
        const auto axisToUint8 = [](float axis) {
            constexpr float scale = 1.3f;
            const float scaledValue = std::clamp<float>(axis * scale, -1.0f, 1.0f);
            return (uint8_t)(std::clamp<float>(std::round(((scaledValue + 1.0f) / 2.0f) * 255.0f), 0.0f, 255.0f));
        };
        pad.leftJoyX = axisToUint8(state.axes[GLFW_GAMEPAD_AXIS_LEFT_X]);
        pad.leftJoyY = axisToUint8(state.axes[GLFW_GAMEPAD_AXIS_LEFT_Y]);
        pad.rightJoyX = axisToUint8(state.axes[GLFW_GAMEPAD_AXIS_RIGHT_X]);
        pad.rightJoyY = axisToUint8(state.axes[GLFW_GAMEPAD_AXIS_RIGHT_Y]);
    }

    uint16_t result = 0;
    for (unsigned i = 0; i < 16; i++) result |= buttons[i] << i;

    pad.buttonStatus = result ^ 0xffff;  // Controls are inverted, so 0 = pressed
}

uint8_t PCSX::Pads::startPoll(Port port) {
    int index = magic_enum::enum_integer(port);
    m_pads[index].getButtons();
    return m_pads[index].startPoll();
}

uint8_t PCSX::Pads::poll(uint8_t value, Port port, uint32_t& padState) {
    int index = magic_enum::enum_integer(port);
    return m_pads[index].poll(value, padState);
}

uint8_t PCSX::Pads::Pad::poll(uint8_t value, uint32_t& padState) {
    if (m_currentByte == 0) {
        m_cmd = value;
        m_currentByte = 1;

        if (m_cmd == magic_enum::enum_integer(PadCommands::Read)) {
            return read();
        } else if (m_type == PadType::Analog) {
            return doDualshockCommand(padState);
        } else {
            PCSX::g_system->log(PCSX::LogClass::SIO0, _("Unknown command for pad: %02X\n"), value);
            m_cmd = magic_enum::enum_integer(PadCommands::Idle);
            m_bufferLen = 0;
            padState = PAD_STATE_IDLE;  // Tell the SIO class we're in an invalid state
            return 0xff;
        }
    } else if (m_currentByte >= m_bufferLen) {
        return 0xff;
    } else if (m_currentByte == 2 && m_type == PadType::Analog) {
        switch (m_cmd) {
            case magic_enum::enum_integer(PadCommands::SetConfigMode):
                m_configMode = value == 1;
                break;
            case magic_enum::enum_integer(PadCommands::SetAnalogMode):
                m_analogMode = value == 1;
                break;
            case magic_enum::enum_integer(PadCommands::Unknown46):
                if (value == 0) {
                    m_buf[4] = 0x01;
                    m_buf[5] = 0x02;
                    m_buf[6] = 0x00;
                    m_buf[7] = 0x0A;
                } else if (value == 1) {
                    m_buf[4] = 0x01;
                    m_buf[5] = 0x01;
                    m_buf[6] = 0x01;
                    m_buf[7] = 0x14;
                }
                break;
            case magic_enum::enum_integer(PadCommands::Unknown47):
                if (value != 0) {
                    m_buf[4] = 0;
                    m_buf[5] = 0;
                    m_buf[6] = 0;
                    m_buf[7] = 0;
                }
                break;
            case magic_enum::enum_integer(PadCommands::Unknown4C):
                if (value == 0) {
                    m_buf[5] = 0x04;
                } else if (value == 1) {
                    m_buf[5] = 0x07;
                }
                break;
        }
    }

    return m_buf[m_currentByte++];
}

uint8_t PCSX::Pads::Pad::doDualshockCommand(uint32_t& padState) {
    m_bufferLen = 8;

    if (m_cmd == magic_enum::enum_integer(PadCommands::SetConfigMode)) {
        if (m_configMode) {  // The config mode version of this command does not reply with pad data
            static const uint8_t reply[] = {0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            std::memcpy(m_buf, reply, 8);
            return 0xf3;
        } else {
            return read();
        }
    } else if (m_cmd == magic_enum::enum_integer(PadCommands::GetAnalogMode) && m_configMode) {
        static uint8_t reply[] = {0x00, 0x5a, 0x01, 0x02, 0x00, 0x02, 0x01, 0x00};

        reply[4] = m_analogMode ? 1 : 0;
        std::memcpy(m_buf, reply, 8);
        return 0xf3;
    } else if (m_cmd == magic_enum::enum_integer(PadCommands::UnlockRumble) && m_configMode) {
        static uint8_t reply[] = {0x00, 0x5a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

        std::memcpy(m_buf, reply, 8);
        return 0xf3;
    } else if (m_cmd == magic_enum::enum_integer(PadCommands::SetAnalogMode) && m_configMode) {
        static uint8_t reply[] = {0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        std::memcpy(m_buf, reply, 8);
        return 0xf3;
    } else if (m_cmd == magic_enum::enum_integer(PadCommands::Unknown46) && m_configMode) {
        static uint8_t reply[] = {0x00, 0x5a, 0x00, 0x00, 0x01, 0x02, 0x00, 0x0a};

        std::memcpy(m_buf, reply, 8);
        return 0xf3;
    } else if (m_cmd == magic_enum::enum_integer(PadCommands::Unknown47) && m_configMode) {
        static uint8_t reply[] = {0x00, 0x5a, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00};

        std::memcpy(m_buf, reply, 8);
        return 0xf3;
    } else if (m_cmd == magic_enum::enum_integer(PadCommands::Unknown4C) && m_configMode) {
        static uint8_t reply[] = {0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        std::memcpy(m_buf, reply, 8);
        return 0xf3;
    } else {
        PCSX::g_system->log(PCSX::LogClass::SIO0, _("Unknown command for pad: %02X\n"), static_cast<uint8_t>(m_cmd));
        m_cmd = magic_enum::enum_integer(PadCommands::Idle);
        m_bufferLen = 0;
        padState = PAD_STATE_IDLE;  // Tell the SIO class we're in an invalid state
        return 0xff;
    }
}

uint8_t PCSX::Pads::Pad::startPoll() {
    m_currentByte = 0;
    return 0xff;
}

uint8_t PCSX::Pads::Pad::read() {
    const PadData& pad = m_data;
    uint16_t buttonStatus = pad.buttonStatus & pad.overrides;
    if (!m_settings.get<SettingConnected>()) {
        m_bufferLen = 0;
        return 0xff;
    }

    switch (m_type) {
        case PadType::Mouse: {
            const int leftClick = ImGui::IsMouseDown(ImGuiMouseButton_Left) ? 0 : 1;
            const int rightClick = ImGui::IsMouseDown(ImGuiMouseButton_Right) ? 0 : 1;
            const auto& io = ImGui::GetIO();
            const float scaleX = m_settings.get<SettingMouseSensitivityX>();
            const float scaleY = m_settings.get<SettingMouseSensitivityY>();

            const float deltaX = io.MouseDelta.x * scaleX;
            const float deltaY = io.MouseDelta.y * scaleY;

            // The top 4 bits are always set to 1, the low 2 bits seem to always be set to 0.
            // Left/right click are inverted in the response byte, ie 0 = pressed
            m_mousepar[3] = 0xf0 | (leftClick << 3) | (rightClick << 2);
            m_mousepar[4] = (int8_t)std::clamp<float>(deltaX, -128.f, 127.f);
            m_mousepar[5] = (int8_t)std::clamp<float>(deltaY, -128.f, 127.f);

            memcpy(m_buf, m_mousepar, 6);
            m_bufferLen = 6;
            return 0x12;
            break;
        }

        case PadType::Negcon:  // npc101/npc104(slph00001/slph00069)
            m_analogpar[0] = 0x23;
            m_analogpar[2] = buttonStatus & 0xff;
            m_analogpar[3] = buttonStatus >> 8;
            m_analogpar[4] = pad.rightJoyX;
            m_analogpar[5] = pad.rightJoyY;
            m_analogpar[6] = pad.leftJoyX;
            m_analogpar[7] = pad.leftJoyY;

            memcpy(m_buf, m_analogpar, 8);
            m_bufferLen = 8;
            return 0x23;
            break;
        case PadType::Analog:  // scph1110, scph1150
            if (m_analogMode || m_configMode) {
                m_analogpar[0] = 0x73;
                m_analogpar[2] = buttonStatus & 0xff;
                m_analogpar[3] = buttonStatus >> 8;
                m_analogpar[4] = pad.rightJoyX;
                m_analogpar[5] = pad.rightJoyY;
                m_analogpar[6] = pad.leftJoyX;
                m_analogpar[7] = pad.leftJoyY;

                memcpy(m_buf, m_analogpar, 8);
                m_bufferLen = 8;
                return m_configMode ? 0xf3 : 0x73;
            }
            [[fallthrough]];
        case PadType::Digital:
        default:
            m_stdpar[2] = buttonStatus & 0xff;
            m_stdpar[3] = buttonStatus >> 8;

            memcpy(m_buf, m_stdpar, 4);
            m_bufferLen = 4;
            return 0x41;
    }
}

bool PCSX::Pads::configure(PCSX::GUI* gui) {
    // Check for analog mode toggle key
    const bool* keys = ImGui::GetIO().KeysDown;
    for (auto& pad : m_pads) {
        if (pad.m_type == PadType::Analog && pad.m_settings.get<Keyboard_AnalogMode>() != GLFW_KEY_UNKNOWN) {
            const int key = pad.m_settings.get<Keyboard_AnalogMode>();

            if (keys[key]) {
                pad.m_analogMode = !pad.m_analogMode;
            }
        }
    }

    if (!m_showCfg) {
        return false;
    }

    ImGui::SetNextWindowPos(ImVec2(70, 90), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(350, 500), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(_("Pad configuration"), &m_showCfg)) {
        ImGui::End();
        return false;
    }

    static std::function<const char*()> const c_padNames[] = {
        []() { return _("Pad 1"); },
        []() { return _("Pad 2"); },
    };

    if (ImGui::Button(_("Rescan gamepads and re-read game controllers database"))) {
        shutdown();
        init();
    }

    bool changed = false;
    changed |= ImGui::Checkbox(_("Use raw input for mouse"), &gui->isRawMouseMotionEnabled());

    if (ImGui::BeginCombo(_("Pad"), c_padNames[m_selectedPadForConfig]())) {
        for (unsigned i = 0; i < 2; i++) {
            if (ImGui::Selectable(c_padNames[i](), m_selectedPadForConfig == i)) {
                m_selectedPadForConfig = i;
            }
        }
        ImGui::EndCombo();
    }

    if (ImGui::Button(_("Set defaults"))) {
        changed = true;
        m_pads[m_selectedPadForConfig].setDefaults(m_selectedPadForConfig == 0);
    }

    changed |= m_pads[m_selectedPadForConfig].configure();
    ImGui::End();
    return changed;
}

// GLFW doesn't support converting some of the most common keys to strings
static std::string glfwKeyToString(int key) {
    // define strings for some common keys that are not supported by glfwGetKeyName
    switch (key) {
        case GLFW_KEY_UP:
            return _("Keyboard Up");
        case GLFW_KEY_RIGHT:
            return _("Keyboard Right");
        case GLFW_KEY_DOWN:
            return _("Keyboard Down");
        case GLFW_KEY_LEFT:
            return _("Keyboard Left");
        case GLFW_KEY_BACKSPACE:
            return _("Keyboard Backspace");
        case GLFW_KEY_ENTER:
            return _("Keyboard Enter");
        case GLFW_KEY_SPACE:
            return _("Keyboard Space");
        case GLFW_KEY_ESCAPE:
            return _("Keyboard Escape");
        case GLFW_KEY_UNKNOWN:
            return _("Unbound");
    };

    auto keyName = glfwGetKeyName(key, 0);
    if (keyName == nullptr) {
        return fmt::format(f_("Unknown keyboard key {}"), key);
    }

    auto str = std::string(keyName);
    str[0] = toupper(str[0]);
    return fmt::format("Keyboard {}", str);
}

void PCSX::Pads::Pad::keyboardEvent(const Events::Keyboard& event) {
    if (m_buttonToWait == -1) {
        return;
    }
    getButtonFromGUIIndex(m_buttonToWait) = event.key;
    m_buttonToWait = -1;
    m_changed = true;
    map();
}

bool PCSX::Pads::Pad::configure() {
    static std::function<const char*()> const c_inputDevices[] = {
        []() { return _("Auto"); }, []() { return _("Controller"); }, []() { return _("Keyboard"); }};
    static std::function<const char*()> const c_buttonNames[] = {
        []() { return _("Cross"); },      []() { return _("Square"); }, []() { return _("Triangle"); },
        []() { return _("Circle"); },     []() { return _("Select"); }, []() { return _("Start"); },
        []() { return _("L1"); },         []() { return _("R1"); },     []() { return _("L2"); },
        []() { return _("R2"); },         []() { return _("L3"); },     []() { return _("R3"); },
        []() { return _("Analog Mode"); }};
    static std::function<const char*()> const c_dpadDirections[] = {
        []() { return _("Up"); }, []() { return _("Right"); }, []() { return _("Down"); }, []() { return _("Left"); }};
    static std::function<const char*()> const c_controllerTypes[] = {[]() { return _("Digital"); },
                                                                     []() { return _("Analog"); },
                                                                     []() { return _("Mouse"); },
                                                                     []() { return _("Negcon (Unimplemented)"); },
                                                                     []() { return _("Gun (Unimplemented)"); },
                                                                     []() { return _("Guncon (Unimplemented"); }};

    bool changed = false;
    if (ImGui::Checkbox(_("Connected"), &m_settings.get<SettingConnected>().value)) {
        changed = true;
        reset();  // Reset pad state when unplugging/replugging pad
    }

    if (m_type != PadType::Analog) {
        ImGui::BeginDisabled();
    }

    ImGui::Checkbox("Analog mode", &m_analogMode);

    if (m_type != PadType::Analog) {
        ImGui::EndDisabled();
    }

    {
        const char* currentType = c_controllerTypes[static_cast<int>(m_type)]();
        if (ImGui::BeginCombo(_("Controller Type"), currentType)) {
            for (int i = 0; i < 3; i++) {
                if (ImGui::Selectable(c_controllerTypes[i]())) {
                    changed = true;
                    m_type = static_cast<PadType>(i);
                    m_settings.get<SettingDeviceType>().value = m_type;
                    reset();  // Reset pad state when changing pad type
                    map();
                }
            }
            ImGui::EndCombo();
        }
    }

    auto& inputDevice = m_settings.get<SettingInputType>().value;

    if (ImGui::BeginCombo(_("Device type"), c_inputDevices[magic_enum::enum_integer<InputType>(inputDevice)]())) {
        for (auto i : magic_enum::enum_values<InputType>()) {
            if (ImGui::Selectable(c_inputDevices[magic_enum::enum_integer<InputType>(i)](), i == inputDevice)) {
                changed = true;
                inputDevice = i;
            }
        }

        ImGui::EndCombo();
    }
    changed |= ImGui::SliderFloat("Mouse sensitivity X", &m_settings.get<SettingMouseSensitivityX>().value, 0.f, 10.f);
    changed |= ImGui::SliderFloat("Mouse sensitivity Y", &m_settings.get<SettingMouseSensitivityY>().value, 0.f, 10.f);

    ImGui::TextUnformatted(_("Keyboard mapping"));
    if (ImGui::BeginTable("Mapping", 2, ImGuiTableFlags_SizingFixedSame | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn(_("Computer button mapping"));
        ImGui::TableSetupColumn(_("Gamepad button"));
        ImGui::TableHeadersRow();
        for (auto i = 0; i < 13; i++) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(c_buttonNames[i]());
            ImGui::TableSetColumnIndex(0);
            bool hasToPop = false;
            if (m_buttonToWait == i) {
                const ImVec4 highlight = ImGui::GetStyle().Colors[ImGuiCol_TextDisabled];
                ImGui::PushStyleColor(ImGuiCol_Button, highlight);
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, highlight);
                hasToPop = true;
            }

            // The name of the mapped key
            const auto keyName = fmt::format("{}##{}", glfwKeyToString(getButtonFromGUIIndex(i)), i);
            if (ImGui::Button(keyName.c_str(), ImVec2{-1, 0})) {
                m_buttonToWait = i;
            }
            if (hasToPop) {
                ImGui::PopStyleColor(2);
            }
        }
        for (auto i = 0; i < 4; i++) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(c_dpadDirections[i]());
            ImGui::TableSetColumnIndex(0);
            bool hasToPop = false;
            const auto absI = i + 13;
            if (m_buttonToWait == absI) {
                const ImVec4 highlight = ImGui::GetStyle().Colors[ImGuiCol_TextDisabled];
                ImGui::PushStyleColor(ImGuiCol_Button, highlight);
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, highlight);
                hasToPop = true;
            }

            // The name of the mapped key
            const auto keyName = fmt::format("{}##{}", glfwKeyToString(getButtonFromGUIIndex(absI)), absI);
            if (ImGui::Button(keyName.c_str(), ImVec2{-1, 0})) {
                m_buttonToWait = absI;
            }
            if (hasToPop) {
                ImGui::PopStyleColor(2);
            }
        }
        ImGui::EndTable();
    }

    const char* preview = _("No gamepad selected or connected");
    auto& id = m_settings.get<SettingControllerID>().value;
    int glfwjid = id >= 0 ? g_emulator->m_pads->m_gamepadsMap[id] : -1;

    std::vector<const char*> gamepadsNames;

    for (auto& m : g_emulator->m_pads->m_gamepadsMap) {
        if (m == -1) {
            continue;
        }
        const char* name = glfwGetGamepadName(m);
        gamepadsNames.push_back(name);
        if (m == glfwjid) {
            preview = name;
        }
    }

    if (ImGui::BeginCombo(_("Gamepad"), preview)) {
        for (int i = 0; i < gamepadsNames.size(); i++) {
            const auto gamepadName = fmt::format("{}##{}", gamepadsNames[i], i);
            if (ImGui::Selectable(gamepadName.c_str())) {
                changed = true;
                id = i;
                map();
            }
        }

        ImGui::EndCombo();
    }

    if (m_changed) {
        changed = true;
        m_changed = false;
    }

    return changed;
}

int& PCSX::Pads::Pad::getButtonFromGUIIndex(int buttonIndex) {
    switch (buttonIndex) {
        case 0:
            return m_settings.get<Keyboard_PadCross>().value;
        case 1:
            return m_settings.get<Keyboard_PadSquare>().value;
        case 2:
            return m_settings.get<Keyboard_PadTriangle>().value;
        case 3:
            return m_settings.get<Keyboard_PadCircle>().value;
        case 4:
            return m_settings.get<Keyboard_PadSelect>().value;
        case 5:
            return m_settings.get<Keyboard_PadStart>().value;
        case 6:
            return m_settings.get<Keyboard_PadL1>().value;
        case 7:
            return m_settings.get<Keyboard_PadR1>().value;
        case 8:
            return m_settings.get<Keyboard_PadL2>().value;
        case 9:
            return m_settings.get<Keyboard_PadR2>().value;
        case 10:
            return m_settings.get<Keyboard_PadL3>().value;
        case 11:
            return m_settings.get<Keyboard_PadR3>().value;
        case 12:
            return m_settings.get<Keyboard_AnalogMode>().value;
        case 13:
            return m_settings.get<Keyboard_PadUp>().value;
        case 14:
            return m_settings.get<Keyboard_PadRight>().value;
        case 15:
            return m_settings.get<Keyboard_PadDown>().value;
        case 16:
            return m_settings.get<Keyboard_PadLeft>().value;
        default:
            abort();
    }
}

json PCSX::Pads::getCfg() {
    json ret;
    ret[0] = m_pads[0].getCfg();
    ret[1] = m_pads[1].getCfg();
    return ret;
}

json PCSX::Pads::Pad::getCfg() { return m_settings.serialize(); }

void PCSX::Pads::setCfg(const json& j) {
    if (j.count("pads") && j["pads"].is_array()) {
        auto padsCfg = j["pads"];
        if (padsCfg.size() >= 1) {
            m_pads[0].setCfg(padsCfg[0]);
        } else {
            m_pads[0].setDefaults(true);
        }
        if (padsCfg.size() >= 2) {
            m_pads[1].setCfg(padsCfg[1]);
        } else {
            m_pads[1].setDefaults(false);
        }
    } else {
        setDefaults();
    }
}

void PCSX::Pads::Pad::setCfg(const json& j) {
    m_settings.deserialize(j);
    map();
}

void PCSX::Pads::setDefaults() {
    m_pads[0].setDefaults(true);
    m_pads[1].setDefaults(false);
}

void PCSX::Pads::Pad::setDefaults(bool firstController) {
    m_settings.reset();
    if (firstController) {
        m_settings.get<SettingConnected>() = true;
    }
    map();
}

void PCSX::Pads::setLua(Lua L) {
    auto getButton = [this](Lua L, unsigned pad) -> int {
        int n = L.gettop();
        if (n == 0) return L.error("Not enough arguments to getButton");
        if (!L.isnumber(1)) return L.error("Invalid argument to getButton");
        auto buttons = m_pads[pad].m_data.buttonStatus;
        unsigned button = L.checknumber(1);
        L.push((buttons & (1 << button)) == 0);
        return 1;
    };

    auto setOverride = [this](Lua L, unsigned pad) -> int {
        int n = L.gettop();
        if (n == 0) return L.error("Not enough arguments to setOverride");
        if (!L.isnumber(1)) return L.error("Invalid argument to setOverride");
        auto& overrides = m_pads[pad].m_data.overrides;
        unsigned button = L.checknumber(1);
        button = 1 << button;
        overrides &= ~button;
        return 0;
    };

    auto clearOverride = [this](Lua L, unsigned pad) -> int {
        int n = L.gettop();
        if (n == 0) return L.error("Not enough arguments to clearOverride");
        if (!L.isnumber(1)) return L.error("Invalid argument to clearOverride");
        auto& overrides = m_pads[pad].m_data.overrides;
        unsigned button = L.checknumber(1);
        button = 1 << button;
        overrides |= button;
        return 0;
    };

    L.getfieldtable("PCSX", LUA_GLOBALSINDEX);

    // setting constants
    L.getfieldtable("CONSTS");
    L.getfieldtable("PAD");
    L.getfieldtable("BUTTON");

    L.push(lua_Number(0));
    L.setfield("SELECT");
    L.push(lua_Number(3));
    L.setfield("START");
    L.push(lua_Number(4));
    L.setfield("UP");
    L.push(lua_Number(5));
    L.setfield("RIGHT");
    L.push(lua_Number(6));
    L.setfield("DOWN");
    L.push(lua_Number(7));
    L.setfield("LEFT");
    L.push(lua_Number(8));
    L.setfield("L2");
    L.push(lua_Number(9));
    L.setfield("R2");
    L.push(lua_Number(10));
    L.setfield("L1");
    L.push(lua_Number(11));
    L.setfield("R1");
    L.push(lua_Number(12));
    L.setfield("TRIANGLE");
    L.push(lua_Number(13));
    L.setfield("CIRCLE");
    L.push(lua_Number(14));
    L.setfield("CROSS");
    L.push(lua_Number(15));
    L.setfield("SQUARE");

    L.pop();
    L.pop();
    L.pop();

    // pushing settings

    L.getfieldtable("settings");
    L.getfieldtable("pads");
    L.push(lua_Number(1));
    m_pads[0].m_settings.pushValue(L);
    L.settable();
    L.push(lua_Number(2));
    m_pads[0].m_settings.pushValue(L);
    L.settable();
    L.pop();
    L.pop();

    L.getfieldtable("SIO0");
    L.getfieldtable("slots");

    // pads callbacks

    L.getfieldtable(1);
    L.getfieldtable("pads");
    L.getfieldtable(1);

    // push first pad stuff here
    L.declareFunc(
        "getButton", [getButton](Lua L) -> int { return getButton(L, 0); }, -1);
    L.declareFunc(
        "setOverride", [setOverride](Lua L) -> int { return setOverride(L, 0); }, -1);
    L.declareFunc(
        "clearOverride", [clearOverride](Lua L) -> int { return clearOverride(L, 0); }, -1);

    L.pop();
    L.pop();
    L.pop();

    L.getfieldtable(2);
    L.getfieldtable("pads");
    L.getfieldtable(1);

    // push second pad stuff here
    L.declareFunc(
        "getButton", [getButton](Lua L) -> int { return getButton(L, 1); }, -1);
    L.declareFunc(
        "setOverride", [setOverride](Lua L) -> int { return setOverride(L, 1); }, -1);
    L.declareFunc(
        "clearOverride", [clearOverride](Lua L) -> int { return clearOverride(L, 1); }, -1);

    L.pop();
    L.pop();
    L.pop();

    L.pop();
    L.pop();
    L.pop();

    assert(L.gettop() == 0);
}
