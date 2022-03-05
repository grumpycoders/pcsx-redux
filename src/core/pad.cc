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

#define GLFW_INCLUDE_NONE
#define _USE_MATH_DEFINES
#include "core/pad.h"

#include <GL/gl3w.h>
#include <GLFW/glfw3.h>
#include <memory.h>

#include <algorithm>
#include <cmath>

#include "core/system.h"
#include "fmt/format.h"
#include "imgui.h"
#include "magic_enum/include/magic_enum.hpp"
#include "support/file.h"

struct PadData {
    // status of buttons - every controller fills this field
    uint16_t buttonStatus;

    // for analog pad fill those next 4 bytes
    // values are analog in range 0-255 where 127 is center position
    uint8_t rightJoyX, rightJoyY, leftJoyX, leftJoyY;

    // for mouse fill those next 2 bytes
    // values are in range -128 - 127
    uint8_t moveX, moveY;
};

void PCSX::Pads::init() {
    scanGamepads();
    g_system->findResource(
        [](const std::filesystem::path& filename) -> bool {
            std::unique_ptr<File> database(new File(filename));
            if (database->failed()) {
                return false;
            }

            database->seek(0, SEEK_END);
            size_t dbsize = database->tell();
            database->seek(0, SEEK_SET);
            auto dbStr = database->readString(dbsize);

            int ret = glfwUpdateGamepadMappings(dbStr.c_str());

            return ret;
        },
        "gamecontrollerdb.txt", "resources", std::filesystem::path("third_party") / "SDL_GameControllerDB");
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

void PCSX::Pads::Pad::map() {
    m_padID = g_emulator->m_pads->m_gamepadsMap[m_settings.get<SettingControllerID>()];
    // invalid buttons
    m_scancodes[1] = 255;
    m_scancodes[2] = 255;
    m_padMapping[1] = GLFW_GAMEPAD_BUTTON_INVALID;
    m_padMapping[2] = GLFW_GAMEPAD_BUTTON_INVALID;

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

static constexpr float THRESHOLD = 0.85;

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

void PCSX::Pads::Pad::getButtons(PadData& pad) {
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
        for (unsigned i = 0; i < 16; i++) result |= !(keys[m_scancodes[i]]) << i;
        return result;
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
    {
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

        // Normalize an axis from (-1, 1) to (0, 255) with 127 = center
        const auto axisToUint8 = [](float axis) {
            constexpr float scale = 1.3;
            const float scaledValue = std::clamp<float>(axis * scale, -1.0f, 1.0f);
            return (uint8_t)(std::clamp<float>(std::round(((scaledValue + 1.0f) / 2.0f) * 255.0f), 0.0f, 255.0f));
        };

        pad.leftJoyX = axisToUint8(state.axes[GLFW_GAMEPAD_AXIS_LEFT_X]);
        pad.leftJoyY = axisToUint8(state.axes[GLFW_GAMEPAD_AXIS_LEFT_Y]);
        pad.rightJoyX = axisToUint8(state.axes[GLFW_GAMEPAD_AXIS_RIGHT_X]);
        pad.rightJoyY = axisToUint8(state.axes[GLFW_GAMEPAD_AXIS_RIGHT_Y]);
    }
    uint16_t result = 0;
    for (unsigned i = 0; i < 16; i++) result |= !buttons[i] << i;

    pad.buttonStatus = result;
}

void PCSX::Pads::Pad::readPort(PadData& data) {
    memset(&data, 0, sizeof(PadData));
    getButtons(data);
}

uint8_t PCSX::Pads::startPoll(Port port) {
    PadData padd;
    int index = port == Port1 ? 0 : 1;
    m_pads[index].readPort(padd);
    return m_pads[index].startPoll(padd);
}

uint8_t PCSX::Pads::poll(uint8_t value, Port port) {
    int index = port == Port1 ? 0 : 1;
    return m_pads[index].poll(value);
}

uint8_t PCSX::Pads::Pad::poll(uint8_t value) { return m_bufc > m_bufcount ? 0xff : m_buf[m_bufc++]; }

uint8_t PCSX::Pads::Pad::startPoll(const PadData& pad) {
    m_bufc = 0;

    if (!m_settings.get<SettingConnected>()) {
        m_bufcount = 0;
        return 0xff;
    }

    switch (m_type) {
        case PadType::Mouse:
            m_mousepar[3] = pad.buttonStatus & 0xff;
            m_mousepar[4] = pad.buttonStatus >> 8;
            m_mousepar[5] = pad.moveX;
            m_mousepar[6] = pad.moveY;

            memcpy(m_buf, m_mousepar, 7);
            m_bufcount = 6;
            break;
        case PadType::Negcon:  // npc101/npc104(slph00001/slph00069)
            m_analogpar[1] = 0x23;
            m_analogpar[3] = pad.buttonStatus & 0xff;
            m_analogpar[4] = pad.buttonStatus >> 8;
            m_analogpar[5] = pad.rightJoyX;
            m_analogpar[6] = pad.rightJoyY;
            m_analogpar[7] = pad.leftJoyX;
            m_analogpar[8] = pad.leftJoyY;

            memcpy(m_buf, m_analogpar, 9);
            m_bufcount = 8;
            break;
        case PadType::AnalogJoy:  // scph1110
        case PadType::AnalogPad:  // scph1150
            m_analogpar[1] = 0x73;
            m_analogpar[3] = pad.buttonStatus & 0xff;
            m_analogpar[4] = pad.buttonStatus >> 8;
            m_analogpar[5] = pad.rightJoyX;
            m_analogpar[6] = pad.rightJoyY;
            m_analogpar[7] = pad.leftJoyX;
            m_analogpar[8] = pad.leftJoyY;

            memcpy(m_buf, m_analogpar, 9);
            m_bufcount = 8;
            break;
        case PadType::Standard:
        default:
            m_stdpar[3] = pad.buttonStatus & 0xff;
            m_stdpar[4] = pad.buttonStatus >> 8;

            memcpy(m_buf, m_stdpar, 5);
            m_bufcount = 4;
    }

    return m_buf[m_bufc++];
}

bool PCSX::Pads::configure() {
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

    if (ImGui::BeginCombo(_("Pad"), c_padNames[m_selectedPadForConfig]())) {
        for (unsigned i = 0; i < 2; i++) {
            if (ImGui::Selectable(c_padNames[i](), m_selectedPadForConfig == i)) {
                m_selectedPadForConfig = i;
            }
        }
        ImGui::EndCombo();
    }

    bool changed = false;
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
    };

    auto keyName = glfwGetKeyName(key, 0);
    if (keyName == nullptr) {
        return fmt::format(_("Unknown keyboard key {}"), key);
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
        []() { return _("Auto"); },
        []() { return _("Controller"); },
        []() { return _("Keyboard"); },
    };
    static std::function<const char*()> const c_buttonNames[] = {
        []() { return _("Cross"); },  []() { return _("Square"); }, []() { return _("Triangle"); },
        []() { return _("Circle"); }, []() { return _("Select"); }, []() { return _("Start"); },
        []() { return _("L1"); },     []() { return _("R1"); },     []() { return _("L2"); },
        []() { return _("R2"); },
    };
    static std::function<const char*()> const c_dpadDirections[] = {
        []() { return _("Up"); },
        []() { return _("Right"); },
        []() { return _("Down"); },
        []() { return _("Left"); },
    };

    bool changed = false;
    changed |= ImGui::Checkbox(_("Connected"), &m_settings.get<SettingConnected>().value);

    auto& type = m_settings.get<SettingInputType>().value;

    if (ImGui::BeginCombo(_("Device type"), c_inputDevices[magic_enum::enum_integer<InputType>(type)]())) {
        for (auto i : magic_enum::enum_values<InputType>()) {
            if (ImGui::Selectable(c_inputDevices[magic_enum::enum_integer<InputType>(i)](), i == type)) {
                changed = true;
                type = i;
            }
        }

        ImGui::EndCombo();
    }

    ImGui::Text(_("Keyboard mapping"));
    if (ImGui::BeginTable("Mapping", 2, ImGuiTableFlags_SizingFixedSame)) {
        ImGui::TableSetupColumn(_("Computer button mapping"));
        ImGui::TableSetupColumn(_("Gamepad button"));
        ImGui::TableHeadersRow();
        for (auto i = 0; i < 10; i++) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(1);
            ImGui::Text(c_buttonNames[i]());
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
            ImGui::Text(c_dpadDirections[i]());
            ImGui::TableSetColumnIndex(0);
            bool hasToPop = false;
            const auto absI = i + 10;
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
            return m_settings.get<Keyboard_PadUp>().value;
        case 11:
            return m_settings.get<Keyboard_PadRight>().value;
        case 12:
            return m_settings.get<Keyboard_PadDown>().value;
        case 13:
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
