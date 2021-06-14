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
#include "core/pad.h"

#include <GL/gl3w.h>
#include <GLFW/glfw3.h>
#include <fmt/core.h>
#include <memory.h>

#include "imgui.h"

enum {
    // MOUSE SCPH-1030
    PSE_PAD_TYPE_MOUSE = 1,
    // NEGCON - 16 button analog controller SLPH-00001
    PSE_PAD_TYPE_NEGCON = 2,
    // GUN CONTROLLER - gun controller SLPH-00014 from Konami
    PSE_PAD_TYPE_GUN = 3,
    // STANDARD PAD SCPH-1080, SCPH-1150
    PSE_PAD_TYPE_STANDARD = 4,
    // ANALOG JOYSTICK SCPH-1110
    PSE_PAD_TYPE_ANALOGJOY = 5,
    // GUNCON - gun controller SLPH-00034 from Namco
    PSE_PAD_TYPE_GUNCON = 6,
    // ANALOG CONTROLLER SCPH-1150
    PSE_PAD_TYPE_ANALOGPAD = 7,
};

struct PadDataS {
    // controler type - fill it withe predefined values above
    uint8_t controllerType;

    // status of buttons - every controller fills this field
    uint16_t buttonStatus;

    // for analog pad fill those next 4 bytes
    // values are analog in range 0-255 where 127 is center position
    uint8_t rightJoyX, rightJoyY, leftJoyX, leftJoyY;

    // for mouse fill those next 2 bytes
    // values are in range -128 - 127
    uint8_t moveX, moveY;
};

PCSX::Pads::Pads() : m_listener(g_system->m_eventBus) {}

void PCSX::Pads::Pad::map() {
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

static const float TRIGGER_THRESHOLD = 0.85;
static const float AXIS_THRESHOLD = 0.75;

// Certain buttons on controllers are actually axis that can be pressed, half-pressed, etc.
bool PCSX::Pads::Pad::isControllerButtonPressed(int button, GLFWgamepadstate* state) {
    switch (button) {
        case GLFW_GAMEPAD_BUTTON_LEFT_TRIGGER:
            return state->axes[GLFW_GAMEPAD_AXIS_LEFT_TRIGGER] >= TRIGGER_THRESHOLD;
        case GLFW_GAMEPAD_BUTTON_RIGHT_TRIGGER:
            return state->axes[GLFW_GAMEPAD_AXIS_RIGHT_TRIGGER] >= TRIGGER_THRESHOLD;
        default:
            return state->buttons[m_padMapping[button]];
    }
}

uint16_t PCSX::Pads::Pad::getButtons() {
    if (!m_settings.get<SettingConnected>()) return 0xffff;
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
        return getKeyboardButtons();
    }

    if (m_padID >= 0) {
        hasPad = glfwGetGamepadState(m_padID, &state);
    }

    if (!hasPad) {
        if (inputType == InputType::Auto) {
            return getKeyboardButtons();
        }
        return 0xffff;
    }

    bool buttons[16];
    for (unsigned i = 0; i < 16; i++) {
        buttons[i] = isControllerButtonPressed(i, &state);
    }
    if (state.axes[GLFW_GAMEPAD_AXIS_LEFT_Y] >= AXIS_THRESHOLD) buttons[6] = true;
    if (state.axes[GLFW_GAMEPAD_AXIS_LEFT_X] >= AXIS_THRESHOLD) buttons[5] = true;
    if (state.axes[GLFW_GAMEPAD_AXIS_LEFT_Y] <= -AXIS_THRESHOLD) buttons[4] = true;
    if (state.axes[GLFW_GAMEPAD_AXIS_LEFT_X] <= -AXIS_THRESHOLD) buttons[7] = true;
    uint16_t result = 0;
    for (unsigned i = 0; i < 16; i++) result |= !buttons[i] << i;

    return result;
}

void PCSX::Pads::Pad::readPort(PadDataS* data) {
    memset(data, 0, sizeof(PadDataS));
    data->buttonStatus = getButtons();
}

uint8_t PCSX::Pads::startPoll(Port port) {
    PadDataS padd;
    int index = port == Port1 ? 0 : 1;
    m_pads[index].readPort(&padd);
    return m_pads[index].startPoll(&padd);
}

uint8_t PCSX::Pads::poll(uint8_t value, Port port) {
    int index = port == Port1 ? 0 : 1;
    return m_pads[index].poll(value);
}

uint8_t PCSX::Pads::Pad::poll(uint8_t value) {
    if (m_bufc > m_bufcount) return 0;
    return m_buf[m_bufc++];
}

uint8_t PCSX::Pads::Pad::startPoll(PadDataS* pad) {
    m_bufc = 0;

    switch (pad->controllerType) {
        case PSE_PAD_TYPE_MOUSE:
            m_mousepar[3] = pad->buttonStatus & 0xff;
            m_mousepar[4] = pad->buttonStatus >> 8;
            m_mousepar[5] = pad->moveX;
            m_mousepar[6] = pad->moveY;

            memcpy(m_buf, m_mousepar, 7);
            m_bufcount = 6;
            break;
        case PSE_PAD_TYPE_NEGCON:  // npc101/npc104(slph00001/slph00069)
            m_analogpar[1] = 0x23;
            m_analogpar[3] = pad->buttonStatus & 0xff;
            m_analogpar[4] = pad->buttonStatus >> 8;
            m_analogpar[5] = pad->rightJoyX;
            m_analogpar[6] = pad->rightJoyY;
            m_analogpar[7] = pad->leftJoyX;
            m_analogpar[8] = pad->leftJoyY;

            memcpy(m_buf, m_analogpar, 9);
            m_bufcount = 8;
            break;
        case PSE_PAD_TYPE_ANALOGPAD:  // scph1150
            m_analogpar[1] = 0x73;
            m_analogpar[3] = pad->buttonStatus & 0xff;
            m_analogpar[4] = pad->buttonStatus >> 8;
            m_analogpar[5] = pad->rightJoyX;
            m_analogpar[6] = pad->rightJoyY;
            m_analogpar[7] = pad->leftJoyX;
            m_analogpar[8] = pad->leftJoyY;

            memcpy(m_buf, m_analogpar, 9);
            m_bufcount = 8;
            break;
        case PSE_PAD_TYPE_ANALOGJOY:  // scph1110
            m_analogpar[1] = 0x53;
            m_analogpar[3] = pad->buttonStatus & 0xff;
            m_analogpar[4] = pad->buttonStatus >> 8;
            m_analogpar[5] = pad->rightJoyX;
            m_analogpar[6] = pad->rightJoyY;
            m_analogpar[7] = pad->leftJoyX;
            m_analogpar[8] = pad->leftJoyY;

            memcpy(m_buf, m_analogpar, 9);
            m_bufcount = 8;
            break;
        case PSE_PAD_TYPE_STANDARD:
        default:
            m_stdpar[3] = pad->buttonStatus & 0xff;
            m_stdpar[4] = pad->buttonStatus >> 8;

            memcpy(m_buf, m_stdpar, 5);
            m_bufcount = 4;
    }

    return m_buf[m_bufc++];
}

bool PCSX::Pads::configure() {
    bool changed = false;

#if 0
    if (!m_showCfg) {
        configuringButton = false;  // since the GUI is off, turn off configuring buttons
        return changed;               // early exit if the pad config window is off
    }

    ImGui::SetNextWindowPos(ImVec2(70, 90), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(550, 220), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(_("Pad configuration"), &m_showCfg)) {
        ImGui::End();
        return changed;
    }

    static const char* inputDevices[] = {"Pad 1 [Keyboard]", "Pad 1 [Controller]", "Pad 2 [Keyboard]",
                                         "Pad 2 [Controller]"};  // list of options for the drop down table
    static const char* buttonNames[] = {
        "Cross   ", "Square  ", "Triangle", "Circle  ", "Select  ", "Start   ",
        "L1      ", "R1      ", "L2      ", "R2      "};  // PS1 controller buttons (padded to 8 characters for GUI
                                                          // prettiness)
    static const char* dpadDirections[] = {
        "Up      ", "Right   ", "Down    ",
        "Left    "};  // PS1 controller dpad directions (padded to 8 characters for GUI prettiness)
    auto& type = m_settings.get<SettingSelectedPad>().value;

    if (ImGui::BeginCombo(_("Device"), inputDevices[type])) {
        for (auto i = 0; i < 4; i++) {
            if (ImGui::Selectable(inputDevices[i])) {  // present the options (Configure joypad 1, joypad 2, etc)
                changed = true;
                type = (pad_config_option_t)i;
            }
        }

        ImGui::EndCombo();
    }

    const auto buttonSize = ImVec2(200, 30);  // Nice button size for every button so that it's aligned

    ImGui::Text(_("Configure buttons"));
    for (auto i = 0; i < 10;) {  // render the GUI for 2 buttons at a time. 2 buttons per line.
        ImGui::Text(buttonNames[i]);
        ImGui::SameLine();
        if (ImGui::Button(keyToString(*getButtonFromGUIIndex(i, type), i, type).c_str(),
                          buttonSize)) {  // if the button gets pressed, set this as the button to be configured
            configButton(i);              // mark button to be configured
            changed = true;
        }
        i++;

        ImGui::SameLine();

        ImGui::Text(buttonNames[i]);
        ImGui::SameLine();
        if (ImGui::Button(keyToString(*getButtonFromGUIIndex(i, type), i, type).c_str(),
                          buttonSize)) {  // if the button gets pressed, set this as the button to be configured
            configButton(i);              // mark button to be configured
            changed = true;
        }
        i++;
    }

    ImGui::NewLine();
    ImGui::Text(_("Configure dpad"));
    for (auto i = 0; i < 4;) {  // render the GUI for 2 dpad directions at a time. 2 buttons per line.
        ImGui::Text(dpadDirections[i]);
        ImGui::SameLine();
        if (ImGui::Button(keyToString(*getButtonFromGUIIndex(i + 10, type), i + 10, type).c_str(),
                          buttonSize)) {  // if the button gets pressed, set this as the button to be configured
            configButton(i +
                         10);  // mark button to be configured (+10 because the dpad is preceded by 10 other buttons)
            changed = true;
        }

        i++;
        ImGui::SameLine();

        ImGui::Text(dpadDirections[i]);
        ImGui::SameLine();
        if (ImGui::Button(keyToString(*getButtonFromGUIIndex(i + 10, type), i + 10, type).c_str(),
                          buttonSize)) {  // if the button gets pressed, set this as the button to be configured
            configButton(i + 10);         // mark button to be configured
            changed = true;
        }
        i++;
    }

    ImGui::End();

    if (configuringButton && (type == Pad_Controller || type == Pad2_Controller)) {  // handle joypad rebinding
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            if (event.type == SDL_JOYBUTTONDOWN) {
                auto* button = getButtonFromGUIIndex(configuredButtonIndex,
                                                     type);  // get reference to the button that we want to change
                *button = event.cbutton.button;              // change the button's mapping
                save = true;                                 // tell the program to save
                configuringButton = false;  // Now that we changed the binding, we're not configuring a button anymore
                break;
            }

            else if (event.type ==
                     SDL_JOYAXISMOTION) {  // L2 and R2 are not actually buttons on most controllers, but axis. Pain.
                if ((event.jaxis.axis == SDL_CONTROLLER_AXIS_TRIGGERLEFT ||
                     event.jaxis.axis == SDL_CONTROLLER_AXIS_TRIGGERRIGHT) &&
                    event.jaxis.value >= TRIGGER_DEADZONE) {
                    const auto key = (event.jaxis.axis == SDL_CONTROLLER_AXIS_TRIGGERLEFT)
                                         ? SDL_CONTROLLER_BUTTON_LEFTSHOULDER2
                                         : SDL_CONTROLLER_BUTTON_RIGHTSHOULDER2;
                    *getButtonFromGUIIndex(configuredButtonIndex, type) =
                        key;  // change the button's mapping to our custom L2 scancode
                    save = true;
                    configuringButton = false;
                    break;
                }
            }
        }
    }

    if (save) {  // check if a button was rebinded
        save = false;
        return true;
    }

#endif

    return changed;
}

#if 0
/// Mark a button as the button to config
void PCSX::PAD::configButton(int index) {
    configuringButton = true;
    configuredButtonIndex = index;
}

/// Actually update the binding for the button set to be configured
void PCSX::PAD::updateBinding(GLFWwindow* window, int key, int scancode, int action, int mods) {
    if (!configuringButton)  // if we're not configuring a button, exit early
        return;

    const auto type = m_settings.get<SettingSelectedPad>();
    if (type == Pad_Controller ||
        type == Pad2_Controller)  // if we're configuring a controller and not the keyboard, exit early
        return;

    *getButtonFromGUIIndex(configuredButtonIndex, type) =
        key;                    // set the scancode of the button that's being configured
    configuringButton = false;  // since we changed the mapping, we're not configuring a button anymore
    save = true;                // tell the GUI we need to save the new config
}

int* PCSX::PAD::getButtonFromGUIIndex(int buttonIndex, pad_config_option_t configOption) {
    if (configOption == Pad_Keyboard) {
        switch (buttonIndex) {  // Order is the same as they're on the GUI
            case 0:
                return &m_settings.get<Keyboard_PadCross>().value;
            case 1:
                return &m_settings.get<Keyboard_PadSquare>().value;
            case 2:
                return &m_settings.get<Keyboard_PadTriangle>().value;
            case 3:
                return &m_settings.get<Keyboard_PadCircle>().value;
            case 4:
                return &m_settings.get<Keyboard_PadSelect>().value;
            case 5:
                return &m_settings.get<Keyboard_PadStart>().value;
            case 6:
                return &m_settings.get<Keyboard_PadL1>().value;
            case 7:
                return &m_settings.get<Keyboard_PadR1>().value;
            case 8:
                return &m_settings.get<Keyboard_PadL2>().value;
            case 9:
                return &m_settings.get<Keyboard_PadR2>().value;
            case 10:
                return &m_settings.get<Keyboard_PadUp>().value;
            case 11:
                return &m_settings.get<Keyboard_PadRight>().value;
            case 12:
                return &m_settings.get<Keyboard_PadDown>().value;
            case 13:
                return &m_settings.get<Keyboard_PadLeft>().value;
            default:
                printf("[PAD] Somehow read from invalid button config\n");
        }
    }

    else if (configOption == Pad2_Keyboard) {
        switch (buttonIndex) {  // Order is the same as they're on the GUI
            case 0:
                return &m_settings.get<Keyboard_Pad2Cross>().value;
            case 1:
                return &m_settings.get<Keyboard_Pad2Square>().value;
            case 2:
                return &m_settings.get<Keyboard_Pad2Triangle>().value;
            case 3:
                return &m_settings.get<Keyboard_Pad2Circle>().value;
            case 4:
                return &m_settings.get<Keyboard_Pad2Select>().value;
            case 5:
                return &m_settings.get<Keyboard_Pad2Start>().value;
            case 6:
                return &m_settings.get<Keyboard_Pad2L1>().value;
            case 7:
                return &m_settings.get<Keyboard_Pad2R1>().value;
            case 8:
                return &m_settings.get<Keyboard_Pad2L2>().value;
            case 9:
                return &m_settings.get<Keyboard_Pad2R2>().value;
            case 10:
                return &m_settings.get<Keyboard_Pad2Up>().value;
            case 11:
                return &m_settings.get<Keyboard_Pad2Right>().value;
            case 12:
                return &m_settings.get<Keyboard_Pad2Down>().value;
            case 13:
                return &m_settings.get<Keyboard_Pad2Left>().value;
            default:
                printf("[PAD] Somehow read from invalid button config\n");
        }
    }

    else if (configOption == Pad_Controller) {
        switch (buttonIndex) {
            case 0:
                return &m_settings.get<Controller_PadCross>().value;
            case 1:
                return &m_settings.get<Controller_PadSquare>().value;
            case 2:
                return &m_settings.get<Controller_PadTriangle>().value;
            case 3:
                return &m_settings.get<Controller_PadCircle>().value;
            case 4:
                return &m_settings.get<Controller_PadSelect>().value;
            case 5:
                return &m_settings.get<Controller_PadStart>().value;
            case 6:
                return &m_settings.get<Controller_PadL1>().value;
            case 7:
                return &m_settings.get<Controller_PadR1>().value;
            case 8:
                return &m_settings.get<Controller_PadL2>().value;
            case 9:
                return &m_settings.get<Controller_PadR2>().value;
            case 10:
                return &m_settings.get<Controller_PadUp>().value;
            case 11:
                return &m_settings.get<Controller_PadRight>().value;
            case 12:
                return &m_settings.get<Controller_PadDown>().value;
            case 13:
                return &m_settings.get<Controller_PadLeft>().value;
            default:
                printf("[PAD] Somehow read from invalid button config\n");
        }
    }

    else if (configOption == Pad2_Controller) {
        switch (buttonIndex) {
            case 0:
                return &m_settings.get<Controller_Pad2Cross>().value;
            case 1:
                return &m_settings.get<Controller_Pad2Square>().value;
            case 2:
                return &m_settings.get<Controller_Pad2Triangle>().value;
            case 3:
                return &m_settings.get<Controller_Pad2Circle>().value;
            case 4:
                return &m_settings.get<Controller_Pad2Select>().value;
            case 5:
                return &m_settings.get<Controller_Pad2Start>().value;
            case 6:
                return &m_settings.get<Controller_Pad2L1>().value;
            case 7:
                return &m_settings.get<Controller_Pad2R1>().value;
            case 8:
                return &m_settings.get<Controller_Pad2L2>().value;
            case 9:
                return &m_settings.get<Controller_Pad2R2>().value;
            case 10:
                return &m_settings.get<Controller_Pad2Up>().value;
            case 11:
                return &m_settings.get<Controller_Pad2Right>().value;
            case 12:
                return &m_settings.get<Controller_Pad2Down>().value;
            case 13:
                return &m_settings.get<Controller_Pad2Left>().value;
            default:
                printf("[PAD] Somehow read from invalid button config\n");
        }
    }

    else
        printf("Invalid joypad number. This is neither joypad 1 nor 2");
}

/// GLFW doesn't support converting some of the most common keys to strings, and neither does the SDL controller API
/// Key: The scancode of a GLFW key or an SDL controller button
/// Index: The button's id (used for when there's multiple buttons with the same label)
/// ConfigOption: Are we configuring a controller or the keyboard
std::string PCSX::PAD::keyToString(int key, int index, pad_config_option_t configOption) {
    if (configOption == Pad_Controller || configOption == Pad2_Controller) {  // if it's a controller button
        switch (key) {
            case SDL_CONTROLLER_BUTTON_INVALID:
                return fmt::format("Unmapped##{}", index);
            case SDL_CONTROLLER_BUTTON_START:
                return fmt::format("Start##{}", index);
            case SDL_CONTROLLER_BUTTON_BACK:
                return fmt::format("Select##{}", index);
            case SDL_CONTROLLER_BUTTON_DPAD_UP:
                return fmt::format("D-Pad Up##{}", index);
            case SDL_CONTROLLER_BUTTON_DPAD_RIGHT:
                return fmt::format("D-Pad Right##{}", index);
            case SDL_CONTROLLER_BUTTON_DPAD_DOWN:
                return fmt::format("D-Pad Down##{}", index);
            case SDL_CONTROLLER_BUTTON_DPAD_LEFT:
                return fmt::format("D-Pad Left##{}", index);
            case SDL_CONTROLLER_BUTTON_LEFTSHOULDER:
                return fmt::format("Left Shoulder##{}", index);
            case SDL_CONTROLLER_BUTTON_RIGHTSHOULDER:
                return fmt::format("Right Shoulder##{}", index);
            case SDL_CONTROLLER_BUTTON_LEFTSHOULDER2:
                return fmt::format("Left Shoulder 2##{}", index);
            case SDL_CONTROLLER_BUTTON_RIGHTSHOULDER2:
                return fmt::format("Right Shoulder 2##{}", index);

            default:
                return fmt::format("Controller button {}##{}", key, index);
        }
    }

    // else if it is a keyboard key
    switch (key) {  // define strings for some common keys that are not supported by glfwGetKeyName
        case GLFW_KEY_UP:
            return fmt::format("Keyboard Up##{}", index);
        case GLFW_KEY_RIGHT:
            return fmt::format("Keyboard Right##{}", index);
        case GLFW_KEY_DOWN:
            return fmt::format("Keyboard Down##{}", index);
        case GLFW_KEY_LEFT:
            return fmt::format("Keyboard Left##{}", index);
        case GLFW_KEY_BACKSPACE:
            return fmt::format("Keyboard Backspace##{}", index);
        case GLFW_KEY_ENTER:
            return fmt::format("Keyboard Enter##{}", index);
        case GLFW_KEY_SPACE:
            return fmt::format("Keyboard Space##{}", index);

        default: {  // handle the rest of the buttons
            auto keyName = glfwGetKeyName(key, 0);
            if (keyName == nullptr) return fmt::format("Keyboard Unknown##{}", index);

            auto str = std::string(keyName);  // capitalize first character of the key's name
            str[0] = toupper(str[0]);
            return fmt::format("Keyboard {}##{}", str, index);
        }
    }
}

#endif

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
        // xxx
        printf("Blah");
    } else {
        setDefaults();
    }
}

void PCSX::Pads::Pad::setCfg(const json& j) { map(); }

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
