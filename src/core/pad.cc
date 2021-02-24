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
    
#include <memory.h>

#include "imgui.h"
#define GLFW_INCLUDE_NONE
#include <GL/gl3w.h>
#include <GLFW/glfw3.h>
#include <fmt/core.h>

#include "core/pad.h"
#include "core/psemu_plugin_defs.h"
 
bool PCSX::PAD::configuringButton = false;
bool PCSX::PAD::save = false;

int PCSX::PAD::configuredButtonIndex = 0;
decltype(PCSX::PAD::settings) PCSX::PAD::settings;

PCSX::PAD::PAD(pad_t pad) : m_padIdx(pad), m_connected(pad == PAD1), m_isKeyboard(pad == PAD1), m_pad(nullptr) {
    mapScancodes();
}

void PCSX::PAD::init() {
    bool foundOne = false;
    mapScancodes();

    for (int i = 0; i < SDL_NumJoysticks(); ++i) {
        if (SDL_IsGameController(i)) {
            if (!foundOne && m_padIdx == PAD2) {
                foundOne = true;
                continue;
            }
            m_pad = SDL_GameControllerOpen(i);
            m_isKeyboard = false;
            if (m_pad) break;
        }
    }
}

/// Map keyboard bindings
void PCSX::PAD::mapScancodes() {
    // invalid buttons 
    m_scancodes[1] = 255;
    m_scancodes[2] = 255;
    m_padMapping[1] = SDL_CONTROLLER_BUTTON_INVALID;
    m_padMapping[2] = SDL_CONTROLLER_BUTTON_INVALID;

    if (m_padIdx == PAD1) {
        m_scancodes[0] = settings.get<PCSX::PAD::Keyboard_Pad1Select>();  // SELECT
        m_scancodes[3] = settings.get<PCSX::PAD::Keyboard_Pad1Start>();   // START
        m_scancodes[4] = settings.get<PCSX::PAD::Keyboard_Pad1Up>();      // UP
        m_scancodes[5] = settings.get<PCSX::PAD::Keyboard_Pad1Right>();   // RIGHT
        m_scancodes[6] = settings.get<PCSX::PAD::Keyboard_Pad1Down>();    // DOWN
        m_scancodes[7] = settings.get<PCSX::PAD::Keyboard_Pad1Left>();    // LEFT
        m_scancodes[8] = settings.get<PCSX::PAD::Keyboard_Pad1L2>();         // L2
        m_scancodes[9] = settings.get<PCSX::PAD::Keyboard_Pad1R2>();         // R2
        m_scancodes[10] = settings.get<PCSX::PAD::Keyboard_Pad1L1>();        // L1
        m_scancodes[11] = settings.get<PCSX::PAD::Keyboard_Pad1R1>();        // R1
        m_scancodes[12] = settings.get<PCSX::PAD::Keyboard_Pad1Triangle>();  // TRIANGLE
        m_scancodes[13] = settings.get<PCSX::PAD::Keyboard_Pad1Circle>();    // CIRCLE
        m_scancodes[14] = settings.get<PCSX::PAD::Keyboard_Pad1Cross>();     // CROSS
        m_scancodes[15] = settings.get<PCSX::PAD::Keyboard_Pad1Square>();    // SQUARE

        m_padMapping[0] = settings.get<PCSX::PAD::Controller_Pad1Select>(); // SELECT
        m_padMapping[3] = settings.get<PCSX::PAD::Controller_Pad1Start>();  // START
        m_padMapping[4] = settings.get<PCSX::PAD::Controller_Pad1Up>();     // UP
        m_padMapping[5] = settings.get<PCSX::PAD::Controller_Pad1Right>();  // RIGHT
        m_padMapping[6] = settings.get<PCSX::PAD::Controller_Pad1Down>();   // DOWN
        m_padMapping[7] = settings.get<PCSX::PAD::Controller_Pad1Left>();   // LEFT
        m_padMapping[8] = settings.get<PCSX::PAD::Controller_Pad1L2>();    // L2
        m_padMapping[9] = settings.get<PCSX::PAD::Controller_Pad1R2>();     // R2
        m_padMapping[10] = settings.get<PCSX::PAD::Controller_Pad1L1>();    // L1
        m_padMapping[11] = settings.get<PCSX::PAD::Controller_Pad1R1>();    // R1
        m_padMapping[12] = settings.get<PCSX::PAD::Controller_Pad1Triangle>(); // TRIANGLE
        m_padMapping[13] = settings.get<PCSX::PAD::Controller_Pad1Circle>(); // CIRCLE
        m_padMapping[14] = settings.get<PCSX::PAD::Controller_Pad1Cross>();  // CROSS
        m_padMapping[15] = settings.get<PCSX::PAD::Controller_Pad1Square>(); // SQUARE
    }

    else if (m_padIdx == PAD2) {
        m_scancodes[0] = settings.get<PCSX::PAD::Keyboard_Pad2Select>();  // SELECT
        m_scancodes[3] = settings.get<PCSX::PAD::Keyboard_Pad2Start>();   // START
        m_scancodes[4] = settings.get<PCSX::PAD::Keyboard_Pad2Up>();      // UP
        m_scancodes[5] = settings.get<PCSX::PAD::Keyboard_Pad2Right>();   // RIGHT
        m_scancodes[6] = settings.get<PCSX::PAD::Keyboard_Pad2Down>();    // DOWN
        m_scancodes[7] = settings.get<PCSX::PAD::Keyboard_Pad2Left>();    // LEFT
        m_scancodes[8] = settings.get<PCSX::PAD::Keyboard_Pad2L2>();         // L2
        m_scancodes[9] = settings.get<PCSX::PAD::Keyboard_Pad2R2>();         // R2
        m_scancodes[10] = settings.get<PCSX::PAD::Keyboard_Pad2L1>();        // L1
        m_scancodes[11] = settings.get<PCSX::PAD::Keyboard_Pad2R1>();        // R1
        m_scancodes[12] = settings.get<PCSX::PAD::Keyboard_Pad2Triangle>();  // TRIANGLE
        m_scancodes[13] = settings.get<PCSX::PAD::Keyboard_Pad2Circle>();    // CIRCLE
        m_scancodes[14] = settings.get<PCSX::PAD::Keyboard_Pad2Cross>();     // CROSS
        m_scancodes[15] = settings.get<PCSX::PAD::Keyboard_Pad2Square>();    // SQUARE 

        m_padMapping[0] = settings.get<PCSX::PAD::Controller_Pad2Select>(); // SELECT
        m_padMapping[3] = settings.get<PCSX::PAD::Controller_Pad2Start>();  // START
        m_padMapping[4] = settings.get<PCSX::PAD::Controller_Pad2Up>();     // UP
        m_padMapping[5] = settings.get<PCSX::PAD::Controller_Pad2Right>();  // RIGHT
        m_padMapping[6] = settings.get<PCSX::PAD::Controller_Pad2Down>();   // DOWN
        m_padMapping[7] = settings.get<PCSX::PAD::Controller_Pad2Left>();   // LEFT
        m_padMapping[8] = settings.get<PCSX::PAD::Controller_Pad2L2>();    // L2
        m_padMapping[9] = settings.get<PCSX::PAD::Controller_Pad2R2>();     // R2
        m_padMapping[10] = settings.get<PCSX::PAD::Controller_Pad2L1>();    // L1
        m_padMapping[11] = settings.get<PCSX::PAD::Controller_Pad2R1>();    // R1
        m_padMapping[12] = settings.get<PCSX::PAD::Controller_Pad2Triangle>(); // TRIANGLE
        m_padMapping[13] = settings.get<PCSX::PAD::Controller_Pad2Circle>(); // CIRCLE
        m_padMapping[14] = settings.get<PCSX::PAD::Controller_Pad2Cross>();  // CROSS
        m_padMapping[15] = settings.get<PCSX::PAD::Controller_Pad2Square>(); // SQUARE
    }
}

void PCSX::PAD::shutdown() {
    if (m_pad) SDL_GameControllerClose(m_pad);
}

PCSX::PAD::~PAD() {}

static const int16_t threshold = 28000;

/// Certain buttons on controllers are actually axis that can be pressed, half-pressed, etc.
/// Given that we need to handle both axis and buttons in a common way but SDL doesn't offer that capability
/// We do it ourselves
bool PCSX::PAD::isControllerButtonPressed(int scancode) { 
    switch (scancode) {
        case SDL_CONTROLLER_BUTTON_LEFTSHOULDER2: return SDL_GameControllerGetAxis(m_pad, SDL_CONTROLLER_AXIS_TRIGGERLEFT) >= TRIGGER_DEADZONE;
        case SDL_CONTROLLER_BUTTON_RIGHTSHOULDER2: return SDL_GameControllerGetAxis(m_pad, SDL_CONTROLLER_AXIS_TRIGGERRIGHT) >= TRIGGER_DEADZONE;        
        default: return SDL_GameControllerGetButton(m_pad, (SDL_GameControllerButton)m_padMapping[scancode]); // normal buttons
    }
}

uint16_t PCSX::PAD::getButtons() {
    uint16_t result = 0xffff;
    if (!m_connected) return result;

    if (m_isKeyboard) {
        const bool* keys = ImGui::GetIO().KeysDown;
        result = 0;
        for (unsigned i = 0; i < 16; i++) result |= !(keys[m_scancodes[i]]) << i;
    } else if (m_pad) {
        bool buttons[16];
        for (unsigned i = 0; i < 16; i++) buttons[i] = isControllerButtonPressed(i);
        Sint16 axisX, axisY, trL, trR;
        axisX = SDL_GameControllerGetAxis(m_pad, SDL_CONTROLLER_AXIS_LEFTX);
        axisY = SDL_GameControllerGetAxis(m_pad, SDL_CONTROLLER_AXIS_LEFTY);
        trL = SDL_GameControllerGetAxis(m_pad, SDL_CONTROLLER_AXIS_TRIGGERLEFT);
        trR = SDL_GameControllerGetAxis(m_pad, SDL_CONTROLLER_AXIS_TRIGGERRIGHT);
        if (axisY >= threshold) buttons[6] = true;
        if (axisX >= threshold) buttons[5] = true;
        if (axisY <= -threshold) buttons[4] = true;
        if (axisX <= -threshold) buttons[7] = true;
        if (trL >= threshold) buttons[8] = true;
        if (trR >= threshold) buttons[9] = true;
        result = 0;
        for (unsigned i = 0; i < 16; i++) result |= !buttons[i] << i;
    }

    return result;
}

void PCSX::PAD::readPort(PadDataS* data) {
    memset(data, 0, sizeof(PadDataS));
    data->buttonStatus = getButtons();
}

unsigned char PCSX::PAD::startPoll() {
    PadDataS padd;

    readPort(&padd);

    return startPoll(&padd);
}
unsigned char PCSX::PAD::poll(unsigned char value) {
    if (m_bufc > m_bufcount) return 0;
    return m_buf[m_bufc++];
}

unsigned char PCSX::PAD::startPoll(PadDataS* pad) {
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

// GUI stuff (move out of here and into an impl class)
bool PCSX::PAD::configure() {
    if (!m_showCfg) {
        configuringButton = false; // since the GUI is off, turn off configuring buttons    
        return false; // early exit if the pad config window is off
    }
    
    ImGui::SetNextWindowPos(ImVec2(70, 90), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(550, 220), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(_("Pad configuration"), &m_showCfg)) {
        ImGui::End();
        return false;
    }

    bool changed = false;

    static const char* inputDevices[] = {"Pad 1 [Keyboard]", "Pad 1 [Controller]",
                                         "Pad 2 [Keyboard]", "Pad 2 [Controller]" }; // list of options for the drop down table
    static const char* buttonNames[] = {
        "Cross   ", "Square  ", "Triangle", "Circle  ", "Select  ", "Start   ",
        "L1      ", "R1      ", "L2      ", "R2      "
    }; // PS1 controller buttons (padded to 8 characters for GUI prettiness)
    static const char* dpadDirections[] = {"Up      ", "Right   ", "Down    ", "Left    "}; // PS1 controller dpad directions (padded to 8 characters for GUI prettiness)
    auto& type = settings.get<SettingSelectedPad>().value;

    if (ImGui::BeginCombo(_("Device"), inputDevices[type])) {
        for (auto i = 0; i < 4; i++) {
            if (ImGui::Selectable(inputDevices[i])) { // present the options (Configure joypad 1, joypad 2, etc)
                changed = true;
                type = (pad_config_option_t) i;
            }
        }

        ImGui::EndCombo();
    }

    const auto buttonSize = ImVec2(200, 30); // Nice button size for every button so that it's aligned

    ImGui::Text(_("Configure buttons"));
    for (auto i = 0; i < 10;) { // render the GUI for 2 buttons at a time. 2 buttons per line.
        ImGui::Text(buttonNames[i]);
        ImGui::SameLine();
        if (ImGui::Button(keyToString (*getButtonFromGUIIndex(i, type), i, type).c_str(), buttonSize)) {// if the button gets pressed, set this as the button to be configured
            configButton(i); // mark button to be configured
            changed = true;
        }
        i++;

        ImGui::SameLine();

        ImGui::Text(buttonNames[i]);
        ImGui::SameLine();  
        if (ImGui::Button(keyToString(*getButtonFromGUIIndex(i, type), i, type).c_str(), buttonSize)) {// if the button gets pressed, set this as the button to be configured
            configButton(i); // mark button to be configured
            changed = true;
        }
        i++;
    }

    ImGui::NewLine();
    ImGui::Text(_("Configure dpad"));
    for (auto i = 0; i < 4;) { // render the GUI for 2 dpad directions at a time. 2 buttons per line.
        ImGui::Text(dpadDirections[i]);
        ImGui::SameLine();        
        if (ImGui::Button(keyToString (*getButtonFromGUIIndex(i+10, type), i+10, type).c_str(), buttonSize)) {// if the button gets pressed, set this as the button to be configured
            configButton(i + 10); // mark button to be configured (+10 because the dpad is preceded by 10 other buttons)
            changed = true;
        }

        i++;
        ImGui::SameLine();

        ImGui::Text(dpadDirections[i]);
        ImGui::SameLine();        
        if (ImGui::Button(keyToString (*getButtonFromGUIIndex(i+10, type), i+10, type).c_str(), buttonSize)) {// if the button gets pressed, set this as the button to be configured
            configButton(i + 10); // mark button to be configured
            changed = true;
        }
        i++;
    }

    ImGui::End();
    
    if (configuringButton && (type == Pad1_Controller || type == Pad2_Controller)) { // handle joypad rebinding
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            if (event.type == SDL_JOYBUTTONDOWN) {
                auto* button = getButtonFromGUIIndex(configuredButtonIndex, type); // get reference to the button that we want to change
                *button = event.cbutton.button; // change the button's mapping
                save = true; // tell the program to save
                configuringButton = false; // Now that we changed the binding, we're not configuring a button anymore
                break;
            }

            else if (event.type == SDL_JOYAXISMOTION) { // L2 and R2 are not actually buttons on most controllers, but axis. Pain.
                if ((event.jaxis.axis == SDL_CONTROLLER_AXIS_TRIGGERLEFT || event.jaxis.axis == SDL_CONTROLLER_AXIS_TRIGGERRIGHT) && event.jaxis.value >= TRIGGER_DEADZONE) {
                    const auto key = (event.jaxis.axis == SDL_CONTROLLER_AXIS_TRIGGERLEFT) ? SDL_CONTROLLER_BUTTON_LEFTSHOULDER2 : SDL_CONTROLLER_BUTTON_RIGHTSHOULDER2;
                    *getButtonFromGUIIndex(configuredButtonIndex, type) = key; // change the button's mapping to our custom L2 scancode
                    save = true; 
                    configuringButton = false;
                    break;
                }
            }
        }
    }

    if (save) { // check if a button was rebinded
        save = false;
        return true;
    }

    return changed;
}

/// Mark a button as the button to config
void PCSX::PAD::configButton(int index) {
    configuringButton = true;
    configuredButtonIndex = index;
}

/// Actually update the binding for the button set to be configured
void PCSX::PAD::updateBinding(GLFWwindow* window, int key, int scancode, int action, int mods) {
    if (!configuringButton) // if we're not configuring a button, exit early
        return;

    const auto type = settings.get<SettingSelectedPad>();
    if (type == Pad1_Controller || type == Pad2_Controller) // if we're configuring a controller and not the keyboard, exit early
        return;
    
    *getButtonFromGUIIndex(configuredButtonIndex, type) = key; // set the scancode of the button that's being configured
    configuringButton = false; // since we changed the mapping, we're not configuring a button anymore
    save = true; // tell the GUI we need to save the new config
}

int* PCSX::PAD::getButtonFromGUIIndex(int buttonIndex, pad_config_option_t configOption) {
    if (configOption == Pad1_Keyboard) {
        switch (buttonIndex) { // Order is the same as they're on the GUI
            case 0:  return &settings.get<Keyboard_Pad1Cross>().value;
            case 1:  return &settings.get<Keyboard_Pad1Square>().value;
            case 2:  return &settings.get<Keyboard_Pad1Triangle>().value;
            case 3:  return &settings.get<Keyboard_Pad1Circle>().value;
            case 4:  return &settings.get<Keyboard_Pad1Select>().value;
            case 5:  return &settings.get<Keyboard_Pad1Start>().value;
            case 6:  return &settings.get<Keyboard_Pad1L1>().value;
            case 7:  return &settings.get<Keyboard_Pad1R1>().value;
            case 8:  return &settings.get<Keyboard_Pad1L2>().value;
            case 9:  return &settings.get<Keyboard_Pad1R2>().value;
            case 10:  return &settings.get<Keyboard_Pad1Up>().value;
            case 11:  return &settings.get<Keyboard_Pad1Right>().value;
            case 12:  return &settings.get<Keyboard_Pad1Down>().value;
            case 13:  return &settings.get<Keyboard_Pad1Left>().value;
            default: printf ("[PAD] Somehow read from invalid button config\n");
        }
    }

    else if (configOption == Pad2_Keyboard) {
        switch (buttonIndex) { // Order is the same as they're on the GUI
            case 0:  return &settings.get<Keyboard_Pad2Cross>().value;
            case 1:  return &settings.get<Keyboard_Pad2Square>().value;
            case 2:  return &settings.get<Keyboard_Pad2Triangle>().value;
            case 3:  return &settings.get<Keyboard_Pad2Circle>().value;
            case 4:  return &settings.get<Keyboard_Pad2Select>().value;
            case 5:  return &settings.get<Keyboard_Pad2Start>().value;
            case 6:  return &settings.get<Keyboard_Pad2L1>().value;
            case 7:  return &settings.get<Keyboard_Pad2R1>().value;
            case 8:  return &settings.get<Keyboard_Pad2L2>().value;
            case 9:  return &settings.get<Keyboard_Pad2R2>().value;
            case 10:  return &settings.get<Keyboard_Pad2Up>().value;
            case 11:  return &settings.get<Keyboard_Pad2Right>().value;
            case 12:  return &settings.get<Keyboard_Pad2Down>().value;
            case 13:  return &settings.get<Keyboard_Pad2Left>().value;
            default: printf ("[PAD] Somehow read from invalid button config\n");
        }
    }

    else if (configOption == Pad1_Controller) {
        switch (buttonIndex) {
            case 0:  return &settings.get<Controller_Pad1Cross>().value;
            case 1:  return &settings.get<Controller_Pad1Square>().value;
            case 2:  return &settings.get<Controller_Pad1Triangle>().value;
            case 3:  return &settings.get<Controller_Pad1Circle>().value;
            case 4:  return &settings.get<Controller_Pad1Select>().value;
            case 5:  return &settings.get<Controller_Pad1Start>().value;
            case 6:  return &settings.get<Controller_Pad1L1>().value;
            case 7:  return &settings.get<Controller_Pad1R1>().value;
            case 8:  return &settings.get<Controller_Pad1L2>().value;
            case 9:  return &settings.get<Controller_Pad1R2>().value;
            case 10:  return &settings.get<Controller_Pad1Up>().value;
            case 11:  return &settings.get<Controller_Pad1Right>().value;
            case 12:  return &settings.get<Controller_Pad1Down>().value;
            case 13:  return &settings.get<Controller_Pad1Left>().value;
            default: printf ("[PAD] Somehow read from invalid button config\n");
        }    
    }

    else if (configOption == Pad2_Controller) {
        switch (buttonIndex) {
            case 0:  return &settings.get<Controller_Pad2Cross>().value;
            case 1:  return &settings.get<Controller_Pad2Square>().value;
            case 2:  return &settings.get<Controller_Pad2Triangle>().value;
            case 3:  return &settings.get<Controller_Pad2Circle>().value;
            case 4:  return &settings.get<Controller_Pad2Select>().value;
            case 5:  return &settings.get<Controller_Pad2Start>().value;
            case 6:  return &settings.get<Controller_Pad2L1>().value;
            case 7:  return &settings.get<Controller_Pad2R1>().value;
            case 8:  return &settings.get<Controller_Pad2L2>().value;
            case 9:  return &settings.get<Controller_Pad2R2>().value;
            case 10:  return &settings.get<Controller_Pad2Up>().value;
            case 11:  return &settings.get<Controller_Pad2Right>().value;
            case 12:  return &settings.get<Controller_Pad2Down>().value;
            case 13:  return &settings.get<Controller_Pad2Left>().value;
            default: printf ("[PAD] Somehow read from invalid button config\n");
        }
    }

    else printf ("Invalid joypad number. This is neither joypad 1 nor 2");
}

/// GLFW doesn't support converting some of the most common keys to strings, and neither does the SDL controller API
/// Key: The scancode of a GLFW key or an SDL controller button
/// Index: The button's id (used for when there's multiple buttons with the same label)
/// ConfigOption: Are we configuring a controller or the keyboard
std::string PCSX::PAD::keyToString(int key, int index, pad_config_option_t configOption) {
    if (configOption == Pad1_Controller || configOption == Pad2_Controller) { // if it's a controller button
        switch (key) {
            case SDL_CONTROLLER_BUTTON_INVALID: return fmt::format("Unmapped##{}", index);
            case SDL_CONTROLLER_BUTTON_START: return fmt::format("Start##{}", index);
            case SDL_CONTROLLER_BUTTON_BACK: return fmt::format("Select##{}", index);
            case SDL_CONTROLLER_BUTTON_DPAD_UP: return fmt::format("D-Pad Up##{}", index);
            case SDL_CONTROLLER_BUTTON_DPAD_RIGHT: return fmt::format("D-Pad Right##{}", index);
            case SDL_CONTROLLER_BUTTON_DPAD_DOWN: return fmt::format("D-Pad Down##{}", index);
            case SDL_CONTROLLER_BUTTON_DPAD_LEFT: return fmt::format("D-Pad Left##{}", index);
            case SDL_CONTROLLER_BUTTON_LEFTSHOULDER: return fmt::format("Left Shoulder##{}", index);
            case SDL_CONTROLLER_BUTTON_RIGHTSHOULDER: return fmt::format("Right Shoulder##{}", index);
            case SDL_CONTROLLER_BUTTON_LEFTSHOULDER2: return fmt::format("Left Shoulder 2##{}", index);
            case SDL_CONTROLLER_BUTTON_RIGHTSHOULDER2: return fmt::format("Right Shoulder 2##{}", index);
            
            default: return fmt::format("Controller button {}##{}", key, index);
        }
    }

    // else if it is a keyboard key
    switch (key) {  // define strings for some common keys that are not supported by glfwGetKeyName
        case GLFW_KEY_UP: return fmt::format("Keyboard Up##{}", index);
        case GLFW_KEY_RIGHT:return fmt::format("Keyboard Right##{}", index);
        case GLFW_KEY_DOWN: return fmt::format("Keyboard Down##{}", index);
        case GLFW_KEY_LEFT: return fmt::format("Keyboard Left##{}", index);
        case GLFW_KEY_BACKSPACE: return fmt::format("Keyboard Backspace##{}", index);
        case GLFW_KEY_ENTER: return fmt::format("Keyboard Enter##{}", index);
        case GLFW_KEY_SPACE: return fmt::format("Keyboard Space##{}", index);

        default: { // handle the rest of the buttons
            auto keyName = glfwGetKeyName(key, 0);
            if (keyName == nullptr) 
                return fmt::format("Keyboard Unknown##{}", index);

            auto str = std::string(keyName); // capitalize first character of the key's name
            str[0] = toupper(str[0]);
            return fmt::format("Keyboard {}##{}", str, index);
        }
    }
}

json PCSX::PAD::getCfg() { 
    return settings.serialize(); 
}

void PCSX::PAD::setCfg(const json& j) {
    if (j.count("pad") && j["pad"].is_object()) {
        settings.deserialize(j["pad"]);
    } 
    
    else {
        settings.reset();
    }
}
