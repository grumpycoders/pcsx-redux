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

#include <stdint.h>
#include <SDL.h>
#include <GLFW/glfw3.h>

#include "imgui.h" // for joypad config menu
#include "core/system.h" // for configure() function
#include "core/psxemulator.h"
#include "json.hpp" // for getCfg

struct PadDataS;
using json = nlohmann::json;

namespace PCSX {
class PAD {
  public:

    enum pad_t { PAD1, PAD2 };

    enum pad_config_option_t {
        Pad1_Keyboard,
        Pad1_Controller,
        Pad2_Keyboard,
        Pad2_Controller
    };

    PAD(pad_t pad);
    ~PAD();
    void init();
    void shutdown();
    static void updateBinding(GLFWwindow* window, int key, int scancode, int action, int mods); // Actually update the binding for the button set to be configured
    unsigned char startPoll();
    unsigned char poll(unsigned char);
    
    json getCfg();
    void setCfg(const json &j);
    bool configure();
    bool m_showCfg = false;

  private:
    void readPort(PadDataS *pad);
    unsigned char startPoll(PadDataS *pad);
    uint16_t getButtons();
    void mapScancodes(); // load keyboard bindings
    void configButton(int index); // pick the button to config
    static int* getButtonFromGUIIndex(int buttonIndex, pad_config_option_t configOption);
    static std::string keyToString(int key, int index, pad_config_option_t configOption);

    pad_t m_padIdx = PAD1;

    bool m_connected = false;
    bool m_isKeyboard = false;
    int m_joystick = -1;
    int m_scancodes[16];
    int m_padMapping[16];

    SDL_GameController *m_pad = NULL;

    unsigned char m_buf[256];
    unsigned char m_stdpar[10] = {0x00, 0x41, 0x5a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char m_mousepar[8] = {0x00, 0x12, 0x5a, 0xff, 0xff, 0xff, 0xff};
    unsigned char m_analogpar[9] = {0x00, 0xff, 0x5a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const int16_t TRIGGER_DEADZONE = INT16_MAX; // The L2/R2 buttons on typical gamepads are actually axis. This variable sets a threshold that decides
                                                // How pressed a trigger button needs to be in order to actually be considered pressed. INT16_MAX means that it should be fully pulled down.
    
    /// In order to use the axis as regular buttons, we're going to define our own scancodes using some of SDL's reserved ones that will never be used by the library
    static const int SDL_CONTROLLER_BUTTON_LEFTSHOULDER2 = -2; 
    static const int SDL_CONTROLLER_BUTTON_RIGHTSHOULDER2 = -3;
    bool isControllerButtonPressed(int scancode);

    int m_bufcount, m_bufc; 
public:
    static bool configuringButton; // are we configuring a button in the GUI?
    static int configuredButtonIndex; // Which button are we configuring in the GUI?
    static bool save; // do we need to save?

    // settings block
    // Pad 1 keyboard bindings
    typedef Setting<int, TYPESTRING("Keyboard_Pad1Up"), GLFW_KEY_UP> Keyboard_Pad1Up;
    typedef Setting<int, TYPESTRING("Keyboard_Pad1Right"), GLFW_KEY_RIGHT> Keyboard_Pad1Right;
    typedef Setting<int, TYPESTRING("Keyboard_Pad1Down"), GLFW_KEY_DOWN> Keyboard_Pad1Down;
    typedef Setting<int, TYPESTRING("Keyboard_Pad1Left"), GLFW_KEY_LEFT> Keyboard_Pad1Left;
    typedef Setting<int, TYPESTRING("Keyboard_Pad1Cross"), GLFW_KEY_X> Keyboard_Pad1Cross;
    typedef Setting<int, TYPESTRING("Keyboard_Pad1Triangle"), GLFW_KEY_S> Keyboard_Pad1Triangle;
    typedef Setting<int, TYPESTRING("Keyboard_Pad1Square"), GLFW_KEY_Z> Keyboard_Pad1Square;
    typedef Setting<int, TYPESTRING("Keyboard_Pad1Circle"), GLFW_KEY_D> Keyboard_Pad1Circle;
    typedef Setting<int, TYPESTRING("Keyboard_Pad1Select"), GLFW_KEY_BACKSPACE> Keyboard_Pad1Select;
    typedef Setting<int, TYPESTRING("Keyboard_Pad1Sstart"), GLFW_KEY_ENTER> Keyboard_Pad1Start;
    typedef Setting<int, TYPESTRING("Keyboard_Pad1L1"), GLFW_KEY_Q> Keyboard_Pad1L1;
    typedef Setting<int, TYPESTRING("Keyboard_Pad1L2"), GLFW_KEY_A> Keyboard_Pad1L2;
    typedef Setting<int, TYPESTRING("Keyboard_Pad1R1"), GLFW_KEY_R> Keyboard_Pad1R1;
    typedef Setting<int, TYPESTRING("Keyboard_Pad1R2"), GLFW_KEY_F> Keyboard_Pad1R2;

    // Pad2 keyboard bindings
    typedef Setting<int, TYPESTRING("Keyboard_Pad2Up"), GLFW_KEY_UP> Keyboard_Pad2Up;
    typedef Setting<int, TYPESTRING("Keyboard_Pad2Right"), GLFW_KEY_RIGHT> Keyboard_Pad2Right;
    typedef Setting<int, TYPESTRING("Keyboard_Pad2Down"), GLFW_KEY_DOWN> Keyboard_Pad2Down;
    typedef Setting<int, TYPESTRING("Keyboard_Pad2Left"), GLFW_KEY_LEFT> Keyboard_Pad2Left;
    typedef Setting<int, TYPESTRING("Keyboard_Pad2Cross"), GLFW_KEY_X> Keyboard_Pad2Cross;
    typedef Setting<int, TYPESTRING("Keyboard_Pad2Triangle"), GLFW_KEY_S> Keyboard_Pad2Triangle;
    typedef Setting<int, TYPESTRING("Keyboard_Pad2Square"), GLFW_KEY_Z> Keyboard_Pad2Square;
    typedef Setting<int, TYPESTRING("Keyboard_Pad2Circle"), GLFW_KEY_D> Keyboard_Pad2Circle;
    typedef Setting<int, TYPESTRING("Keyboard_Pad2Select"), GLFW_KEY_BACKSPACE> Keyboard_Pad2Select;
    typedef Setting<int, TYPESTRING("Keyboard_Pad2Sstart"), GLFW_KEY_ENTER> Keyboard_Pad2Start;
    typedef Setting<int, TYPESTRING("Keyboard_Pad2L1"), GLFW_KEY_Q> Keyboard_Pad2L1;
    typedef Setting<int, TYPESTRING("Keyboard_Pad2L2"), GLFW_KEY_A> Keyboard_Pad2L2;
    typedef Setting<int, TYPESTRING("Keyboard_Pad2R1"), GLFW_KEY_R> Keyboard_Pad2R1;
    typedef Setting<int, TYPESTRING("Keyboard_Pad2R2"), GLFW_KEY_F> Keyboard_Pad2R2;

    // Pad 1 controller bindings
    typedef Setting<int, TYPESTRING("Controller_Pad1Up"), SDL_CONTROLLER_BUTTON_DPAD_UP> Controller_Pad1Up;
    typedef Setting<int, TYPESTRING("Controller_Pad1Right"), SDL_CONTROLLER_BUTTON_DPAD_RIGHT> Controller_Pad1Right;
    typedef Setting<int, TYPESTRING("Controller_Pad1Down"), SDL_CONTROLLER_BUTTON_DPAD_DOWN> Controller_Pad1Down;
    typedef Setting<int, TYPESTRING("Controller_Pad1Left"), SDL_CONTROLLER_BUTTON_DPAD_LEFT> Controller_Pad1Left;
    typedef Setting<int, TYPESTRING("Controller_Pad1Cross"), SDL_CONTROLLER_BUTTON_A> Controller_Pad1Cross;
    typedef Setting<int, TYPESTRING("Controller_Pad1Triangle"), SDL_CONTROLLER_BUTTON_Y> Controller_Pad1Triangle;
    typedef Setting<int, TYPESTRING("Controller_Pad1Square"), SDL_CONTROLLER_BUTTON_X> Controller_Pad1Square;
    typedef Setting<int, TYPESTRING("Controller_Pad1Circle"), SDL_CONTROLLER_BUTTON_B> Controller_Pad1Circle;
    typedef Setting<int, TYPESTRING("Controller_Pad1Select"), SDL_CONTROLLER_BUTTON_BACK> Controller_Pad1Select;
    typedef Setting<int, TYPESTRING("Controller_Pad1Sstart"), SDL_CONTROLLER_BUTTON_START> Controller_Pad1Start;
    typedef Setting<int, TYPESTRING("Controller_Pad1L1"), SDL_CONTROLLER_BUTTON_LEFTSHOULDER> Controller_Pad1L1;
    typedef Setting<int, TYPESTRING("Controller_Pad1L2"), SDL_CONTROLLER_BUTTON_LEFTSHOULDER2> Controller_Pad1L2;
    typedef Setting<int, TYPESTRING("Controller_Pad1R1"), SDL_CONTROLLER_BUTTON_RIGHTSHOULDER> Controller_Pad1R1;
    typedef Setting<int, TYPESTRING("Controller_Pad1R2"), SDL_CONTROLLER_BUTTON_RIGHTSHOULDER2> Controller_Pad1R2;
    
    // Pad 2 controller bindings
    typedef Setting<int, TYPESTRING("Controller_Pad2Up"), SDL_CONTROLLER_BUTTON_DPAD_UP> Controller_Pad2Up;
    typedef Setting<int, TYPESTRING("Controller_Pad2Right"), SDL_CONTROLLER_BUTTON_DPAD_RIGHT> Controller_Pad2Right;
    typedef Setting<int, TYPESTRING("Controller_Pad2Down"), SDL_CONTROLLER_BUTTON_DPAD_DOWN> Controller_Pad2Down;
    typedef Setting<int, TYPESTRING("Controller_Pad2Left"), SDL_CONTROLLER_BUTTON_DPAD_LEFT> Controller_Pad2Left;
    typedef Setting<int, TYPESTRING("Controller_Pad2Cross"), SDL_CONTROLLER_BUTTON_A> Controller_Pad2Cross;
    typedef Setting<int, TYPESTRING("Controller_Pad2Triangle"), SDL_CONTROLLER_BUTTON_Y> Controller_Pad2Triangle;
    typedef Setting<int, TYPESTRING("Controller_Pad2Square"), SDL_CONTROLLER_BUTTON_X> Controller_Pad2Square;
    typedef Setting<int, TYPESTRING("Controller_Pad2Circle"), SDL_CONTROLLER_BUTTON_B> Controller_Pad2Circle;
    typedef Setting<int, TYPESTRING("Controller_Pad2Select"), SDL_CONTROLLER_BUTTON_BACK> Controller_Pad2Select;
    typedef Setting<int, TYPESTRING("Controller_Pad2Sstart"), SDL_CONTROLLER_BUTTON_START> Controller_Pad2Start;
    typedef Setting<int, TYPESTRING("Controller_Pad2L1"), SDL_CONTROLLER_BUTTON_LEFTSHOULDER> Controller_Pad2L1;
    typedef Setting<int, TYPESTRING("Controller_Pad2L2"), SDL_CONTROLLER_BUTTON_LEFTSHOULDER2> Controller_Pad2L2;
    typedef Setting<int, TYPESTRING("Controller_Pad2R1"), SDL_CONTROLLER_BUTTON_RIGHTSHOULDER> Controller_Pad2R1;
    typedef Setting<int, TYPESTRING("Controller_Pad2R2"), SDL_CONTROLLER_BUTTON_RIGHTSHOULDER2> Controller_Pad2R2;
    typedef Setting<pad_config_option_t, TYPESTRING("SelectedPad"), Pad1_Keyboard> SettingSelectedPad;

    static Settings<Keyboard_Pad1Up, Keyboard_Pad1Right, Keyboard_Pad1Down, Keyboard_Pad1Left, Keyboard_Pad1Cross, Keyboard_Pad1Triangle, Keyboard_Pad1Square, Keyboard_Pad1Circle, Keyboard_Pad1Select, Keyboard_Pad1Start, Keyboard_Pad1L1, Keyboard_Pad1L2, Keyboard_Pad1R1, Keyboard_Pad1R2,
                    Keyboard_Pad2Up, Keyboard_Pad2Right, Keyboard_Pad2Down, Keyboard_Pad2Left, Keyboard_Pad2Cross, Keyboard_Pad2Triangle, Keyboard_Pad2Square, Keyboard_Pad2Circle, Keyboard_Pad2Select, Keyboard_Pad2Start, Keyboard_Pad2L1, Keyboard_Pad2L2, Keyboard_Pad2R1, Keyboard_Pad2R2,
                    Controller_Pad1Up, Controller_Pad1Right, Controller_Pad1Down, Controller_Pad1Left, Controller_Pad1Cross, Controller_Pad1Triangle, Controller_Pad1Square, Controller_Pad1Circle, Controller_Pad1Select, Controller_Pad1Start, Controller_Pad1L1, Controller_Pad1L2, Controller_Pad1R1, Controller_Pad1R2,
                    Controller_Pad2Up, Controller_Pad2Right, Controller_Pad2Down, Controller_Pad2Left, Controller_Pad2Cross, Controller_Pad2Triangle, Controller_Pad2Square, Controller_Pad2Circle, Controller_Pad2Select, Controller_Pad2Start, Controller_Pad2L1, Controller_Pad2L2, Controller_Pad2R1, Controller_Pad2R2,
                    SettingSelectedPad> settings;
};

}  // namespace PCSX
