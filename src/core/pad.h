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
        Pad1_Joypad,
        Pad2_Keyboard,
        Pad2_Joypad
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
    static std::string glfwKeyToString(int glfwKey, int index);

    pad_t m_padIdx = PAD1;

    bool m_connected = false;
    bool m_isKeyboard = false;
    int m_joystick = -1;
    int m_scancodes[16];
    SDL_GameController *m_pad = NULL;

    unsigned char m_buf[256];
    unsigned char m_stdpar[10] = {0x00, 0x41, 0x5a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char m_mousepar[8] = {0x00, 0x12, 0x5a, 0xff, 0xff, 0xff, 0xff};
    unsigned char m_analogpar[9] = {0x00, 0xff, 0x5a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    int m_bufcount, m_bufc; 
public:
    static bool configuringButton; // are we configuring a button in the GUI?
    static int configuredButtonIndex; // Which button are we configuring in the GUI?
    static bool save; // do we need to save?

    // settings block
    typedef Setting<int, TYPESTRING("Pad1Up"), GLFW_KEY_UP> Pad1Up;
    typedef Setting<int, TYPESTRING("Pad1Right"), GLFW_KEY_RIGHT> Pad1Right;
    typedef Setting<int, TYPESTRING("Pad1Down"), GLFW_KEY_DOWN> Pad1Down;
    typedef Setting<int, TYPESTRING("Pad1Left"), GLFW_KEY_LEFT> Pad1Left;
    typedef Setting<int, TYPESTRING("Pad1Cross"), GLFW_KEY_X> Pad1Cross;
    typedef Setting<int, TYPESTRING("Pad1Triangle"), GLFW_KEY_S> Pad1Triangle;
    typedef Setting<int, TYPESTRING("Pad1Square"), GLFW_KEY_Z> Pad1Square;
    typedef Setting<int, TYPESTRING("Pad1Circle"), GLFW_KEY_D> Pad1Circle;
    typedef Setting<int, TYPESTRING("Pad1Select"), GLFW_KEY_BACKSPACE> Pad1Select;
    typedef Setting<int, TYPESTRING("Pad1Sstart"), GLFW_KEY_ENTER> Pad1Start;
    typedef Setting<int, TYPESTRING("Pad1L1"), GLFW_KEY_Q> Pad1L1;
    typedef Setting<int, TYPESTRING("Pad1L2"), GLFW_KEY_A> Pad1L2;
    typedef Setting<int, TYPESTRING("Pad1R1"), GLFW_KEY_R> Pad1R1;
    typedef Setting<int, TYPESTRING("Pad1R2"), GLFW_KEY_F> Pad1R2;

    typedef Setting<int, TYPESTRING("Pad2Up"), GLFW_KEY_UP> Pad2Up;
    typedef Setting<int, TYPESTRING("Pad2Right"), GLFW_KEY_RIGHT> Pad2Right;
    typedef Setting<int, TYPESTRING("Pad2Down"), GLFW_KEY_DOWN> Pad2Down;
    typedef Setting<int, TYPESTRING("Pad2Left"), GLFW_KEY_LEFT> Pad2Left;
    typedef Setting<int, TYPESTRING("Pad2Cross"), GLFW_KEY_X> Pad2Cross;
    typedef Setting<int, TYPESTRING("Pad2Triangle"), GLFW_KEY_S> Pad2Triangle;
    typedef Setting<int, TYPESTRING("Pad2Square"), GLFW_KEY_Z> Pad2Square;
    typedef Setting<int, TYPESTRING("Pad2Circle"), GLFW_KEY_D> Pad2Circle;
    typedef Setting<int, TYPESTRING("Pad2Select"), GLFW_KEY_BACKSPACE> Pad2Select;
    typedef Setting<int, TYPESTRING("Pad2Sstart"), GLFW_KEY_ENTER> Pad2Start;
    typedef Setting<int, TYPESTRING("Pad2L1"), GLFW_KEY_Q> Pad2L1;
    typedef Setting<int, TYPESTRING("Pad2L2"), GLFW_KEY_A> Pad2L2;
    typedef Setting<int, TYPESTRING("Pad2R1"), GLFW_KEY_R> Pad2R1;
    typedef Setting<int, TYPESTRING("Pad2R2"), GLFW_KEY_F> Pad2R2;
    typedef Setting<pad_config_option_t, TYPESTRING("SelectedPad"), Pad1_Keyboard> SettingSelectedPad;

    static Settings<Pad1Up, Pad1Right, Pad1Down, Pad1Left, Pad1Cross, Pad1Triangle, Pad1Square, Pad1Circle, Pad1Select, Pad1Start, Pad1L1, Pad1L2, Pad1R1, Pad1R2,
                    Pad2Up, Pad2Right, Pad2Down, Pad2Left, Pad2Cross, Pad2Triangle, Pad2Square, Pad2Circle, Pad2Select, Pad2Start, Pad2L1, Pad2L2, Pad2R1, Pad2R2,
                    SettingSelectedPad> settings;
};

}  // namespace PCSX
