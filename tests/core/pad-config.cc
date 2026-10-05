/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include <SDL3/SDL_scancode.h>

#include "core/pad.h"
#include "gtest/gtest.h"

// The "pads" section of the config attached to issue #2094, written by a GLFW build.
static const char* c_glfwPads = R"json([
    {
        "Connected": true,
        "Controller_PadCircle": 1,
        "Controller_PadCross": 0,
        "Controller_PadDown": 13,
        "Controller_PadL1": 4,
        "Controller_PadL2": 15,
        "Controller_PadL3": 9,
        "Controller_PadLeft": 14,
        "Controller_PadR1": 5,
        "Controller_PadR2": 16,
        "Controller_PadR3": 10,
        "Controller_PadRight": 12,
        "Controller_PadSelect": 6,
        "Controller_PadSquare": 2,
        "Controller_PadSstart": 7,
        "Controller_PadTriangle": 3,
        "Controller_PadUp": 11,
        "DeviceType": 1,
        "ID": 0,
        "Keyboard_AnalogMode": 256,
        "Keyboard_PadCircle": 68,
        "Keyboard_PadCross": 88,
        "Keyboard_PadDown": 264,
        "Keyboard_PadL1": 81,
        "Keyboard_PadL2": 65,
        "Keyboard_PadL3": 87,
        "Keyboard_PadLeft": 263,
        "Keyboard_PadR1": 82,
        "Keyboard_PadR2": 70,
        "Keyboard_PadR3": 84,
        "Keyboard_PadRight": 262,
        "Keyboard_PadSelect": 92,
        "Keyboard_PadSquare": 90,
        "Keyboard_PadSstart": 257,
        "Keyboard_PadTriangle": 83,
        "Keyboard_PadUp": 265,
        "MouseSensitivityX": 0.5,
        "MouseSensitivityY": 0.5,
        "PadType": 2
    },
    {
        "Connected": false,
        "Controller_PadCircle": 1,
        "Controller_PadCross": 0,
        "Controller_PadDown": 13,
        "Controller_PadL1": 4,
        "Controller_PadL2": 15,
        "Controller_PadL3": 9,
        "Controller_PadLeft": 14,
        "Controller_PadR1": 5,
        "Controller_PadR2": 16,
        "Controller_PadR3": 10,
        "Controller_PadRight": 12,
        "Controller_PadSelect": 6,
        "Controller_PadSquare": 2,
        "Controller_PadSstart": 7,
        "Controller_PadTriangle": 3,
        "Controller_PadUp": 11,
        "DeviceType": 0,
        "ID": 0,
        "Keyboard_AnalogMode": -1,
        "Keyboard_PadCircle": 68,
        "Keyboard_PadCross": 88,
        "Keyboard_PadDown": 264,
        "Keyboard_PadL1": 81,
        "Keyboard_PadL2": 65,
        "Keyboard_PadL3": 87,
        "Keyboard_PadLeft": 263,
        "Keyboard_PadR1": 82,
        "Keyboard_PadR2": 70,
        "Keyboard_PadR3": 84,
        "Keyboard_PadRight": 262,
        "Keyboard_PadSelect": 259,
        "Keyboard_PadSquare": 90,
        "Keyboard_PadSstart": 257,
        "Keyboard_PadTriangle": 83,
        "Keyboard_PadUp": 265,
        "MouseSensitivityX": 0.5,
        "MouseSensitivityY": 0.5,
        "PadType": 1
    }
])json";

TEST(PadConfig, MigratesGlfwKeys) {
    auto pads = nlohmann::json::parse(c_glfwPads);
    auto& pad = pads[0];
    EXPECT_TRUE(PCSX::Pads::migrateKeyboardBindings(pad));
    EXPECT_EQ(pad["KeyboardBindingsVersion"], 1);
    EXPECT_EQ(pad["Keyboard_PadUp"], SDL_SCANCODE_UP);
    EXPECT_EQ(pad["Keyboard_PadRight"], SDL_SCANCODE_RIGHT);
    EXPECT_EQ(pad["Keyboard_PadDown"], SDL_SCANCODE_DOWN);
    EXPECT_EQ(pad["Keyboard_PadLeft"], SDL_SCANCODE_LEFT);
    EXPECT_EQ(pad["Keyboard_PadCross"], SDL_SCANCODE_X);
    EXPECT_EQ(pad["Keyboard_PadTriangle"], SDL_SCANCODE_S);
    EXPECT_EQ(pad["Keyboard_PadSquare"], SDL_SCANCODE_Z);
    EXPECT_EQ(pad["Keyboard_PadCircle"], SDL_SCANCODE_D);
    EXPECT_EQ(pad["Keyboard_PadSelect"], SDL_SCANCODE_BACKSLASH);
    EXPECT_EQ(pad["Keyboard_PadSstart"], SDL_SCANCODE_RETURN);
    EXPECT_EQ(pad["Keyboard_PadL1"], SDL_SCANCODE_Q);
    EXPECT_EQ(pad["Keyboard_PadL2"], SDL_SCANCODE_A);
    EXPECT_EQ(pad["Keyboard_PadL3"], SDL_SCANCODE_W);
    EXPECT_EQ(pad["Keyboard_PadR1"], SDL_SCANCODE_R);
    EXPECT_EQ(pad["Keyboard_PadR2"], SDL_SCANCODE_F);
    EXPECT_EQ(pad["Keyboard_PadR3"], SDL_SCANCODE_T);
    EXPECT_EQ(pad["Keyboard_AnalogMode"], SDL_SCANCODE_ESCAPE);
    EXPECT_EQ(pad["Controller_PadUp"], 11);

    auto& pad2 = pads[1];
    EXPECT_TRUE(PCSX::Pads::migrateKeyboardBindings(pad2));
    EXPECT_EQ(pad2["Keyboard_PadSelect"], SDL_SCANCODE_BACKSPACE);
    EXPECT_EQ(pad2["Keyboard_AnalogMode"], SDL_SCANCODE_UNKNOWN);

    EXPECT_FALSE(PCSX::Pads::migrateKeyboardBindings(pad));
    EXPECT_EQ(pad["Keyboard_PadUp"], SDL_SCANCODE_UP);
}

TEST(PadConfig, LeavesScancodesAlone) {
    // Unstamped config from an SDL build: default bindings, analog mode unbound.
    auto pads = nlohmann::json::parse(c_glfwPads);
    auto& pad = pads[0];
    PCSX::Pads::migrateKeyboardBindings(pad);
    pad.erase("KeyboardBindingsVersion");
    pad["Keyboard_AnalogMode"] = SDL_SCANCODE_UNKNOWN;
    auto before = pad;
    EXPECT_FALSE(PCSX::Pads::migrateKeyboardBindings(pad));
    pad.erase("KeyboardBindingsVersion");
    EXPECT_EQ(pad, before);

    // Stamped config: never touched, whatever the values look like.
    auto stamped = nlohmann::json::parse(c_glfwPads)[0];
    stamped["KeyboardBindingsVersion"] = 1;
    before = stamped;
    EXPECT_FALSE(PCSX::Pads::migrateKeyboardBindings(stamped));
    EXPECT_EQ(stamped, before);
}
