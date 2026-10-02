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

// A pad object as written by a GLFW-era build with the stock bindings.
static json glfwEraPad() {
    return json::parse(R"({
        "Keyboard_PadUp": 265, "Keyboard_PadRight": 262, "Keyboard_PadDown": 264, "Keyboard_PadLeft": 263,
        "Keyboard_PadCross": 88, "Keyboard_PadTriangle": 83, "Keyboard_PadSquare": 90, "Keyboard_PadCircle": 68,
        "Keyboard_PadSelect": 259, "Keyboard_PadSstart": 257, "Keyboard_PadL1": 81, "Keyboard_PadL2": 65,
        "Keyboard_PadL3": 87, "Keyboard_PadR1": 82, "Keyboard_PadR2": 70, "Keyboard_PadR3": 84,
        "Keyboard_AnalogMode": -1, "Controller_PadCross": 0, "DeviceType": 1, "Connected": true
    })");
}

TEST(PadGlfwMigration, StockBindings) {
    json pad = glfwEraPad();
    EXPECT_TRUE(PCSX::Pads::migrateGlfwKeyboardBindings(pad));
    EXPECT_EQ(pad["Keyboard_PadCross"], SDL_SCANCODE_X);
    EXPECT_EQ(pad["Keyboard_PadUp"], SDL_SCANCODE_UP);
    EXPECT_EQ(pad["Keyboard_PadRight"], SDL_SCANCODE_RIGHT);
    EXPECT_EQ(pad["Keyboard_PadDown"], SDL_SCANCODE_DOWN);
    EXPECT_EQ(pad["Keyboard_PadLeft"], SDL_SCANCODE_LEFT);
    EXPECT_EQ(pad["Keyboard_PadTriangle"], SDL_SCANCODE_S);
    EXPECT_EQ(pad["Keyboard_PadSquare"], SDL_SCANCODE_Z);
    EXPECT_EQ(pad["Keyboard_PadCircle"], SDL_SCANCODE_D);
    EXPECT_EQ(pad["Keyboard_PadSelect"], SDL_SCANCODE_BACKSPACE);
    EXPECT_EQ(pad["Keyboard_PadSstart"], SDL_SCANCODE_RETURN);
    EXPECT_EQ(pad["Keyboard_PadL1"], SDL_SCANCODE_Q);
    EXPECT_EQ(pad["Keyboard_PadL2"], SDL_SCANCODE_A);
    EXPECT_EQ(pad["Keyboard_PadL3"], SDL_SCANCODE_W);
    EXPECT_EQ(pad["Keyboard_PadR1"], SDL_SCANCODE_R);
    EXPECT_EQ(pad["Keyboard_PadR2"], SDL_SCANCODE_F);
    EXPECT_EQ(pad["Keyboard_PadR3"], SDL_SCANCODE_T);
    EXPECT_EQ(pad["Keyboard_AnalogMode"], SDL_SCANCODE_UNKNOWN);
    // Non-keyboard entries are left alone.
    EXPECT_EQ(pad["Controller_PadCross"], 0);
    EXPECT_EQ(pad["DeviceType"], 1);
    // Running it again is a no-op since AnalogMode no longer holds the GLFW sentinel.
    json again = pad;
    EXPECT_FALSE(PCSX::Pads::migrateGlfwKeyboardBindings(again));
    EXPECT_EQ(again, pad);
}

TEST(PadGlfwMigration, UnmappableKeysBecomeUnbound) {
    json pad = glfwEraPad();
    pad["Keyboard_PadL1"] = 341;  // GLFW_KEY_LEFT_CONTROL
    pad["Keyboard_PadL2"] = 334;  // GLFW_KEY_KP_ADD
    pad["Keyboard_PadR1"] = 96;   // GLFW_KEY_GRAVE_ACCENT
    pad["Keyboard_PadR2"] = 161;  // GLFW_KEY_WORLD_1, never handled
    pad["Keyboard_PadR3"] = -1;   // GLFW_KEY_UNKNOWN
    pad["Keyboard_PadUp"] = "junk";
    EXPECT_TRUE(PCSX::Pads::migrateGlfwKeyboardBindings(pad));
    EXPECT_EQ(pad["Keyboard_PadL1"], SDL_SCANCODE_LCTRL);
    EXPECT_EQ(pad["Keyboard_PadL2"], SDL_SCANCODE_KP_PLUS);
    EXPECT_EQ(pad["Keyboard_PadR1"], SDL_SCANCODE_GRAVE);
    EXPECT_EQ(pad["Keyboard_PadR2"], SDL_SCANCODE_UNKNOWN);
    EXPECT_EQ(pad["Keyboard_PadR3"], SDL_SCANCODE_UNKNOWN);
    EXPECT_EQ(pad["Keyboard_PadUp"], SDL_SCANCODE_UNKNOWN);
}

TEST(PadGlfwMigration, PreAnalogModeFile) {
    // Configs written before the analog mode binding existed lack the key entirely.
    json pad = glfwEraPad();
    pad.erase("Keyboard_AnalogMode");
    EXPECT_TRUE(PCSX::Pads::migrateGlfwKeyboardBindings(pad));
    EXPECT_EQ(pad["Keyboard_PadCross"], SDL_SCANCODE_X);
    EXPECT_EQ(pad["Keyboard_AnalogMode"], SDL_SCANCODE_UNKNOWN);
}

TEST(PadGlfwMigration, SdlEraUntouched) {
    json pad = json::parse(R"({"Keyboard_PadCross": 27, "Keyboard_PadUp": 82, "Keyboard_AnalogMode": 0})");
    json orig = pad;
    EXPECT_FALSE(PCSX::Pads::migrateGlfwKeyboardBindings(pad));
    EXPECT_EQ(pad, orig);
    pad["Keyboard_AnalogMode"] = SDL_SCANCODE_M;
    orig = pad;
    EXPECT_FALSE(PCSX::Pads::migrateGlfwKeyboardBindings(pad));
    EXPECT_EQ(pad, orig);
    // Non-objects and empty objects are ignored.
    json empty = json::object();
    EXPECT_FALSE(PCSX::Pads::migrateGlfwKeyboardBindings(empty));
    json null;
    EXPECT_FALSE(PCSX::Pads::migrateGlfwKeyboardBindings(null));
}

TEST(PadGlfwMigration, TableCoverage) {
    EXPECT_EQ(PCSX::Pads::glfwKeyToSdlScancode(-1), SDL_SCANCODE_UNKNOWN);
    EXPECT_EQ(PCSX::Pads::glfwKeyToSdlScancode(32), SDL_SCANCODE_SPACE);
    EXPECT_EQ(PCSX::Pads::glfwKeyToSdlScancode(48), SDL_SCANCODE_0);
    EXPECT_EQ(PCSX::Pads::glfwKeyToSdlScancode(49), SDL_SCANCODE_1);
    EXPECT_EQ(PCSX::Pads::glfwKeyToSdlScancode(301), SDL_SCANCODE_F12);
    EXPECT_EQ(PCSX::Pads::glfwKeyToSdlScancode(320), SDL_SCANCODE_KP_0);
    EXPECT_EQ(PCSX::Pads::glfwKeyToSdlScancode(348), SDL_SCANCODE_MENU);
    EXPECT_EQ(PCSX::Pads::glfwKeyToSdlScancode(302), SDL_SCANCODE_UNKNOWN);  // GLFW_KEY_F13, never handled
    EXPECT_EQ(PCSX::Pads::glfwKeyToSdlScancode(100000), SDL_SCANCODE_UNKNOWN);
}
