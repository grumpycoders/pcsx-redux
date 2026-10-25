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

#pragma once

#include <uv.h>

#include <chrono>
#include <thread>

#include "gtest/gtest.h"

// Owns a uv_loop_t for the duration of a scope. uv_loop_close returns EBUSY
// while any handle is still open or still closing, and ignoring that return
// leaks the loop's internals, so the destructor keeps pumping until it takes.
// Declare it before the objects that use it so they are destroyed first.
struct Loop : uv_loop_t {
    Loop() { EXPECT_EQ(uv_loop_init(this), 0); }
    Loop(const Loop&) = delete;
    Loop& operator=(const Loop&) = delete;
    ~Loop() {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(300);
        while (std::chrono::steady_clock::now() < deadline) {
            uv_run(this, UV_RUN_NOWAIT);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        int result = uv_loop_close(this);
        for (int i = 0; (i < 200) && (result == UV_EBUSY); i++) {
            uv_run(this, UV_RUN_NOWAIT);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            result = uv_loop_close(this);
        }
        EXPECT_EQ(result, 0);
    }
};
