/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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

#include <assert.h>
#include <core/uv_wrapper.h>

void PCSX::UV::init() {
    int result = uv_loop_init(&m_loop);
    assert(result == 0);
}

void PCSX::UV::close() {
    int result = uv_loop_close(&m_loop);
    assert(result == 0);
}

void PCSX::UV::run() { uv_run(&m_loop, UV_RUN_NOWAIT); }

void PCSX::UV::purge(std::function<void()> purge) {
    if (purge) {
        do {
            purge();
        } while (uv_run(&m_loop, UV_RUN_NOWAIT));
        purge();
    } else {
        uv_run(&m_loop, UV_RUN_DEFAULT);
    }
}
