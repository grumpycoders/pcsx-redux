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

#include <cstdlib>

#include "gtest/gtest.h"
#include "support/uvfile.h"

// An emergency exit skips joining the uv thread; process exit must still be
// clean, with no std::terminate from the static std::thread's destructor.
TEST(UvThread, EmergencyExitDoesNotTerminate) {
    // Earlier tests leave threads behind, and a forked child of a threaded process can hang or crash.
    testing::FLAGS_gtest_death_test_style = "threadsafe";
    EXPECT_EXIT(
        {
            {
                PCSX::UvThreadOp::UvThread uvThread;
                uvThread.setEmergencyExit();
            }
            std::exit(0);
        },
        testing::ExitedWithCode(0), "");
}
