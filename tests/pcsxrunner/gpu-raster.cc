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

#include "gtest/gtest.h"
#include "main/main.h"

// The gpu-raster phase suites characterize the software GPU against
// hardware-captured truth values. Each phase binary is built with
// PCSX_TESTS=1 so probes that depend on uninitialized-VRAM boot
// junk on real silicon (and therefore can't be reproduced under
// emulation) are skipped via CESTER_MAYBE_TEST; everything else
// asserts. The software GPU is the only renderer being verified
// here.

#define GPU_RASTER_TEST(phase)                                                                            \
    TEST(GPURaster, Phase##phase) {                                                                       \
        MainInvoker invoker("-no-ui", "-run", "-bios", "src/mips/openbios/openbios.bin", "-testmode",     \
                            "-interpreter", "-loadexe",                                                   \
                            "src/mips/tests/gpu-raster-phase" #phase "/gpu-raster-phase" #phase           \
                            ".ps-exe");                                                                   \
        int ret = invoker.invoke();                                                                       \
        EXPECT_EQ(ret, 0);                                                                                \
    }

GPU_RASTER_TEST(1)
GPU_RASTER_TEST(2)
GPU_RASTER_TEST(3)
GPU_RASTER_TEST(4)
GPU_RASTER_TEST(5)
GPU_RASTER_TEST(6)
GPU_RASTER_TEST(7)
GPU_RASTER_TEST(8)
GPU_RASTER_TEST(9)
GPU_RASTER_TEST(10)
GPU_RASTER_TEST(11)
GPU_RASTER_TEST(12)
GPU_RASTER_TEST(13)
GPU_RASTER_TEST(14)
GPU_RASTER_TEST(15)
GPU_RASTER_TEST(16)
GPU_RASTER_TEST(17)
GPU_RASTER_TEST(18)
GPU_RASTER_TEST(19)
GPU_RASTER_TEST(20)
GPU_RASTER_TEST(21)
GPU_RASTER_TEST(22)
