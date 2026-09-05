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

// ENDX (1F801D9Ch/1D9Eh) drives a full latch -> key-on clear -> re-latch cycle with a
// second voice held as a control, and asserts its own verdict rather than printing one
// to be read by eye, so a non-zero exit here is a regression and not a diagnostic.
// Behaviour checked against an SCPH-1001. The interpreter is used because the SPU runs
// on its own thread, so some CPU/SPU jitter is expected; the dynarec widens it.
TEST(SPU, Endx) {
    MainInvoker invoker("-no-ui", "-run", "-bios", "src/mips/openbios/openbios.bin", "-testmode",
                        "-interpreter", "-loadexe", "src/mips/tests/spu-endx/spu-endx.ps-exe");
    int ret = invoker.invoke();
    EXPECT_EQ(ret, 0);
}

// Two things psx-spx documents about SPU IRQ9: the SPU disables its own interrupt when
// the address matches, and a voice keeps reading SPU RAM after it has been keyed off and
// its envelope has fallen to zero. The guest asserts both against a playing voice first,
// so a dead status flag cannot be mistaken for a silent voice that stopped reading.
TEST(SPU, OffVoiceIrq) {
    MainInvoker invoker("-no-ui", "-run", "-bios", "src/mips/openbios/openbios.bin", "-testmode",
                        "-interpreter", "-loadexe",
                        "src/mips/tests/spu-offvoice/spu-offvoice.ps-exe");
    int ret = invoker.invoke();
    EXPECT_EQ(ret, 0);
}
