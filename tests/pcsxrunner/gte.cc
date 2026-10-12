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

TEST(GTE, Interpreter) {
    MainInvoker invoker("-no-ui", "-run", "-bios", "src/mips/openbios/openbios.bin", "-testmode", "-interpreter",
                        "-luacov", "-loadexe", "src/mips/tests/gte/gte.ps-exe");
    int ret = invoker.invoke();
    EXPECT_EQ(ret, 0);
}

TEST(GTE, Dynarec) {
    MainInvoker invoker("-no-ui", "-run", "-bios", "src/mips/openbios/openbios.bin", "-testmode", "-dynarec",
                        "-luacov", "-loadexe", "src/mips/tests/gte/gte.ps-exe");
    int ret = invoker.invoke();
    EXPECT_EQ(ret, 0);
}

// A GTE register write still in flight survives a save state. Code poked into RAM queues
// MTC2 IR1 in the delay slot of a register jump, which ends a dynarec block, and reads it back
// three instructions later, storing to 0x80100100 on a mismatch. The state is saved at a vsync
// where the write has not landed, then loaded again; the readback must still match.
static const char c_pendingWriteSaveState[] = R"(
local ram = ffi.cast('uint32_t*', PCSX.getMemPtr())
local base = 0x100000 / 4
local out = 0x100100 / 4
local code = {
    -- 0x80100000: toggle t0, jr t2 with MTC2 t0, IR1 in the delay slot
    0x39080001, 0x01400008, 0x48884800, 0x00000000,
    -- 0x80100010: MFC2 t1, IR1 three instructions after the write, loop if it matches
    0x00000000, 0x00000000, 0x48094800, 0x00000000,
    0x15280004, 0x00000000, 0x08040000, 0x00000000,
    -- 0x80100034: mismatch, store t0 to 0x80100100 forever
    0x00000000, 0x3c0a8010, 0xad480100, 0x0804000d, 0x00000000,
}
local sentinel = 0xdeadbeef
local frames, state, saveFrame, tries = 0, nil, nil, 0
GtePendingListener = PCSX.Events.createEventListener('GPU::Vsync', function()
    frames = frames + 1
    local r = PCSX.getRegisters()
    if frames == 120 then
        for i, w in ipairs(code) do ram[base + i - 1] = w end
        ram[out] = sentinel
        r.GPR.n.t0 = 0x10
        r.GPR.n.t2 = 0x80100010
        r.pc = 0x80100000
    elseif frames > 121 and not state then
        tries = tries + 1
        if ram[out] ~= sentinel then PCSX.quit(4) return end
        if r.CP2D.r[9] ~= r.GPR.n.t0 then
            state = PCSX.createSaveState()
            saveFrame = frames
        elseif tries > 300 then PCSX.quit(5) return end
    elseif state and frames == saveFrame + 1 then
        PCSX.loadSaveState(state)
    elseif state and frames == saveFrame + 4 then
        if ram[out] == sentinel then PCSX.quit(0) else PCSX.quit(1) end
    end
end)
)";

TEST(GTE, PendingWriteSaveState) {
    MainInvoker invoker("-no-ui", "-run", "-bios", "src/mips/openbios/openbios.bin", "-testmode", "-interpreter",
                        "-exec", c_pendingWriteSaveState);
    int ret = invoker.invoke();
    EXPECT_EQ(ret, 0);
}

TEST(GTE, PendingWriteSaveStateDynarec) {
    MainInvoker invoker("-no-ui", "-run", "-bios", "src/mips/openbios/openbios.bin", "-testmode", "-dynarec",
                        "-exec", c_pendingWriteSaveState);
    int ret = invoker.invoke();
    EXPECT_EQ(ret, 0);
}

// MFC2 and CFC2 whose destination is read by the next instruction. That instruction sees the
// old value, and the cop2 value must land after it.
static const char c_cop2LoadDelay[] = R"(
local ram = ffi.cast('uint32_t*', PCSX.getMemPtr())
local base = 0x100000 / 4
local out = 0x100100 / 4
local code = {
    -- 0x80100000: t1 = 0x55, IR1 = 0x1234, MFC2 t1 <- IR1 with t1 read in the load delay slot
    0x34090055, 0x34081234, 0x48884800, 0x00000000, 0x00000000, 0x00000000,
    0x48094800, 0x01205021,
    -- t3 = 0x66, R11R12 = 0x1234, CFC2 t3 <- R11R12 with t3 read in the load delay slot
    0x340b0066, 0x48c80000, 0x00000000, 0x00000000, 0x00000000,
    0x484b0000, 0x01606021, 0x00000000,
    -- store t1..t4 to 0x80100100 and spin
    0x3c0d8010, 0xada90100, 0xadaa0104, 0xadab0108, 0xadac010c, 0x08040015, 0x00000000,
}
local frames = 0
Cop2DelayListener = PCSX.Events.createEventListener('GPU::Vsync', function()
    frames = frames + 1
    if frames == 120 then
        for i, w in ipairs(code) do ram[base + i - 1] = w end
        for i = 0, 3 do ram[out + i] = 0xdeadbeef end
        PCSX.getRegisters().pc = 0x80100000
    elseif frames == 123 then
        if ram[out] == 0x1234 and ram[out + 1] == 0x55 and ram[out + 2] == 0x1234 and ram[out + 3] == 0x66 then
            PCSX.quit(0)
        else
            PCSX.quit(1)
        end
    end
end)
)";

TEST(GTE, MoveFromLoadDelayInterpreter) {
    MainInvoker invoker("-no-ui", "-run", "-bios", "src/mips/openbios/openbios.bin", "-testmode", "-interpreter",
                        "-exec", c_cop2LoadDelay);
    int ret = invoker.invoke();
    EXPECT_EQ(ret, 0);
}

TEST(GTE, MoveFromLoadDelayDynarec) {
    MainInvoker invoker("-no-ui", "-run", "-bios", "src/mips/openbios/openbios.bin", "-testmode", "-dynarec",
                        "-exec", c_cop2LoadDelay);
    int ret = invoker.invoke();
    EXPECT_EQ(ret, 0);
}
