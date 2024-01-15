/*

MIT License

Copyright (c) 2023 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#pragma once

#include "psyqo/hardware/hwregs.hh"

namespace psyqo::Hardware::CDRom {

enum class CDL : uint8_t {
    SYNC = 0,
    NOP = 1,
    SETLOC = 2,
    PLAY = 3,
    FORWARD = 4,
    BACKWARD = 5,
    READN = 6,
    STANDBY = 7,
    STOP = 8,
    PAUSE = 9,
    INIT = 10,
    MUTE = 11,
    DEMUTE = 12,
    SETFILTER = 13,
    SETMODE = 14,
    GETMODE = 15,
    GETLOCL = 16,
    GETLOCP = 17,
    READT = 18,
    GETTN = 19,
    GETTD = 20,
    SEEKL = 21,
    SEEKP = 22,
    SETCLOCK = 23,
    GETCLOCK = 24,
    TEST = 25,
    GETID = 26,
    READS = 27,
    RESET = 28,
    GETQ = 29,
    READTOC = 30,
};

extern Hardware::Register<0x0800, uint8_t, WriteQueue::Bypass> Ctrl;
extern Hardware::Register<0x0801, uint8_t, WriteQueue::Bypass> Response;
extern Hardware::Register<0x0802, uint8_t, WriteQueue::Bypass> Fifo;
extern Hardware::Register<0x0803, uint8_t, WriteQueue::Bypass> InterruptControl;

template <typename Reg, unsigned m>
struct Access {
    static volatile uint8_t& access(int index = 0) {
        Ctrl = m;
        return Reg::access(index);
    }
};

struct CommandFifo {
    void send(CDL cmd) {
        Ctrl = 0;
        Response = static_cast<uint8_t>(cmd);
    }
    template <typename... Args>
    void send(CDL cmd, Args... args) {
        Ctrl = 0;
        recursiveSend(args...);
        Response = static_cast<uint8_t>(cmd);
    }

  private:
    void recursiveSend(uint8_t arg) { Fifo = arg; }
    template <typename... Args>
    void recursiveSend(uint8_t arg, Args... args) {
        Fifo = arg;
        recursiveSend(args...);
    }
};

extern CommandFifo Command;
extern Register<0, uint8_t, WriteQueue::Bypass, Access<BasicAccess<0x0803, 0xbf801000, uint8_t>, 0>> DataRequest;
extern Register<0, uint8_t, WriteQueue::Bypass, Access<BasicAccess<0x0802, 0xbf801000, uint8_t>, 1>> CauseMask;
extern Register<0, uint8_t, WriteQueue::Bypass, Access<BasicAccess<0x0803, 0xbf801000, uint8_t>, 1>> Cause;

}  // namespace psyqo::Hardware::CDRom
