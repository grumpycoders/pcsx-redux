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

#include "psyqo/hardware/cdrom.hh"

psyqo::Hardware::Register<0x0800, uint8_t, psyqo::Hardware::WriteQueue::Bypass> psyqo::Hardware::CDRom::Ctrl;
psyqo::Hardware::Register<0x0801, uint8_t, psyqo::Hardware::WriteQueue::Bypass> psyqo::Hardware::CDRom::Response;
psyqo::Hardware::Register<0x0802, uint8_t, psyqo::Hardware::WriteQueue::Bypass> psyqo::Hardware::CDRom::Fifo;
psyqo::Hardware::Register<0x0803, uint8_t, psyqo::Hardware::WriteQueue::Bypass> psyqo::Hardware::CDRom::InterruptControl;

psyqo::Hardware::CDRom::CommandFifo psyqo::Hardware::CDRom::Command;
psyqo::Hardware::Register<0, uint8_t, psyqo::Hardware::WriteQueue::Bypass, psyqo::Hardware::CDRom::Access<psyqo::Hardware::BasicAccess<0x0803, 0xbf801000, uint8_t>, 0>> psyqo::Hardware::CDRom::DataRequest;
psyqo::Hardware::Register<0, uint8_t, psyqo::Hardware::WriteQueue::Bypass, psyqo::Hardware::CDRom::Access<psyqo::Hardware::BasicAccess<0x0802, 0xbf801000, uint8_t>, 1>> psyqo::Hardware::CDRom::CauseMask;
psyqo::Hardware::Register<0, uint8_t, psyqo::Hardware::WriteQueue::Bypass, psyqo::Hardware::CDRom::Access<psyqo::Hardware::BasicAccess<0x0803, 0xbf801000, uint8_t>, 1>> psyqo::Hardware::CDRom::Cause;
