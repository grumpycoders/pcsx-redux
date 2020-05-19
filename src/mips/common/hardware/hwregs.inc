/*

MIT License

Copyright (c) 2019 PCSX-Redux authors

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

.set SBUS_DEV0_ADDR,    0x1f801000
.set SBUS_DEV8_ADDR,    0x1f801004

.set SBUS_DEV0_CTRL,    0x1f801008
.set SBUS_DEV1_CTRL,    0x1f80100C
.set SBUS_DEV2_CTRL,    0x1f801010
.set SBUS_DEV4_CTRL,    0x1f801014
.set SBUS_DEV5_CTRL,    0x1f801018
.set SBUS_DEV8_CTRL,    0x1f80101C

.set SBUS_COM_CTRL,     0x1f801020

.set RAM_SIZE,          0x1f801060

.set BIU_CONFIG,        0xfffe0130
