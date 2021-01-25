/*

MIT License

Copyright (c) 2020 PCSX-Redux authors

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

#define MAKEIOCTL(c, s) ((c << 8 | s))

#define PSXFIOCNBLOCK MAKEIOCTL('f', 1)
#define PSXFIOCSCAN MAKEIOCTL('f', 2)

#define PSXTIOCRAW MAKEIOCTL('t', 1)
#define PSXTIOCFLUSH MAKEIOCTL('t', 2)
#define PSXTIOCREOPEN MAKEIOCTL('t', 3)
#define PSXTIOCBAUD MAKEIOCTL('t', 4)
#define PSXTIOCEXIT MAKEIOCTL('t', 5)
#define PSXTIOCDTR MAKEIOCTL('t', 6)
#define PSXTIOCRTS MAKEIOCTL('t', 7)
#define PSXTIOCLEN MAKEIOCTL('t', 8)
#define PSXTIOCPARITY MAKEIOCTL('t', 9)
#define PSXTIOSTATUS MAKEIOCTL('t', 10)
#define PSXTIOERRRST MAKEIOCTL('t', 11)
#define PSXTIOEXIST MAKEIOCTL('t', 12)
#define PSXTIORLEN MAKEIOCTL('t', 13)

#define PSXDIOFORMAT MAKEIOCTL('d', 1)
