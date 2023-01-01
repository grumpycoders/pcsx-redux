/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

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

#include "common/hardware/cdrom.h"
#include "common/hardware/dma.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/irq.h"
#include "common/syscalls/syscalls.h"

#undef unix
#define CESTER_NO_SIGNAL
#define CESTER_NO_TIME
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#include "exotic/cester.h"

#include "cester-hw.c"

#if 1
#include "cdlgetlocl.c"
#include "cdlgetlocp.c"
#include "cdlgettd.c"
#include "cdlgettn.c"
#include "cdlid.c"
#include "cdlinit.c"
#include "cdlnop.c"
#include "cdlreadn.c"
#include "cdlreads.c"
#include "cdlseekl.c"
#include "cdlseekp.c"
#include "cdlsetloc.c"
#include "cdlsetmode.c"
#include "cdltest.c"
#include "invalid.c"
#include "race.c"
#include "reading.c"
#else
#include "race.c"
#endif
