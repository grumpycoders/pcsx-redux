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

// This file isn't to be compiled directly. It's to be included in every
// sub test .c file that requires access to the exception handler test system.

// clang-format off

CESTER_BODY(
    static int s_got40;
    static int s_got80;
    static uint32_t s_cause;
    static uint32_t s_epc;
    static uint32_t s_from;
    static uint32_t * s_resume;
    static uint32_t * s_regs;
    static void (*s_customhandler)() = NULL;
    uint32_t handler(uint32_t * regs, uint32_t from) {
        if (from == 0x40) s_got40 = 1;
        if (from == 0x80) s_got80 = 1;

        uint32_t cause;
        uint32_t epc;

        s_from = from;

        asm("mfc0 %0, $13\nnop\nmfc0 %1, $14\nnop" : "=r"(cause), "=r"(epc));

        s_cause = cause;
        s_epc = epc;

        if (s_customhandler) s_customhandler();

        return s_resume ? ((uint32_t)s_resume) : (epc + 4);
    }
    void installExceptionHandlers(uint32_t (*handler)(uint32_t * regs, uint32_t from));
    void uninstallExceptionHandlers();

    uint32_t branchbranch1();
    uint32_t branchbranch2();
    uint32_t jumpjump1();
    uint32_t jumpjump2();
    uint32_t cpu_LWR_LWL_half(uint32_t buff[], uint32_t initial);
    uint32_t cpu_LWR_LWL_nodelay(uint32_t buff[], uint32_t initial);
    uint32_t cpu_LWR_LWL_delayed(uint32_t buff[], uint32_t initial);
    uint32_t linkandload();
    uint32_t lwandlink();
    uint32_t nolink();

    static int s_interruptsWereEnabled;
)

CESTER_BEFORE_EACH(cpu_tests, testname, testindex,
    s_got40 = 0;
    s_got80 = 0;
    s_cause = 0;
    s_epc = 0;
    s_from = 0;
    s_resume = NULL;
    s_regs = NULL;
    s_customhandler = NULL;
)

CESTER_BEFORE_ALL(cpu_tests,
    s_interruptsWereEnabled = enterCriticalSection();
    installExceptionHandlers(handler);
    syscall_flushCache();
)

CESTER_AFTER_ALL(cpu_tests,
    uninstallExceptionHandlers();
    syscall_flushCache();
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

