/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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

// PSYQo unit test suite using snitch.
// Runs on the PlayStation 1 via pcsx-redux.
// Output goes through the BIOS TTY (captured by --stdout).

#include "common/hardware/pcsxhw.h"
#include "common/syscalls/syscalls.h"

#include "snitch_all.hpp"

static void psyqo_console_print(std::string_view message) noexcept {
    for (char c : message) {
        syscall_putchar(c);
    }
}

int main() {
    snitch::cli::console_print = &psyqo_console_print;
    snitch::tests.print_callback = &psyqo_console_print;

    bool success = snitch::tests.run_tests("psyqo");

    if (success) {
        ramsyscall_printf("All tests passed!\n");
    } else {
        ramsyscall_printf("Some tests FAILED!\n");
    }

    // Signal to the emulator via exit code.
    pcsx_exit(success ? 0 : 1);
    return success ? 0 : 1;
}
