/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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

#include <stdio.h>

#include <stdexcept>
#include <string>
#include <utility>

#include "main/main.h"

static std::pair<int, std::string> loopMain(int argc, char **argv) {
    int r = 0;
    std::string errorMsg;
    do {
        try {
            r = pcsxMain(argc, argv);
        } catch (std::exception &e) {
            errorMsg = e.what();
            r = -1;
        } catch (...) {
            errorMsg = "An unknown exception occured.";
            r = -1;
        }
    } while (r == 0x12eb007);

    return {r, errorMsg};
}

#if defined(_WIN32) || defined(_WIN64)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
// Please, clang-format, stop being stubborn and let this windows.h
// header first. Yes, I know it's wrong, blame Microsoft.
#include <shellapi.h>

static void Complain(const char *msg) { MessageBoxA(nullptr, msg, "Error", MB_ICONERROR | MB_OK); }

#ifndef PCSX_CLI
int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine,
                      _In_ int nCmdShow) {
    LPWSTR *argvw;
    char **argv;
    int argc;

    argvw = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argvw) return -1;
    argv = (char **)calloc(argc + 1, sizeof(*argv));
    if (!argv) return -1;
    for (int i = 0; i < argc; i++) {
        int needed;
        char *str;

        needed = WideCharToMultiByte(CP_UTF8, 0, argvw[i], -1, NULL, 0, NULL, NULL);
        if (needed <= 0) {
            argv[i] = nullptr;
            continue;
        }
        str = (char *)calloc(needed, sizeof(char));
        WideCharToMultiByte(CP_UTF8, 0, argvw[i], -1, reinterpret_cast<LPSTR>(str), needed, NULL, NULL);
        argv[i] = str;
    }
    argv[argc] = nullptr;
    LocalFree(argvw);

    auto [r, errorMsg] = loopMain(argc, argv);

    if (!errorMsg.empty()) {
        r = -1;
        fprintf(stderr, "%s\n", errorMsg.c_str());
        Complain(errorMsg.c_str());
    }

    for (int i = 0; i < argc; i++) free(argv[i]);
    free(argv);
    return r;
}
#endif
#else
#ifndef PCSX_CLI
#if defined(__APPLE__) && defined(__MACH__)
extern "C" void Complain(const char* msg);
#else
#include <X11/Xlib.h>
#include <stdlib.h>
#include <string.h>

static void Complain(const char* msg) {
    Display* d = XOpenDisplay(nullptr);
    if (!d) return;

    int s = DefaultScreen(d);
    Window w = XCreateSimpleWindow(d, RootWindow(d, s), 10, 10, 600, 100, 1, BlackPixel(d, s), WhitePixel(d, s));
    XSelectInput(d, w, ExposureMask | KeyPressMask);
    XMapWindow(d, w);

    XEvent e;
    while (1) {
        XNextEvent(d, &e);
        if (e.type == Expose) {
            XDrawString(d, w, DefaultGC(d, s), 10, 10, msg, strlen(msg));
        }
        if (e.type == KeyPress) break;
    }

    XCloseDisplay(d);
    return;
}
#endif
#endif
#endif

#if (!defined(_WIN32) && !defined(_WIN64)) || defined(PCSX_CLI)
int main(int argc, char **argv) {
    auto [r, errorMsg] = loopMain(argc, argv);

    if (errorMsg.empty()) return r;

    fprintf(stderr, "%s\n", errorMsg.c_str());

    Complain(errorMsg.c_str());

    return -1;
}
#endif
