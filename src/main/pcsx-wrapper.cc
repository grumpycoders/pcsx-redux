/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#ifdef _WIN32
#include <objbase.h>
#include <shlobj.h>
#include <shlwapi.h>

static void mymemzero(void* memory, int size) {
    BYTE* ptr = (BYTE*)memory;
    for (unsigned i = 0; i < size; i++) {
        *ptr++ = 0;
    }
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine,
                      _In_ int nCmdShow) {
    SHELLEXECUTEINFO sei;
    HMODULE h = LoadLibrary(L"vcruntime140.dll");

    if (!h) {
        int ret =
            MessageBox(NULL,
                       L"This device is missing required system DLLs to run this application, called the Microsoft "
                       L"Visual C++ Redistributable for Visual Studio 2019. Click Ok to get redirected to Microsoft's "
                       L"website to download the required package. Retry running this application after downloading "
                       L"and installing the package.",
                       L"Missing DLLs", MB_ICONERROR | MB_OKCANCEL | MB_DEFBUTTON1);
        if (ret == IDOK) {
            mymemzero(&sei, sizeof(sei));
            sei.cbSize = sizeof(sei);
            sei.lpVerb = L"open";
            sei.lpFile =
                L"https://support.microsoft.com/en-us/topic/"
                L"the-latest-supported-visual-c-downloads-2647da03-1eea-4433-9aff-95f26a218cc0";
            sei.nShow = SW_SHOWDEFAULT;
            ShellExecuteEx(&sei);
        }
        return 0;
    }

    FreeLibrary(h);
    TCHAR dir[1024];

    GetModuleFileName(NULL, dir, sizeof(dir) / sizeof(dir[0]));

    LPTSTR lastSlash = dir;
    for (LPTSTR p = dir; *p; p++) {
        if (*p == L'\\') {
            lastSlash = p + 1;
        }
    }

    TCHAR fname[] = L"pcsx-redux.main";
    for (unsigned i = 0; i < sizeof(fname) / sizeof(fname[0]); i++) {
        *lastSlash++ = fname[i];
    }

    mymemzero(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_CLASSNAME | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"open";
    sei.lpFile = dir;
    sei.lpClass = L"exefile";
    sei.lpParameters = lpCmdLine;
    sei.lpDirectory = NULL;
    sei.nShow = SW_SHOWDEFAULT;
    sei.hInstApp = NULL;

    BOOL res = ShellExecuteEx(&sei);

    if (res) {
        DWORD code = 0;
        WaitForSingleObject(sei.hProcess, INFINITE);
        GetExitCodeProcess(sei.hProcess, &code);
        return code;
    } else {
        DWORD error = GetLastError();
        MessageBox(NULL, L"An unknown error occured while trying to run this application.", L"Error",
                   MB_ICONERROR | MB_OK | MB_DEFBUTTON1);
    }

    return 1;
}
#endif
