/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#if defined(_WIN32) || defined(_WIN64)

#include "support/uvfile.h"
#include "support/version.h"
#include "support/windowswrapper.h"
#include "support/zip.h"

bool PCSX::Update::applyUpdate(const std::filesystem::path& binDir) {
    if (!m_hasUpdate) return false;
    auto tmp = std::filesystem::temp_directory_path();

    ZipArchive zip(m_download);
    if (zip.failed()) return false;
    IO<File> script(new PosixFile(tmp / "pcsx-redux-update.ps1", FileOps::TRUNCATE));
    if (script->failed()) return false;

    script->writeString("Write-Host \"Waiting for PCSX-Redux to close in order to self-update...\"\n");
    script->writeString("Wait-Process -Id ");
    script->writeString(std::to_string(GetCurrentProcessId()));
    script->writeString("\n");
    script->writeString("Write-Host \"Self-updating...\"\n");

    zip.listAllDirectories([&script, &binDir](const std::string_view& name) {
        script->writeString("New-Item -Force -Path \"");
        script->writeString(binDir.string());
        script->writeString("\" -Name \"");
        script->writeString(name);
        script->writeString("\" -ItemType \"directory\"");
        script->writeString("\n");
    });

    unsigned count = 0;
    zip.listAllFiles([&zip, &script, &tmp, &binDir, &count](const std::string_view& name) {
        IO<File> out(new UvFile(tmp / ("pcsx-update-file-" + std::to_string(count++) + ".tmp"), FileOps::TRUNCATE));
        IO<File> in(zip.openFile(name));
        Slice data = in->read(in->size());
        out->write(std::move(data));
        script->writeString("Move-Item -Force -Path \"");
        script->writeString(out->filename().string());
        script->writeString("\" -Destination \"");
        script->writeString((binDir / name).string());
        script->writeString("\"\n");
    });

    script->writeString("Set-Location -Path \"");
    script->writeString(binDir.string());
    script->writeString("\"\n");

    script->writeString("Start-Process -FilePath \"pcsx-redux.exe\"\n");

    script->close();

    std::string cmd;
    cmd = "cmd.exe /c powershell.exe -ExecutionPolicy Bypass -windowstyle hidden -file ";
    cmd += (tmp / "pcsx-redux-update.ps1").string();
#ifdef UNICODE
    int needed;
    wchar_t* str;

    needed = MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), -1, nullptr, 0);
    if (needed <= 0) return false;
    str = (wchar_t*)_malloca(needed * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, cmd.c_str(), -1, str, needed);
#else
    char* str = cmd.c_str();
#endif
    PROCESS_INFORMATION processInformation = {0};
    STARTUPINFO startupInfo = {0};
    CreateProcess(NULL, str, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &startupInfo, &processInformation);

#ifdef UNICODE
    _freea(str);
#endif

    return true;
}

#endif
