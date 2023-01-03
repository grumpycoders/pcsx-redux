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

#include "support/md5.h"
#include "support/uvfile.h"
#include "support/version.h"
#include "support/windowswrapper.h"
#include "support/zip.h"

bool PCSX::Update::canFullyApply() { return true; }

bool PCSX::Update::applyUpdate(const std::filesystem::path& binDir) {
    if (!m_hasUpdate) return false;
    auto tmp = std::filesystem::temp_directory_path();

    std::error_code ec;
    std::filesystem::remove(tmp / "pcsx-redux-update.started", ec);

    ZipArchive zip(m_download);
    if (zip.failed()) return false;
    IO<File> script(new PosixFile(tmp / "pcsx-redux-update.ps1", FileOps::TRUNCATE));
    if (script->failed()) return false;

    script->writeString("New-Item -Path \"");
    script->writeString(tmp.string());
    script->writeString("pcsx-redux-update.started\" -ItemType File | Out-Null\n");
    script->writeString("Write-Host \"Waiting for PCSX-Redux to close in order to self-update...\"\n");
    script->writeString("Wait-Process -Id ");
    script->writeString(std::to_string(GetCurrentProcessId()));
    script->writeString(" -ErrorAction SilentlyContinue\n");
    script->writeString("Remove-Item -Path \"");
    script->writeString(tmp.string());
    script->writeString("pcsx-redux-update.started\"\n");
    script->writeString("$Confirmation = Read-Host -Prompt \"Proceed with the upgrade (y/n)?\"\n");
    script->writeString("if ($Confirmation -ne \"y\") {\n");
    script->writeString("    Write-Host \"Cancelling update.\"\n");
    script->writeString("    exit 1\n");
    script->writeString("}\n");
    script->writeString("Write-Host \"Self-updating...\"\n");

    zip.listAllDirectories([&script, &binDir](const std::string_view& name) {
        script->writeString("New-Item -Force -Path \"");
        script->writeString(binDir.string());
        script->writeString("\" -Name \"");
        script->writeString(name);
        script->writeString("\" -ItemType \"directory\"");
        script->writeString("\n");
    });

    script->writeString("$failed = $False\n");

    unsigned count = 0;
    zip.listAllFiles([&zip, &script, &tmp, &binDir, &count](const std::string_view& name) {
        auto filename = tmp / ("pcsx-update-file-" + std::to_string(count++) + ".tmp");
        IO<File> out(new UvFile(filename, FileOps::TRUNCATE));
        IO<File> in(zip.openFile(name));
        Slice data = in->read(in->size());
        uint8_t digest[16];
        MD5 md5;
        md5.update(data);
        md5.finish(digest);
        out->write(std::move(data));
        script->writeString("$expectedhash = \"");
        for (unsigned i = 0; i < 16; i++) {
            script->writeString(fmt::format("{:02X}", digest[i]));
        }
        script->writeString("\"\n");
        script->writeString("$filehash = Get-FileHash -Algorithm MD5 -Path \"");
        script->writeString(filename.string());
        script->writeString("\"\n");
        script->writeString("if (-not ($filehash.Hash -eq $expectedhash)) {\n");
        script->writeString("    Write-Host \"Error: file hash mismatch for ");
        script->writeString(name);
        script->writeString("\"\n");
        script->writeString("    $failed = $True\n");
        script->writeString("}\n");
    });

    script->writeString("if ($failed) {\n");
    script->writeString("    Write-Host \"Corruption detected, cancelling update.\"\n");
    script->writeString("    Write-Host \"Retry the update, or download from website.\"\n");
    script->writeString("    Read-Host -Prompt \"Press Enter to exit\"\n");
    script->writeString("    exit 1\n");
    script->writeString("}\n");

    count = 0;
    zip.listAllFiles([&zip, &script, &tmp, &binDir, &count](const std::string_view& name) {
        auto filename = tmp / ("pcsx-update-file-" + std::to_string(count++) + ".tmp");
        script->writeString("Copy-Item -Force -Path \"");
        script->writeString(filename.string());
        script->writeString("\" -Destination \"");
        script->writeString((binDir / name).string());
        script->writeString("\"\n");
        script->writeString("Remove-Item -Path \"");
        script->writeString(filename.string());
        script->writeString("\"\n");
    });

    script->writeString("Set-Location -Path \"");
    script->writeString(binDir.string());
    script->writeString("\"\n");

    script->writeString("Start-Process -FilePath \"pcsx-redux.exe\"\n");

    script->close();

    std::string cmd;
    cmd = "cmd.exe /c powershell.exe -ExecutionPolicy Bypass -file ";
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

    while (!std::filesystem::exists(tmp / "pcsx-redux-update.started"))
        ;

    return true;
}

#endif
