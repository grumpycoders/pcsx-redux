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

#include "core/kernel.h"
#include "core/r3000a.h"

static std::string fileFlagsToString(uint16_t flags) {
    std::string ret = " ";
    if (flags & 0x0001) ret += "READ ";
    if (flags & 0x0002) ret += "WRITE ";
    if (flags & 0x0004) ret += "NBLOCK ";
    if (flags & 0x0008) ret += "SCAN ";
    if (flags & 0x0010) ret += "RLOCK ";
    if (flags & 0x0020) ret += "WLOCK ";
    if (flags & 0x0040) ret += "U0040 ";
    if (flags & 0x0080) ret += "U0080 ";
    if (flags & 0x0100) ret += "APPEND ";
    if (flags & 0x0200) ret += "CREAT ";
    if (flags & 0x0400) ret += "TRUNC ";
    if (flags & 0x0800) ret += "U0800 ";
    if (flags & 0x1000) ret += "SCAN2 ";
    if (flags & 0x2000) ret += "RCOM ";
    if (flags & 0x4000) ret += "NBUF ";
    if (flags & 0x8000) ret += "ASYNC ";
    return ret;
}

std::string deviceFlagsToString(uint32_t flags) {
    std::string ret = " ";
    if (flags & 0x01) ret += "CHAR ";
    if (flags & 0x02) ret += "CONS ";
    if (flags & 0x04) ret += "BLOCK ";
    if (flags & 0x08) ret += "RAW ";
    if (flags & 0x10) ret += "FS ";
    return ret;
}

static const char *psxerrnoToString(uint32_t ferrno) {
    const char *errnoStrs[] = {
        "ENOERR",  "EPERM",  "ENOENT",  "ESRCH",       "EINTR",       "EIO",      "ENXIO",  "E2BIG",
        "ENOEXEC", "EBADF",  "ECHILD",  "EAGAIN",      "ENOMEM",      "EACCESS",  "EFAULT", "ENOTBLK",
        "EBUSY",   "EEXIST", "EXDEV",   "ENODEV",      "ENOTDIR",     "EISDIR",   "EINVAL", "ENFILE",
        "EMFILE",  "ENOTTY", "ETXTBSY", "EFBIG",       "ENOSPC",      "ESPIPE",   "EROFS",  "EFORMAT",
        "EPIPE",   "EDOM",   "ERANGE",  "EWOULDBLOCK", "EINPROGRESS", "EALREADY",
    };

    if (ferrno >= (sizeof(errnoStrs) / sizeof(errnoStrs[0]))) return "<INVALID>";
    return errnoStrs[ferrno];
}

static std::string deviceToString(uint32_t *device) {
    uint32_t name = device[0];
    uint32_t flags = device[1];
    uint32_t blockSize = device[2];
    uint32_t desc = device[3];

    name = SWAP_LE32(name);
    flags = SWAP_LE32(flags);
    blockSize = SWAP_LE32(blockSize);
    desc = SWAP_LE32(desc);

    std::string ret = "";
    ret += fmt::sprintf(".name = 0x%08x:\"%s\" ", name, PSXS(name));
    ret += fmt::sprintf(".flags = 0x%02x:{%s} ", flags, deviceFlagsToString(flags));
    ret += fmt::sprintf(".blockSize = %i ", blockSize);
    ret += fmt::sprintf(".desc = 0x%08x:\"%s\" ", desc, PSXS(desc));
    return ret;
}

static std::string fileToString(uint32_t *file) {
    uint32_t flags = file[0];
    uint32_t deviceId = file[1];
    uint32_t buffer = file[2];
    uint32_t count = file[3];
    uint32_t offset = file[4];
    uint32_t deviceFlags = file[5];
    uint32_t ferrno = file[6];
    uint32_t device = file[7];
    uint32_t length = file[8];
    uint32_t lba = file[9];
    uint32_t fd = file[10];

    std::string ret = "";

    flags = SWAP_LE32(flags);
    deviceId = SWAP_LE32(deviceId);
    buffer = SWAP_LE32(buffer);
    count = SWAP_LE32(count);
    offset = SWAP_LE32(offset);
    deviceFlags = SWAP_LE32(deviceFlags);
    ferrno = SWAP_LE32(ferrno);
    device = SWAP_LE32(device);
    length = SWAP_LE32(length);
    lba = SWAP_LE32(lba);
    fd = SWAP_LE32(fd);

    ret += fmt::sprintf(".flags = %i:{%s} ", flags, fileFlagsToString(flags));
    ret += fmt::sprintf(".deviceId = %i ", deviceId);
    ret += fmt::sprintf(".buffer = 0x%08x ", buffer);
    ret += fmt::sprintf(".count = %i ", count);
    ret += fmt::sprintf(".offset = %i ", offset);
    ret += fmt::sprintf(".deviceFlags = %02x:{%s} ", deviceFlags, deviceFlagsToString(deviceFlags));
    ret += fmt::sprintf(".errno = %i:%s ", ferrno, psxerrnoToString(ferrno));
    ret += fmt::sprintf(".device = 0x%08x:{%s} ", device, deviceToString((uint32_t *)PSXM(device)));
    ret += fmt::sprintf(".length = %i ", length);
    ret += fmt::sprintf(".lba = %i ", lba);
    ret += fmt::sprintf(".fd = %i ", fd);

    return ret;
}

static const char *fileActionToString(uint32_t action) {
    if (action == 1) return "READ";
    if (action == 2) return "WRITE";
    return "<UKNOWN>";
}

static const char *const A0names[] = {
    // 00
    "open", "lseek", "read", "write", "close", "ioctl", "exit", "isFileConsole", "getc", "putc", "todigit", nullptr,
    "strtoul", "strtol", "abs", "labs",
    // 10
    "atoi", "atol", "atob", "setjmp", "longjmp", "strcat", "strncat", "strcmp", "strncmp", "strcpy", "strncpy",
    "strlen", "index", "rindex", "strchr", "strrchr",
    // 20
    "strpbrk", "strspn", "strcspn", "strtok", "strstr", "toupper", "tolower", "bcopy", "bzero", "bcmp", "memcpy",
    "memset", "memmove", "memcmp", "memchr", "rand",
    // 30
    "srand", "qsort", "strtod", "user_malloc", "user_free", "lsearch", "bsearch", "user_calloc", "user_realloc",
    "user_initheap", "abort", "getchar", "putchar", "gets", "puts", "printf",
    // 40
    "SystemErrorUnresolvedException", "loadExeHeader", "loadExe", "exec", "flushCache", "installKernelHandlers",
    "GPU_dw", "GPU_mem2vram", "GPU_send", "GPU_cw", "GPU_cwb", "GPU_sendPackets", "GPU_abort", "GPU_getStatus",
    "GPU_sync", nullptr,
    // 50
    nullptr, "loadAndExec", nullptr, nullptr, "initCDRom", "initMC", "deinitCDRom", nullptr, nullptr, nullptr, nullptr,
    "dev_tty_init", "dev_tty_open", "dev_tty_action", "dev_tty_ioctl", "dev_cd_open",
    // 60
    "dev_cd_read", "dev_cd_close", "dev_cd_firstFile", "dev_cd_nextFile", "dev_cd_chdir", "dev_mc_open", "dev_mc_read",
    "dev_mc_write", "dev_mc_close", "dev_mc_firstFile", "dev_mc_nextFile", nullptr, nullptr, nullptr, nullptr,
    "clearFileError",
    // 70
    "initCDRom", "initMC", "deinitCDRom", nullptr, nullptr, nullptr, nullptr, nullptr, "cdromSeekL", nullptr, nullptr,
    nullptr, "cdromGetStatus", nullptr, "cdromRead", nullptr,
    // 80
    nullptr, "cdromSetMode", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr,
    // 90
    "cdromIOVerifier", "cdromDMAVerifier", "cdromIOHandler", "cdromDMAVerifier", "getLastCDRomError", "cdromInnerInit",
    "addCDRomDevice", "addMemoryCardDevice", "addConsoleDevice", "addDummyConsoleDevice", nullptr, nullptr,
    "setConfiguration", "getConfiguration", "setCDRomIRQAutoAck", "setMemSize",
    // a0
    "quickReboot", "cdromException", "enqueueCDRomHandlers", "dequeueCDRomHandlers", "cdromGetFileLBA",
    "cdromBlockReading", "cdromBlockGetStatus", "buLowLevelOpCompleted", "buLowLevelOpError1", "buLowLevelOpError2",
    "buLowLevelOpError3", "cardInfo", "buReadTOC", "buSetAutoFormat", "buError3", "cardTest",
    // b0
    nullptr, nullptr, "ioabort", nullptr, "getSystemInfo",
    // eol
};

unsigned PCSX::Kernel::getA0namesSize() { return (sizeof(A0names) / sizeof(A0names[0])); }

const char *PCSX::Kernel::getA0name(uint32_t call) {
    const char *name = nullptr;
    if (call < getA0namesSize()) name = A0names[call];
    return name;
}

void PCSX::R3000Acpu::logA0KernelCall(uint32_t call) {
    auto &debugSettings = g_emulator->settings.get<Emulator::SettingDebugSettings>();
    uint32_t *flags = nullptr;
    switch (call / 32) {
        case 0:
            flags = &debugSettings.get<Emulator::DebugSettings::KernelCallA0_00_1f>().value;
            break;
        case 1:
            flags = &debugSettings.get<Emulator::DebugSettings::KernelCallA0_20_3f>().value;
            break;
        case 2:
            flags = &debugSettings.get<Emulator::DebugSettings::KernelCallA0_40_5f>().value;
            break;
        case 3:
            flags = &debugSettings.get<Emulator::DebugSettings::KernelCallA0_60_7f>().value;
            break;
        case 4:
            flags = &debugSettings.get<Emulator::DebugSettings::KernelCallA0_80_9f>().value;
            break;
        case 5:
            flags = &debugSettings.get<Emulator::DebugSettings::KernelCallA0_a0_bf>().value;
            break;
    }
    uint32_t bit = 1 << (call % 32);
    if (!flags || ((*flags & bit) == 0)) return;
    auto &n = m_regs.GPR.n;
    const char *const name = Kernel::getA0name(call);
    if (name) g_system->log(LogClass::KERNEL, "KernelCall A0:%02X:%s(", call, name);

    switch (call) {
        case 0x00: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%04x {%s})", n.a0, PSXS(n.a0), n.a1,
                          fileFlagsToString(n.a1));
            break;
        }
        case 0x01: {
            g_system->log(LogClass::KERNEL, "%i, %i, %i)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x02: {
            g_system->log(LogClass::KERNEL, "%i, 0x%08x, %i)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x03: {
            g_system->log(LogClass::KERNEL, "%i, 0x%08x, %i)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x04: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x05: {
            g_system->log(LogClass::KERNEL, "%i, %i, %i)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x06: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x07: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x08: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x09: {
            g_system->log(LogClass::KERNEL, "%i, %i)", n.a0, n.a1);
            break;
        }
        case 0x0a: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x0c: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\",  0x%08x, %i)", n.a0, PSXS(n.a0), n.a1, n.a2);
            break;
        }
        case 0x0d: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\",  0x%08x, %i)", n.a0, PSXS(n.a0), n.a1, n.a2);
            break;
        }
        case 0x0e: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x0f: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x10: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\")", n.a0, PSXS(n.a0));
            break;
        }
        case 0x11: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\")", n.a0, PSXS(n.a0));
            break;
        }
        case 0x12: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%08x)", n.a0, PSXS(n.a0), n.a1);
            break;
        }
        case 0x13: {
            g_system->log(LogClass::KERNEL, "0x%08x)", n.a0);
            break;
        }
        case 0x14: {
            g_system->log(LogClass::KERNEL, "0x%08x, %i)", n.a0, n.a1);
            break;
        }
        case 0x15: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%08x:\"%s\")", n.a0, PSXS(n.a0), n.a1, PSXS(n.a1));
            break;
        }
        case 0x16: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%08x:\"%s\", %i)", n.a0, PSXS(n.a0), n.a1, PSXS(n.a1),
                          n.a2);
            break;
        }
        case 0x17: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%08x:\"%s\")", n.a0, PSXS(n.a0), n.a1, PSXS(n.a1));
            break;
        }
        case 0x18: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%08x:\"%s\", %i)", n.a0, PSXS(n.a0), n.a1, PSXS(n.a1),
                          n.a2);
            break;
        }
        case 0x19: {
            g_system->log(LogClass::KERNEL, "0x%08x, 0x%08x:\"%s\")", n.a0, n.a1, PSXS(n.a1));
            break;
        }
        case 0x1a: {
            g_system->log(LogClass::KERNEL, "0x%08x, 0x%08x:\"%s\", %i)", n.a0, n.a1, PSXS(n.a1), n.a2);
            break;
        }
        case 0x1b: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\")", n.a0, PSXS(n.a0));
            break;
        }
        case 0x1c: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", '%c')", n.a0, PSXS(n.a0), n.a1);
            break;
        }
        case 0x1d: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", '%c')", n.a0, PSXS(n.a0), n.a1);
            break;
        }
        case 0x1e: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", '%c')", n.a0, PSXS(n.a0), n.a1);
            break;
        }
        case 0x1f: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", '%c')", n.a0, PSXS(n.a0), n.a1);
            break;
        }
        case 0x20: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%08x:\"%s\")", n.a0, PSXS(n.a0), n.a1, PSXS(n.a1));
            break;
        }
        case 0x21: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%08x:\"%s\")", n.a0, PSXS(n.a0), n.a1, PSXS(n.a1));
            break;
        }
        case 0x22: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%08x:\"%s\")", n.a0, PSXS(n.a0), n.a1, PSXS(n.a1));
            break;
        }
        case 0x23: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%08x:\"%s\")", n.a0, PSXS(n.a0), n.a1, PSXS(n.a1));
            break;
        }
        case 0x24: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%08x:\"%s\")", n.a0, PSXS(n.a0), n.a1, PSXS(n.a1));
            break;
        }
        case 0x25: {
            g_system->log(LogClass::KERNEL, "'%c')", n.a0);
            break;
        }
        case 0x26: {
            g_system->log(LogClass::KERNEL, "'%c')", n.a0);
            break;
        }
        case 0x27: {
            g_system->log(LogClass::KERNEL, "0x%08x, 0x%08x, %i)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x28: {
            g_system->log(LogClass::KERNEL, "0x%08x, %i)", n.a0, n.a1);
            break;
        }
        case 0x29: {
            g_system->log(LogClass::KERNEL, "0x%08x, 0x%08x, %i)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x2a: {
            g_system->log(LogClass::KERNEL, "0x%08x, 0x%08x, %i)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x2b: {
            g_system->log(LogClass::KERNEL, "0x%08x, 0x%02x, %i)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x2c: {
            g_system->log(LogClass::KERNEL, "0x%08x, 0x%08x, %i)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x2d: {
            g_system->log(LogClass::KERNEL, "0x%08x, 0x%08x, %i)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x2e: {
            g_system->log(LogClass::KERNEL, "0x%08x, 0x%02x, %i)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x2f: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x30: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x31: {
            g_system->log(LogClass::KERNEL, "0x%08x, %i, %i, 0x%08x)", n.a0, n.a1, n.a2, n.a3);
            break;
        }
        case 0x32: {
            g_system->log(LogClass::KERNEL, "\"%s\", 0x%08x)", n.a0, n.a1);
            break;
        }
        case 0x33: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x34: {
            g_system->log(LogClass::KERNEL, "0x%08x)", n.a0);
            break;
        }
        case 0x35: {
            uint32_t cmp = *(uint32_t *)PSXM(n.sp + 0x10);
            g_system->log(LogClass::KERNEL, "0x%08x, 0x%08x, %i, %i, 0x%08x)", n.a0, n.a1, n.a2, n.a3, SWAP_LE32(cmp));
            break;
        }
        case 0x36: {
            uint32_t cmp = *(uint32_t *)PSXM(n.sp + 0x10);
            g_system->log(LogClass::KERNEL, "0x%08x, 0x%08x, %i, %i, 0x%08x)", n.a0, n.a1, n.a2, n.a3, SWAP_LE32(cmp));
            break;
        }
        case 0x37: {
            g_system->log(LogClass::KERNEL, "%i, %i)", n.a0, n.a1);
            break;
        }
        case 0x38: {
            g_system->log(LogClass::KERNEL, "0x%08x, %i)", n.a0, n.a1);
            break;
        }
        case 0x39: {
            g_system->log(LogClass::KERNEL, "0x%08x, %i)", n.a0, n.a1);
            break;
        }
        case 0x3a: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x3b: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x3c: {
            g_system->log(LogClass::KERNEL, "'%c')", n.a0);
            break;
        }
        case 0x3d: {
            g_system->log(LogClass::KERNEL, "0x%08x)", n.a0);
            break;
        }
        case 0x3e: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\")", n.a0, PSXS(n.a0));
            break;
        }
        case 0x3f: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", ...)", n.a0, PSXS(n.a0));
            break;
        }
        case 0x40: {
            g_system->log(LogClass::KERNEL, ")", PSXS(n.a0));
            break;
        }
        case 0x41: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%08x)", n.a0, PSXS(n.a0), n.a1);
            break;
        }
        case 0x42: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%08x)", n.a0, PSXS(n.a0), n.a1);
            break;
        }
        case 0x43: {
            uint32_t *header = (uint32_t *)PSXM(n.a0);
            uint32_t newPc = *header;
            g_system->log(LogClass::KERNEL, "0x%08x {.pc = 0x%08x}, %i, 0x%08x)", n.a0, SWAP_LE32(newPc), n.a1, n.a2);
            break;
        }
        case 0x44: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x45: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x46: {
            uint32_t src = *(uint32_t *)PSXM(n.sp + 0x10);
            g_system->log(LogClass::KERNEL, "%i, %i, %i, %i, 0x%08x)", n.a0, n.a1, n.a2, n.a3, SWAP_LE32(src));
            break;
        }
        case 0x47: {
            uint32_t src = *(uint32_t *)PSXM(n.sp + 0x10);
            g_system->log(LogClass::KERNEL, "%i, %i, %i, %i, 0x%08x)", n.a0, n.a1, n.a2, n.a3, SWAP_LE32(src));
            break;
        }
        case 0x48: {
            g_system->log(LogClass::KERNEL, "0x%08x)", n.a0);
            break;
        }
        case 0x49: {
            g_system->log(LogClass::KERNEL, "0x%08x)", n.a0);
            break;
        }
        case 0x4a: {
            g_system->log(LogClass::KERNEL, "0x%08x, %i)", n.a0, n.a1);
            break;
        }
        case 0x4b: {
            g_system->log(LogClass::KERNEL, "0x%08x)", n.a0);
            break;
        }
        case 0x4c: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x4d: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x4e: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x51: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%08x, 0x%08x)", n.a0, PSXS(n.a0), n.a1, n.a2);
            break;
        }
        case 0x54: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x55: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x56: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x5b: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x5c: {
            uint32_t *file = (uint32_t *)PSXM(n.a0);
            g_system->log(LogClass::KERNEL, "0x%08x {%s}, 0x%08x:\"%s\", 0x%04x {%s})", n.a0, fileToString(file), n.a1,
                          PSXS(n.a1), n.a2, fileFlagsToString(n.a2));
            break;
        }
        case 0x5d: {
            uint32_t *file = (uint32_t *)PSXM(n.a0);
            g_system->log(LogClass::KERNEL, "0x%08x {%s}, %i {%s})", n.a0, fileToString(file), n.a1,
                          fileActionToString(n.a1));
            break;
        }
        case 0x5e: {
            uint32_t *file = (uint32_t *)PSXM(n.a0);
            g_system->log(LogClass::KERNEL, "0x%08x {%s}, %i, %i)", n.a0, fileToString(file), n.a1, n.a2);
            break;
        }
        case 0x5f: {
            uint32_t *file = (uint32_t *)PSXM(n.a0);
            g_system->log(LogClass::KERNEL, "0x%08x {%s}, 0x%08x:\"%s\", 0x%04x {%s})", n.a0, fileToString(file), n.a1,
                          PSXS(n.a1), n.a2, fileFlagsToString(n.a2));
            break;
        }
        case 0x60: {
            uint32_t *file = (uint32_t *)PSXM(n.a0);
            g_system->log(LogClass::KERNEL, "0x%08x {%s}, 0x%08x, %i)", n.a0, fileToString(file), n.a1, n.a2);
            break;
        }
        case 0x61: {
            uint32_t *file = (uint32_t *)PSXM(n.a0);
            g_system->log(LogClass::KERNEL, "0x%08x {%s})", n.a0, fileToString(file));
            break;
        }
        case 0x62: {
            uint32_t *file = (uint32_t *)PSXM(n.a0);
            g_system->log(LogClass::KERNEL, "0x%08x {%s}, %08x:\"%s\", 0x%08x)", n.a0, fileToString(file), n.a1,
                          PSXS(n.a1), n.a2);
            break;
        }
        case 0x63: {
            uint32_t *file = (uint32_t *)PSXM(n.a0);
            g_system->log(LogClass::KERNEL, "0x%08x {%s}, 0x%08x)", n.a0, fileToString(file), n.a1);
            break;
        }
        case 0x64: {
            uint32_t *file = (uint32_t *)PSXM(n.a0);
            g_system->log(LogClass::KERNEL, "0x%08x {%s}, 0x%08x:\"%s\")", n.a0, fileToString(file), n.a1, PSXS(n.a1));
            break;
        }
        case 0x65: {
            uint32_t *file = (uint32_t *)PSXM(n.a0);
            g_system->log(LogClass::KERNEL, "0x%08x {%s}, 0x%08x:\"%s\", 0x%04x {%s})", n.a0, fileToString(file), n.a1,
                          PSXS(n.a1), n.a2, fileFlagsToString(n.a2));
            break;
        }
        case 0x66: {
            uint32_t *file = (uint32_t *)PSXM(n.a0);
            g_system->log(LogClass::KERNEL, "0x%08x {%s}, 0x%08x, %i)", n.a0, fileToString(file), n.a1, n.a2);
            break;
        }
        case 0x67: {
            uint32_t *file = (uint32_t *)PSXM(n.a0);
            g_system->log(LogClass::KERNEL, "0x%08x {%s}, 0x%08x, %i)", n.a0, fileToString(file), n.a1, n.a2);
            break;
        }
        case 0x68: {
            uint32_t *file = (uint32_t *)PSXM(n.a0);
            g_system->log(LogClass::KERNEL, "0x%08x {%s})", n.a0, fileToString(file));
            break;
        }
        case 0x69: {
            uint32_t *file = (uint32_t *)PSXM(n.a0);
            g_system->log(LogClass::KERNEL, "0x%08x {%s}, %08x:\"%s\", 0x%08x)", n.a0, fileToString(file), n.a1,
                          PSXS(n.a1), n.a2);
            break;
        }
        case 0x6a: {
            uint32_t *file = (uint32_t *)PSXM(n.a0);
            g_system->log(LogClass::KERNEL, "0x%08x {%s}, 0x%08x)", n.a0, fileToString(file), n.a1);
            break;
        }
        case 0x6f: {
            uint32_t *file = (uint32_t *)PSXM(n.a0);
            g_system->log(LogClass::KERNEL, "0x%08x {%s})", n.a0, fileToString(file));
            break;
        }
        case 0x70: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x71: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x72: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x78: {
            uint8_t *msf = (uint8_t *)PSXM(n.a0);
            g_system->log(LogClass::KERNEL, "0x%08x {%02x:%02x:%02x})", n.a0, msf[0], msf[1], msf[2]);
            break;
        }
        case 0x7c: {
            g_system->log(LogClass::KERNEL, "0x%08x)", n.a0);
            break;
        }
        case 0x7e: {
            g_system->log(LogClass::KERNEL, "%i, 0x%08x, 0x%02x)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x81: {
            g_system->log(LogClass::KERNEL, "0x%02x)", n.a0);
            break;
        }
        case 0x90: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x91: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x92: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x93: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x94: {
            g_system->log(LogClass::KERNEL, "0x%08x, 0x%08x)", n.a0, n.a1);
            break;
        }
        case 0x95: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x96: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x97: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x98: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x99: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x9c: {
            g_system->log(LogClass::KERNEL, "%i, %i, 0x%08x)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x9d: {
            g_system->log(LogClass::KERNEL, "0x%08x, 0x%08x, 0x%08x)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x9e: {
            g_system->log(LogClass::KERNEL, "%i, %i)", n.a0, n.a1);
            break;
        }
        case 0x9f: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0xa0: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0xa1: {
            g_system->log(LogClass::KERNEL, "%i, %i)", n.a0, n.a1);
            break;
        }
        case 0xa2: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0xa3: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0xa4: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\")", n.a0, PSXS(n.a0));
            break;
        }
        case 0xa5: {
            g_system->log(LogClass::KERNEL, "%i, %i, 0x%08x)", n.a0, n.a1, n.a2);
            break;
        }
        case 0xa6: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0xa7: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0xa8: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0xa9: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0xaa: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0xab: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0xac: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0xad: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0xae: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0xaf: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0xb2: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0xb4: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        default: {
            g_system->log(LogClass::KERNEL, "KernelCall: unknown kernel call A0:%02X", call);
            break;
        }
    }
    g_system->log(LogClass::KERNEL, " from 0x%08x\n", n.ra);
}

static const char *const B0names[] = {
    // 00
    "kern_malloc", "kern_free", "initTimer", "getTimer", "enableTimerIRQ", "disableTimerIRQ", "restartTimer",
    "deliverEvent", "openEvent", "closeEvent", "waitEvent", "testEvent", "enableEvent", "disableEvent", "openThread",
    "closeThread",
    // 10
    "changeThread", nullptr, "initPad", "startPad", "stopPad", "initPadHighLevel", "readPadHighLevel",
    "returnFromException", "setDefaultExceptionJmpBuf", "setExceptionJmpBuf", nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr,
    // 20
    "undeliverEvent", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr,
    // 30
    nullptr, nullptr, "open", "lseek", "read", "write", "close", "ioctl", "exit", "isFileConsole", "getc", "putc",
    "getchar", "putchar", "gets", "puts",
    // 40
    "chdir", "format", "firstFile", "nextFile", "rename", "delete", "undelete", "addDevice", "removeDevice",
    "printInstalledDevices", "initCard", "startCard", "stopCard", "cardInfoInternal", "mcWriteSector", "mcReadSector",
    // 50
    "mcAllowNewCard", "Krom2RawAdd", nullptr, "Krom2Offset", "getErrno", "getFileErrno", "getC0table", "getB0table",
    "mcGetLastDevice", "checkDevice", nullptr, "setSIO0AutoAck",
    // eol
};

unsigned PCSX::Kernel::getB0namesSize() { return (sizeof(B0names) / sizeof(B0names[0])); }

const char *PCSX::Kernel::getB0name(uint32_t call) {
    const char *name = nullptr;
    if (call < getB0namesSize()) name = B0names[call];
    return name;
}

void PCSX::R3000Acpu::logB0KernelCall(uint32_t call) {
    auto &debugSettings = g_emulator->settings.get<Emulator::SettingDebugSettings>();
    uint32_t *flags = nullptr;
    switch (call / 32) {
        case 0:
            flags = &debugSettings.get<Emulator::DebugSettings::KernelCallB0_00_1f>().value;
            break;
        case 1:
            flags = &debugSettings.get<Emulator::DebugSettings::KernelCallB0_20_3f>().value;
            break;
        case 2:
            flags = &debugSettings.get<Emulator::DebugSettings::KernelCallB0_40_5f>().value;
            break;
    }
    uint32_t bit = 1 << (call % 32);
    if (!flags || ((*flags & bit) == 0)) return;
    auto &n = m_regs.GPR.n;
    const char *const name = Kernel::getB0name(call);
    if (name) g_system->log(LogClass::KERNEL, "KernelCall B0:%02X:%s(", call, name);

    switch (call) {
        case 0x00: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x01: {
            g_system->log(LogClass::KERNEL, "0x%08x)", n.a0);
            break;
        }
        case 0x02: {
            g_system->log(LogClass::KERNEL, "%i, %i, 0x%04x)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x03: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x04: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x05: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x06: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x07: {
            g_system->log(LogClass::KERNEL, "%s, %s)", Kernel::Events::Event::resolveClass(n.a0).c_str(),
                          Kernel::Events::Event::resolveSpec(n.a1).c_str());
            break;
        }
        case 0x08: {
            int id = Kernel::Events::getFirstFreeEvent(reinterpret_cast<const uint32_t *>(g_emulator->m_mem->m_psxM));
            g_system->log(LogClass::KERNEL, "%s, %s, %s, 0x%08x) --> 0x%08x",
                          Kernel::Events::Event::resolveClass(n.a0).c_str(),
                          Kernel::Events::Event::resolveSpec(n.a1).c_str(),
                          Kernel::Events::Event::resolveMode(n.a2).c_str(), n.a3, id | 0xf1000000);
            break;
        }
        case 0x09: {
            Kernel::Events::Event ev{reinterpret_cast<const uint32_t *>(g_emulator->m_mem->m_psxM), n.a0};
            g_system->log(LogClass::KERNEL, "0x%08x {%s, %s})", n.a0, ev.getClass().c_str(), ev.getSpec().c_str());
            break;
        }
        case 0x0a: {
            Kernel::Events::Event ev{reinterpret_cast<const uint32_t *>(g_emulator->m_mem->m_psxM), n.a0};
            g_system->log(LogClass::KERNEL, "0x%08x {%s, %s})", n.a0, ev.getClass().c_str(), ev.getSpec().c_str());
            break;
        }
        case 0x0b: {
            Kernel::Events::Event ev{reinterpret_cast<const uint32_t *>(g_emulator->m_mem->m_psxM), n.a0};
            g_system->log(LogClass::KERNEL, "0x%08x {%s, %s})", n.a0, ev.getClass().c_str(), ev.getSpec().c_str());
            break;
        }
        case 0x0c: {
            Kernel::Events::Event ev{reinterpret_cast<const uint32_t *>(g_emulator->m_mem->m_psxM), n.a0};
            g_system->log(LogClass::KERNEL, "0x%08x {%s, %s})", n.a0, ev.getClass().c_str(), ev.getSpec().c_str());
            break;
        }
        case 0x0d: {
            Kernel::Events::Event ev{reinterpret_cast<const uint32_t *>(g_emulator->m_mem->m_psxM), n.a0};
            g_system->log(LogClass::KERNEL, "0x%08x {%s, %s})", n.a0, ev.getClass().c_str(), ev.getSpec().c_str());
            break;
        }
        case 0x0e: {
            g_system->log(LogClass::KERNEL, "0x%08x, 0x%08x, 0x%08x)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x0f: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x10: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x12: {
            g_system->log(LogClass::KERNEL, "0x%08x, %i, 0x%08x, %i)", n.a0, n.a1, n.a2, n.a3);
            break;
        }
        case 0x13: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x14: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x15: {
            g_system->log(LogClass::KERNEL, "%i, 0x%08x, ...)", n.a0, n.a1);
            break;
        }
        case 0x16: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x17: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x18: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x19: {
            uint32_t *jmpBuf = (uint32_t *)PSXM(n.a0);
            uint32_t ra = jmpBuf[0];
            uint32_t sp = jmpBuf[1];
            g_system->log(LogClass::KERNEL, "0x%08x {.ra = 0x%08x, .sp = 0x%08x})", n.a0, SWAP_LE32(ra), SWAP_LE32(sp));
            break;
        }
        case 0x20: {
            g_system->log(LogClass::KERNEL, "%s, %s)", Kernel::Events::Event::resolveClass(n.a0).c_str(),
                          Kernel::Events::Event::resolveSpec(n.a1).c_str());
            break;
        }
        case 0x32: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%04x {%s})", n.a0, PSXS(n.a0), n.a1,
                          fileFlagsToString(n.a1));
            break;
        }
        case 0x33: {
            g_system->log(LogClass::KERNEL, "%i, %i, %i)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x34: {
            g_system->log(LogClass::KERNEL, "%i, 0x%08x, %i)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x35: {
            g_system->log(LogClass::KERNEL, "%i, 0x%08x, %i)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x36: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x37: {
            g_system->log(LogClass::KERNEL, "%i, %i, %i)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x38: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x39: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x3a: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x3b: {
            g_system->log(LogClass::KERNEL, "%i, %i)", n.a0, n.a1);
            break;
        }
        case 0x3c: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x3d: {
            g_system->log(LogClass::KERNEL, "'%c')", n.a0);
            break;
        }
        case 0x3e: {
            g_system->log(LogClass::KERNEL, "0x%08x)", n.a0);
            break;
        }
        case 0x3f: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\")", n.a0, PSXS(n.a0));
            break;
        }
        case 0x40: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\")", n.a0, PSXS(n.a0));
            break;
        }
        case 0x41: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\")", n.a0, PSXS(n.a0));
            break;
        }
        case 0x42: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%08x)", n.a0, PSXS(n.a0), n.a1);
            break;
        }
        case 0x43: {
            g_system->log(LogClass::KERNEL, "0x%08x)", n.a0);
            break;
        }
        case 0x44: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%08x:\"%s\")", n.a0, PSXS(n.a0), n.a1, PSXS(n.a1));
            break;
        }
        case 0x45: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\")", n.a0, PSXS(n.a0));
            break;
        }
        case 0x46: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\")", n.a0, PSXS(n.a0));
            break;
        }
        case 0x47: {
            g_system->log(LogClass::KERNEL, "0x%08x {%s})", n.a0, deviceToString((uint32_t *)PSXM(n.a0)));
            break;
        }
        case 0x48: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\")", n.a0, PSXS(n.a0));
            break;
        }
        case 0x49: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x4a: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x4b: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x4c: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x4d: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x4e: {
            g_system->log(LogClass::KERNEL, "%i, %i, 0x%08x)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x4f: {
            g_system->log(LogClass::KERNEL, "%i, %i, 0x%08x)", n.a0, n.a1, n.a2);
            break;
        }
        case 0x50: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x51: {
            g_system->log(LogClass::KERNEL, "0x%04x)", n.a0);
            break;
        }
        case 0x53: {
            g_system->log(LogClass::KERNEL, "0x%04x)", n.a0);
            break;
        }
        case 0x54: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x55: {
            g_system->log(LogClass::KERNEL, "0x%08x {%s})", n.a0, fileToString((uint32_t *)PSXM(n.a0)));
            break;
        }
        case 0x56: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x57: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x58: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x59: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\")", n.a0, PSXS(n.a0));
            break;
        }
        case 0x5b: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        default: {
            g_system->log(LogClass::KERNEL, "KernelCall: unknown kernel call B0:%02X", call);
            break;
        }
    }
    g_system->log(LogClass::KERNEL, " from 0x%08x\n", n.ra);
}

static const char *const C0names[] = {
    // 00
    "enqueueRCntIrqs", "enqueueSyscallHandler", "sysEnqIntRP", "sysDeqIntRP", "getFreeEvCBSlot", "getFreeTCBslot",
    "exceptionHandler", "installExceptionHandler", "kern_initheap", nullptr, "setTimerAutoAck", nullptr,
    "enqueueIrqHandler", nullptr, nullptr, nullptr,
    // 10
    nullptr, nullptr, "setupFileIO", "reopenStdio", nullptr, "cdevinput", "cdevscan", "circgetc", "circputc",
    "ioAbortWithMsg", "setDeviceStatus", "installStdIo", "patchA0table", "getDeviceStatus",
    // eol
};

unsigned PCSX::Kernel::getC0namesSize() { return (sizeof(C0names) / sizeof(C0names[0])); }

const char *PCSX::Kernel::getC0name(uint32_t call) {
    const char *name = nullptr;
    if (call < getC0namesSize()) name = C0names[call];
    return name;
}

void PCSX::R3000Acpu::logC0KernelCall(uint32_t call) {
    auto &debugSettings = g_emulator->settings.get<Emulator::SettingDebugSettings>();
    uint32_t *flags = nullptr;
    switch (call / 32) {
        case 0:
            flags = &debugSettings.get<Emulator::DebugSettings::KernelCallC0_00_1f>().value;
            break;
    }
    uint32_t bit = 1 << (call % 32);
    if (!flags || ((*flags & bit) == 0)) return;
    auto &n = m_regs.GPR.n;
    switch (call) {
        case 0x00: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x01: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x02: {
            g_system->log(LogClass::KERNEL, "%i, 0x%08x)", n.a0, n.a1);
            break;
        }
        case 0x03: {
            g_system->log(LogClass::KERNEL, "%i, 0x%08x)", n.a0, n.a1);
            break;
        }
        case 0x04: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x05: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x06: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x07: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x08: {
            g_system->log(LogClass::KERNEL, "0x%08x, %i)", n.a0, n.a1);
            break;
        }
        case 0x0a: {
            g_system->log(LogClass::KERNEL, "%i, %i)", n.a0, n.a1);
            break;
        }
        case 0x0c: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x0d: {
            g_system->log(LogClass::KERNEL, "%i, %i)", n.a0, n.a1);
            break;
        }
        case 0x12: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x13: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x15: {
            g_system->log(LogClass::KERNEL, "0x%08x, '%c')", n.a0, n.a1);
            break;
        }
        case 0x16: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x17: {
            g_system->log(LogClass::KERNEL, "0x%08x, 0x%08x:\"%s\")", n.a0, n.a1, PSXS(n.a1));
            break;
        }
        case 0x18: {
            g_system->log(LogClass::KERNEL, "'%c', 0x%08x)", n.a0, n.a1);
            break;
        }
        case 0x19: {
            g_system->log(LogClass::KERNEL, "0x%08x:\"%s\", 0x%08x:\"%s\")", n.a0, PSXS(n.a0), n.a1, PSXS(n.a1));
            break;
        }
        case 0x1a: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x1b: {
            g_system->log(LogClass::KERNEL, "%i)", n.a0);
            break;
        }
        case 0x1c: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        case 0x1d: {
            g_system->log(LogClass::KERNEL, ")");
            break;
        }
        default: {
            g_system->log(LogClass::KERNEL, "KernelCall: unknown kernel call C0:%02X from 0x%08x\n", call,
                          m_regs.GPR.n.ra);
            break;
        }
    }
}
