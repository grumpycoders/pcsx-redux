/***************************************************************************
 *   Copyright (C) 2007 Ryan Schultz, PCSX-df Team, PCSX team              *
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

/*
 * Miscellaneous functions, including savestates and CD-ROM loading.
 */

#include "core/misc.h"

#include <stddef.h>

#include "core/cdrom.h"
#include "core/gpu.h"
#include "core/mdec.h"
#include "core/ppf.h"
#include "core/psxemulator.h"
#include "spu/interface.h"

// FIXME: should be put in a more global header.
#if defined(__linux__) || defined(__APPLE__)
#define strnicmp strncasecmp
#endif

#define ISODCL(from, to) (to - from + 1)

struct iso_directory_record {
    char length[ISODCL(1, 1)];          /* 711 */
    char ext_attr_length[ISODCL(2, 2)]; /* 711 */
    char extent[ISODCL(3, 10)];         /* 733 */
    char size[ISODCL(11, 18)];          /* 733 */
    char date[ISODCL(19, 25)];          /* 7 by 711 */
    char flags[ISODCL(26, 26)];
    char file_unit_size[ISODCL(27, 27)];         /* 711 */
    char interleave[ISODCL(28, 28)];             /* 711 */
    char volume_sequence_number[ISODCL(29, 32)]; /* 723 */
    unsigned char name_len[ISODCL(33, 33)];      /* 711 */
    char name[1];
};

// local extern
static void trim_key(char *str, char key);
static void split(char *str, char key, char *pout);

void mmssdd(char *b, char *p) {
    int m, s, d;
#if defined(__BIGENDIAN__)
    int block = (b[0] & 0xff) | ((b[1] & 0xff) << 8) | ((b[2] & 0xff) << 16) | (b[3] << 24);
#else
    int block = *((int *)b);
#endif

    block += 150;
    m = block / 4500;          // minutes
    block = block - m * 4500;  // minutes rest
    s = block / 75;            // seconds
    d = block - s * 75;        // seconds rest

    m = ((m / 10) << 4) | m % 10;
    s = ((s / 10) << 4) | s % 10;
    d = ((d / 10) << 4) | d % 10;

    p[0] = m;
    p[1] = s;
    p[2] = d;
}

#define incTime()                         \
    time[0] = PCSX::CDRom::btoi(time[0]); \
    time[1] = PCSX::CDRom::btoi(time[1]); \
    time[2] = PCSX::CDRom::btoi(time[2]); \
    time[2]++;                            \
    if (time[2] == 75) {                  \
        time[2] = 0;                      \
        time[1]++;                        \
        if (time[1] == 60) {              \
            time[1] = 0;                  \
            time[0]++;                    \
        }                                 \
    }                                     \
    time[0] = PCSX::CDRom::itob(time[0]); \
    time[1] = PCSX::CDRom::itob(time[1]); \
    time[2] = PCSX::CDRom::itob(time[2]);

#define READTRACK()                                                      \
    if (!PCSX::g_emulator->m_cdrom->m_iso.readTrack(time)) return false; \
    buf = PCSX::g_emulator->m_cdrom->m_iso.getBuffer();                  \
    if (buf == NULL)                                                     \
        return false;                                                    \
    else                                                                 \
        PCSX::g_emulator->m_cdrom->m_ppf.CheckPPFCache(buf, time[0], time[1], time[2]);

#define READDIR(_dir)             \
    READTRACK();                  \
    memcpy(_dir, buf + 12, 2048); \
                                  \
    incTime();                    \
    READTRACK();                  \
    memcpy(_dir + 2048, buf + 12, 2048);

int GetCdromFile(uint8_t *mdir, uint8_t *time, const char *filename) {
    struct iso_directory_record *dir;
    uint8_t ddir[4096];
    uint8_t *buf;

    // only try to scan if a filename is given
    if (!strlen(filename)) return -1;

    int i = 0;
    while (i < 4096) {
        dir = (struct iso_directory_record *)&mdir[i];
        if (dir->length[0] == 0) {
            return -1;
        }
        i += dir->length[0];

        if (dir->flags[0] & 0x2) {  // it's a dir
            if (!strnicmp((char *)&dir->name[0], filename, dir->name_len[0])) {
                if (filename[dir->name_len[0]] != '\\') continue;

                filename += dir->name_len[0] + 1;

                mmssdd(dir->extent, (char *)time);
                READDIR(ddir);
                i = 0;
                mdir = ddir;
            }
        } else {
            if (!strnicmp((char *)&dir->name[0], filename, strlen(filename))) {
                mmssdd(dir->extent, (char *)time);
                break;
            }
        }
    }
    return 0;
}

bool LoadCdromFile(const char *filename, EXE_HEADER *head) {
    struct iso_directory_record *dir;
    uint8_t time[4], *buf;
    uint8_t mdir[4096];
    char exename[256];
    uint32_t size, addr;
    void *psxaddr;

    if (sscanf(filename, "cdrom:\\%255s", exename) <= 0) {
        // Some games omit backslash (NFS4)
        if (sscanf(filename, "cdrom:%255s", exename) <= 0) {
            PCSX::g_system->printf("LoadCdromFile: EXE NAME PARSING ERROR (%s (%u))\n", filename, strlen(filename));
            exit(1);
        }
    }

    time[0] = PCSX::CDRom::itob(0);
    time[1] = PCSX::CDRom::itob(2);
    time[2] = PCSX::CDRom::itob(0x10);

    READTRACK();

    // skip head and sub, and go to the root directory record
    dir = (struct iso_directory_record *)&buf[12 + 156];

    mmssdd(dir->extent, (char *)time);

    READDIR(mdir);

    if (GetCdromFile(mdir, time, exename) == -1) return -1;

    READTRACK();

    memcpy(head, buf + 12, sizeof(EXE_HEADER));
    size = head->t_size;
    addr = head->t_addr;

    // Cache clear/invalidate dynarec/int. Fixes startup of Casper/X-Files and possibly others.
    PCSX::g_emulator->m_cpu->Clear(addr, size / 4);
    PCSX::g_emulator->m_cpu->invalidateCache();

    while (size) {
        incTime();
        READTRACK();

        psxaddr = (void *)PSXM(addr);
        assert(psxaddr != NULL);
        memcpy(psxaddr, buf + 12, 2048);

        size -= 2048;
        addr += 2048;
    }

    return true;
}

bool CheckCdrom() {
    struct iso_directory_record *dir;
    unsigned char time[4];
    unsigned char *buf;
    unsigned char mdir[4096];
    char exename[256];
    int i, len, c;

    PCSX::g_emulator->m_cdrom->m_ppf.FreePPFCache();

    time[0] = PCSX::CDRom::itob(0);
    time[1] = PCSX::CDRom::itob(2);
    time[2] = PCSX::CDRom::itob(0x10);

    READTRACK();

    memset(PCSX::g_emulator->m_cdromLabel, 0, sizeof(PCSX::g_emulator->m_cdromLabel));
    memset(PCSX::g_emulator->m_cdromId, 0, sizeof(PCSX::g_emulator->m_cdromId));
    memset(exename, 0, sizeof(exename));

    strncpy(PCSX::g_emulator->m_cdromLabel, reinterpret_cast<char *>(buf + 52), 32);

    // skip head and sub, and go to the root directory record
    dir = (struct iso_directory_record *)&buf[12 + 156];

    mmssdd(dir->extent, (char *)time);

    READDIR(mdir);

    if (GetCdromFile(mdir, time, "SYSTEM.CNF;1") != -1) {
        READTRACK();

        sscanf((char *)buf + 12, "BOOT = cdrom:\\%255s", exename);
        if (GetCdromFile(mdir, time, exename) == -1) {
            sscanf((char *)buf + 12, "BOOT = cdrom:%255s", exename);
            if (GetCdromFile(mdir, time, exename) == -1) {
                char *ptr =
                    strstr(reinterpret_cast<char *>(buf + 12), "cdrom:");  // possibly the executable is in some subdir
                if (ptr != NULL) {
                    ptr += 6;
                    while (*ptr == '\\' || *ptr == '/') ptr++;
                    strncpy(exename, ptr, 255);
                    exename[255] = '\0';
                    ptr = exename;
                    while (*ptr != '\0' && *ptr != '\r' && *ptr != '\n') ptr++;
                    *ptr = '\0';
                    if (GetCdromFile(mdir, time, exename) == -1) return -1;  // main executable not found
                } else
                    return -1;
            }
        }
    } else if (GetCdromFile(mdir, time, "PSX.EXE;1") != -1) {
        strcpy(exename, "PSX.EXE;1");
        strcpy(PCSX::g_emulator->m_cdromId, "SLUS99999");
    } else
        return false;  // SYSTEM.CNF and PSX.EXE not found

    if (PCSX::g_emulator->m_cdromId[0] == '\0') {
        len = strlen(exename);
        c = 0;
        for (i = 0; i < len; ++i) {
            if (exename[i] == ';' || c >= sizeof(PCSX::g_emulator->m_cdromId) - 1) break;
            if (isalnum(exename[i])) PCSX::g_emulator->m_cdromId[c++] = exename[i];
        }
    }

    if (PCSX::g_emulator->config().OverClock == 0) {
        PCSX::g_emulator->m_psxClockSpeed = 33868800;  // 33.8688 MHz (stock)
    } else {
        PCSX::g_emulator->m_psxClockSpeed = 33868800 * PCSX::g_emulator->config().PsxClock;
    }

    if (PCSX::g_emulator->m_cdromLabel[0] == ' ') {
        strncpy(PCSX::g_emulator->m_cdromLabel, PCSX::g_emulator->m_cdromId, 9);
    }
    PCSX::g_system->printf(_("CD-ROM Label: %.32s\n"), PCSX::g_emulator->m_cdromLabel);
    PCSX::g_system->printf(_("CD-ROM ID: %.9s\n"), PCSX::g_emulator->m_cdromId);
    PCSX::g_system->printf(_("CD-ROM EXE Name: %.255s\n"), exename);

    PCSX::g_emulator->settings.get<PCSX::Emulator::SettingPsxExe>() = exename;

    if (PCSX::g_emulator->config().PerGameMcd) {
        char mcd1path[MAXPATHLEN] = {'\0'};
        char mcd2path[MAXPATHLEN] = {'\0'};
        sprintf(mcd1path, "memcards/games/%s-%02d.mcd",
                PCSX::g_emulator->settings.get<PCSX::Emulator::SettingPsxExe>().string().c_str(), 1);
        sprintf(mcd2path, "memcards/games/%s-%02d.mcd",
                PCSX::g_emulator->settings.get<PCSX::Emulator::SettingPsxExe>().string().c_str(), 2);
        PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd1>() = mcd1path;
        PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd2>() = mcd2path;
        PCSX::g_emulator->m_sio->LoadMcds(
            PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd1>().string().c_str(),
            PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd2>().string().c_str());
    }

    PCSX::g_emulator->m_cdrom->m_ppf.BuildPPFCache();
    PCSX::g_emulator->m_cdrom->m_iso.LoadSBI(NULL);

    return true;
}

// remove the leading and trailing spaces in a string
void trim(char *str) { trim_key(str, ' '); }

static void trim_key(char *str, char key) {
    int pos = 0;
    char *dest = str;

    // skip leading blanks
    while (str[pos] <= key && str[pos] > 0) pos++;

    while (str[pos]) {
        *(dest++) = str[pos];
        pos++;
    }

    *(dest--) = '\0';  // store the null

    // remove trailing blanks
    while (dest >= str && *dest <= key && *dest > 0) *(dest--) = '\0';
}

// split by the keys codes in strings
static void split(char *str, char key, char *pout) {
    char *psrc = str;
    char *pdst = pout;
    int len = strlen(str);

    for (int i = 0; i < len; i++) {
        if (psrc[i] == '\0' || psrc[i] == key) {
            *pdst = '\0';
            break;
        } else {
            *pdst++ = psrc[i];
        }
    }
}

// lookup table for crc calculation
static unsigned short crctab[256] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,  // 00
    0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,  // 08
    0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,  // 10
    0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,  // 18
    0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,  // 20
    0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,  // 28
    0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,  // 30
    0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,  // 38
    0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,  // 40
    0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,  // 48
    0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,  // 50
    0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,  // 58
    0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,  // 60
    0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,  // 68
    0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,  // 70
    0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,  // 78
    0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,  // 80
    0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,  // 88
    0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,  // 90
    0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,  // 98
    0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,  // a0
    0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,  // a8
    0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,  // b0
    0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,  // b8
    0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,  // c0
    0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,  // c8
    0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,  // d0
    0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,  // d8
    0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,  // e0
    0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,  // e8
    0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,  // f0
    0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0,  // f8
};

uint16_t calcCrc(uint8_t *d, int len) {
    uint16_t crc = 0;

    for (int i = 0; i < len; i++) {
        crc = crctab[(crc >> 8) ^ d[i]] ^ (crc << 8);
    }

    return ~crc;
}
