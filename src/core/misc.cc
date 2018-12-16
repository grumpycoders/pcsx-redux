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

#include <stddef.h>

#include "core/cdrom.h"
#include "core/mdec.h"
#include "core/misc.h"
#include "core/ppf.h"

char g_cdromId[10] = "";
char g_cdromLabel[33] = "";

// PSX Executable types
#define PSX_EXE 1
#define CPE_EXE 2
#define COFF_EXE 3
#define INVALID_EXE 4

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

#define incTime()            \
    time[0] = btoi(time[0]); \
    time[1] = btoi(time[1]); \
    time[2] = btoi(time[2]); \
    time[2]++;               \
    if (time[2] == 75) {     \
        time[2] = 0;         \
        time[1]++;           \
        if (time[1] == 60) { \
            time[1] = 0;     \
            time[0]++;       \
        }                    \
    }                        \
    time[0] = itob(time[0]); \
    time[1] = itob(time[1]); \
    time[2] = itob(time[2]);

#define READTRACK()                           \
    if (CDR_readTrack(time) == -1) return -1; \
    buf = CDR_getBuffer();                    \
    if (buf == NULL)                          \
        return -1;                            \
    else                                      \
        CheckPPFCache(buf, time[0], time[1], time[2]);

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
    int i;

    // only try to scan if a filename is given
    if (!strlen(filename)) return -1;

    i = 0;
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

int LoadCdrom() {
    EXE_HEADER tmpHead;
    struct iso_directory_record *dir;
    uint8_t time[4], *buf;
    uint8_t mdir[4096];
    char exename[256];

    if (!g_config.HLE) {
        if (!g_config.SlowBoot) g_psxRegs.pc = g_psxRegs.GPR.n.ra;
        return 0;
    }

    time[0] = itob(0);
    time[1] = itob(2);
    time[2] = itob(0x10);

    READTRACK();

    // skip head and sub, and go to the root directory record
    dir = (struct iso_directory_record *)&buf[12 + 156];

    mmssdd(dir->extent, (char *)time);

    READDIR(mdir);

    // Load SYSTEM.CNF and scan for the main executable
    if (GetCdromFile(mdir, time, "SYSTEM.CNF;1") == -1) {
        // if SYSTEM.CNF is missing, start an existing PSX.EXE
        if (GetCdromFile(mdir, time, "PSX.EXE;1") == -1) return -1;

        READTRACK();
    } else {
        // read the SYSTEM.CNF
        READTRACK();

        sscanf((char *)buf + 12, "BOOT = cdrom:\\%255s", exename);
        if (GetCdromFile(mdir, time, exename) == -1) {
            sscanf((char *)buf + 12, "BOOT = cdrom:%255s", exename);
            if (GetCdromFile(mdir, time, exename) == -1) {
                char *ptr = strstr(reinterpret_cast<char *>(buf + 12), "cdrom:");
                if (ptr != NULL) {
                    ptr += 6;
                    while (*ptr == '\\' || *ptr == '/') ptr++;
                    strncpy(exename, ptr, 255);
                    exename[255] = '\0';
                    ptr = exename;
                    while (*ptr != '\0' && *ptr != '\r' && *ptr != '\n') ptr++;
                    *ptr = '\0';
                    if (GetCdromFile(mdir, time, exename) == -1) return -1;
                } else
                    return -1;
            }
        }

        // Read the EXE-Header
        READTRACK();
    }

    memcpy(&tmpHead, buf + 12, sizeof(EXE_HEADER));

    g_psxRegs.pc = SWAP32(tmpHead.pc0);
    g_psxRegs.GPR.n.gp = SWAP32(tmpHead.gp0);
    g_psxRegs.GPR.n.sp = SWAP32(tmpHead.s_addr);
    if (g_psxRegs.GPR.n.sp == 0) g_psxRegs.GPR.n.sp = 0x801fff00;

    tmpHead.t_size = SWAP32(tmpHead.t_size);
    tmpHead.t_addr = SWAP32(tmpHead.t_addr);

    // Read the rest of the main executable
    while (tmpHead.t_size) {
        void *ptr = (void *)PSXM(tmpHead.t_addr);

        incTime();
        READTRACK();

        if (ptr != NULL) memcpy(ptr, buf + 12, 2048);

        tmpHead.t_size -= 2048;
        tmpHead.t_addr += 2048;
    }

    return 0;
}

int LoadCdromFile(const char *filename, EXE_HEADER *head) {
    struct iso_directory_record *dir;
    uint8_t time[4], *buf;
    uint8_t mdir[4096];
    char exename[256];
    uint32_t size, addr;
    void *psxaddr;

    if (sscanf(filename, "cdrom:\\%255s", exename) <= 0) {
        // Some games omit backslash (NFS4)
        if (sscanf(filename, "cdrom:%255s", exename) <= 0) {
            PCSX::system->SysPrintf("LoadCdromFile: EXE NAME PARSING ERROR (%s (%u))\n", filename, strlen(filename));
            exit(1);
        }
    }

    time[0] = itob(0);
    time[1] = itob(2);
    time[2] = itob(0x10);

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
    g_psxCpu->Clear(addr, size / 4);
    g_psxRegs.ICache_valid = false;

    while (size) {
        incTime();
        READTRACK();

        psxaddr = (void *)PSXM(addr);
        assert(psxaddr != NULL);
        memcpy(psxaddr, buf + 12, 2048);

        size -= 2048;
        addr += 2048;
    }

    return 0;
}

int CheckCdrom() {
    struct iso_directory_record *dir;
    unsigned char time[4];
    unsigned char *buf;
    unsigned char mdir[4096];
    char exename[256];
    int i, len, c;

    FreePPFCache();

    time[0] = itob(0);
    time[1] = itob(2);
    time[2] = itob(0x10);

    READTRACK();

    memset(g_cdromLabel, 0, sizeof(g_cdromLabel));
    memset(g_cdromId, 0, sizeof(g_cdromId));
    memset(exename, 0, sizeof(exename));

    strncpy(g_cdromLabel, reinterpret_cast<char *>(buf + 52), 32);

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
                char *ptr = strstr(reinterpret_cast<char *>(buf + 12), "cdrom:");  // possibly the executable is in some subdir
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
        strcpy(g_cdromId, "SLUS99999");
    } else
        return -1;  // SYSTEM.CNF and PSX.EXE not found

    if (g_cdromId[0] == '\0') {
        len = strlen(exename);
        c = 0;
        for (i = 0; i < len; ++i) {
            if (exename[i] == ';' || c >= sizeof(g_cdromId) - 1) break;
            if (isalnum(exename[i])) g_cdromId[c++] = exename[i];
        }
    }

    if (g_config.PsxAuto) {  // autodetect system (pal or ntsc)
        if ((g_cdromId[2] == 'e') || (g_cdromId[2] == 'E') || !strncmp(g_cdromId, "DTLS3035", 8) ||
            !strncmp(g_cdromId, "PBPX95001", 9) ||  // according to redump.org, these PAL
            !strncmp(g_cdromId, "PBPX95007", 9) ||  // discs have a non-standard ID;
            !strncmp(g_cdromId, "PBPX95008", 9))    // add more serials if they are discovered.
            g_config.PsxType = PSX_TYPE_PAL;        // pal
        else
            g_config.PsxType = PSX_TYPE_NTSC;  // ntsc
    }

    if (g_config.OverClock == 0) {
        g_psxClockSpeed = 33868800;  // 33.8688 MHz (stock)
    } else {
        g_psxClockSpeed = 33868800 * g_config.PsxClock;
    }

    if (g_cdromLabel[0] == ' ') {
        strncpy(g_cdromLabel, g_cdromId, 9);
    }
    PCSX::system->SysPrintf(_("CD-ROM Label: %.32s\n"), g_cdromLabel);
    PCSX::system->SysPrintf(_("CD-ROM ID: %.9s\n"), g_cdromId);
    PCSX::system->SysPrintf(_("CD-ROM EXE Name: %.255s\n"), exename);

    memset(g_config.PsxExeName, 0, sizeof(g_config.PsxExeName));
    strncpy(g_config.PsxExeName, exename, 11);

    if (g_config.PerGameMcd) {
        char mcd1path[MAXPATHLEN] = {'\0'};
        char mcd2path[MAXPATHLEN] = {'\0'};
#ifdef _WIN32
        sprintf(mcd1path, "memcards\\games\\%s-%02d.mcd", g_config.PsxExeName, 1);
        sprintf(mcd2path, "memcards\\games\\%s-%02d.mcd", g_config.PsxExeName, 2);
#else
        // lk: dot paths should not be hardcoded here, this is for testing only
        sprintf(mcd1path, "%s/.pcsxr/memcards/games/%s-%02d.mcd", getenv("HOME"), g_config.PsxExeName, 1);
        sprintf(mcd2path, "%s/.pcsxr/memcards/games/%s-%02d.mcd", getenv("HOME"), g_config.PsxExeName, 2);
#endif
        strcpy(g_config.Mcd1, mcd1path);
        strcpy(g_config.Mcd2, mcd2path);
        LoadMcds(g_config.Mcd1, g_config.Mcd2);
    }

    BuildPPFCache();
    LoadSBI(NULL);

    return 0;
}

static int PSXGetFileType(FILE *f) {
    unsigned long current;
    uint8_t mybuf[sizeof(EXE_HEADER)];  // EXE_HEADER currently biggest
    EXE_HEADER *exe_hdr;
    FILHDR *coff_hdr;
    size_t amt;

    memset(mybuf, 0, sizeof(mybuf));
    current = ftell(f);
    fseek(f, 0L, SEEK_SET);
    amt = fread(mybuf, sizeof(mybuf), 1, f);
    fseek(f, current, SEEK_SET);

    exe_hdr = (EXE_HEADER *)mybuf;
    if (memcmp(exe_hdr->id, "PS-X EXE", 8) == 0) return PSX_EXE;

    if (mybuf[0] == 'C' && mybuf[1] == 'P' && mybuf[2] == 'E') return CPE_EXE;

    coff_hdr = (FILHDR *)mybuf;
    if (SWAPu16(coff_hdr->f_magic) == 0x0162) return COFF_EXE;

    return INVALID_EXE;
}

static void LoadLibPS() {
    char buf[MAXPATHLEN];
    FILE *f;

    // Load Net Yaroze runtime library (if exists)
    sprintf(buf, "%s/libps.exe", g_config.BiosDir);
    f = fopen(buf, "rb");

    if (f != NULL) {
        fseek(f, 0x800, SEEK_SET);
        fread(g_psxM + 0x10000, 0x61000, 1, f);
        fclose(f);
    }
}

int Load(const char *ExePath) {
    FILE *tmpFile;
    EXE_HEADER tmpHead;
    FILHDR coffHead;
    AOUTHDR optHead;
    SCNHDR section;
    int type, i;
    int retval = 0;
    uint8_t opcode;
    uint32_t section_address, section_size;
    void *psxmaddr;

    strncpy(g_cdromId, "SLUS99999", 9);
    strncpy(g_cdromLabel, "SLUS_999.99", 11);

    tmpFile = fopen(ExePath, "rb");
    if (tmpFile == NULL) {
        PCSX::system->SysPrintf(_("Error opening file: %s.\n"), ExePath);
        retval = -1;
    } else {
        LoadLibPS();

        type = PSXGetFileType(tmpFile);
        switch (type) {
            case PSX_EXE:
                fread(&tmpHead, sizeof(EXE_HEADER), 1, tmpFile);
                fseek(tmpFile, 0x800, SEEK_SET);
                fread(PSXM(SWAP32(tmpHead.t_addr)), SWAP32(tmpHead.t_size), 1, tmpFile);
                fclose(tmpFile);
                g_psxRegs.pc = SWAP32(tmpHead.pc0);
                g_psxRegs.GPR.n.gp = SWAP32(tmpHead.gp0);
                g_psxRegs.GPR.n.sp = SWAP32(tmpHead.s_addr);
                if (g_psxRegs.GPR.n.sp == 0) g_psxRegs.GPR.n.sp = 0x801fff00;
                retval = 0;
                break;

            case CPE_EXE:
                fseek(tmpFile, 6, SEEK_SET); /* Something tells me we should go to 4 and read the "08 00" here... */
                do {
                    fread(&opcode, 1, 1, tmpFile);
                    switch (opcode) {
                        case 1: /* Section loading */
                            fread(&section_address, 4, 1, tmpFile);
                            fread(&section_size, 4, 1, tmpFile);
                            section_address = SWAPu32(section_address);
                            section_size = SWAPu32(section_size);
                            EMU_LOG("Loading %08X bytes from %08X to %08X\n", section_size, ftell(tmpFile),
                                    section_address);
                            fread(PSXM(section_address), section_size, 1, tmpFile);
                            break;
                        case 3:                          /* register loading (PC only?) */
                            fseek(tmpFile, 2, SEEK_CUR); /* unknown field */
                            fread(&g_psxRegs.pc, 4, 1, tmpFile);
                            g_psxRegs.pc = SWAPu32(g_psxRegs.pc);
                            break;
                        case 0: /* End of file */
                            break;
                        default:
                            PCSX::system->SysPrintf(_("Unknown CPE opcode %02x at position %08x.\n"), opcode, ftell(tmpFile) - 1);
                            retval = -1;
                            break;
                    }
                } while (opcode != 0 && retval == 0);
                break;

            case COFF_EXE:
                fread(&coffHead, sizeof(coffHead), 1, tmpFile);
                fread(&optHead, sizeof(optHead), 1, tmpFile);

                g_psxRegs.pc = SWAP32(optHead.entry);
                g_psxRegs.GPR.n.sp = 0x801fff00;

                for (i = 0; i < SWAP16(coffHead.f_nscns); i++) {
                    fseek(tmpFile, sizeof(FILHDR) + SWAP16(coffHead.f_opthdr) + sizeof(section) * i, SEEK_SET);
                    fread(&section, sizeof(section), 1, tmpFile);

                    if (section.s_scnptr != 0) {
                        fseek(tmpFile, SWAP32(section.s_scnptr), SEEK_SET);
                        fread(PSXM(SWAP32(section.s_paddr)), SWAP32(section.s_size), 1, tmpFile);
                    } else {
                        psxmaddr = PSXM(SWAP32(section.s_paddr));
                        assert(psxmaddr != NULL);
                        memset(psxmaddr, 0, SWAP32(section.s_size));
                    }
                }
                break;

            case INVALID_EXE:
                PCSX::system->SysPrintf("%s", _("This file does not appear to be a valid PSX file.\n"));
                retval = -1;
                break;
        }
    }

    if (retval != 0) {
        g_cdromId[0] = '\0';
        g_cdromLabel[0] = '\0';
    }

    return retval;
}

static int LoadBin(unsigned long addr, char *filename) {
    int result = -1;

    FILE *f;
    long len;
    unsigned long mem = addr & 0x001fffff;

    // Load binery files
    f = fopen(filename, "rb");
    if (f != NULL) {
        fseek(f, 0, SEEK_END);
        len = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (len + mem < 0x00200000) {
            if (g_psxM) {
                int readsize = fread(g_psxM + mem, len, 1, f);
                if (readsize == len) result = 0;
            }
        }
        fclose(f);
    }

    if (result == 0)
        PCSX::system->SysPrintf(_("ng Load Bin file: [0x%08x] : %s\n"), addr, filename);
    else
        PCSX::system->SysPrintf(_("ok Load Bin file: [0x%08x] : %s\n"), addr, filename);

    return result;
}

int LoadLdrFile(const char *LdrPath) {
    FILE *tmpFile;
    int retval = 0;  //-1 is error, 0 is success

    tmpFile = fopen(LdrPath, "rt");
    if (tmpFile == NULL) {
        PCSX::system->SysPrintf(_("Error opening file: %s.\n"), LdrPath);
        retval = -1;
    } else {
        int index = 0;
        char sztext[16][256];

        memset(sztext, 0x00, sizeof(sztext));

        while (index <= 15 && fgets(&sztext[index][0], 254, tmpFile)) {
            char szaddr[256];
            char szpath[256];
            char *psrc = &sztext[index][0];
            char *paddr;
            char *ppath;
            int len;
            unsigned long addr = 0L;

            memset(szaddr, 0x00, sizeof(szaddr));
            memset(szpath, 0x00, sizeof(szpath));

            len = strlen(psrc);
            if (len > 0) {
                trim(psrc);
                trim_key(psrc, '\t');
                split(psrc, '\t', szaddr);

                paddr = szaddr;
                ppath = psrc + strlen(paddr);

                // getting address
                trim(paddr);
                trim_key(paddr, '\t');
                addr = strtoul(szaddr, NULL, 16);
                if (addr != 0) {
                    // getting bin filepath in ldrfile
                    trim(ppath);
                    trim_key(ppath, '\t');
                    memmove(szpath, ppath, sizeof(szpath));

                    // Load binary to main memory
                    LoadBin(addr, szpath);
                }
            }

            index++;
        }
    }

    return retval;
}

// STATES
#define PCSXR_HEADER_SZ (10)
#define SZ_GPUPIC (128 * 96 * 3)
static const char PcsxrHeader[32] = "STv4 PCSXR v" PACKAGE_VERSION;

// Savestate Versioning!
// If you make changes to the savestate version, please increment the value below.
static const uint32_t SaveVersion = 0x8b410008;

int SaveState(const char *file) {
    gzFile f;
    long size;

    f = gzopen(file, "wb9");  // Best ratio but slow
    if (f == NULL) return -1;
    return SaveStateGz(f, &size);
}

int LoadState(const char *file) {
    gzFile f;

    f = gzopen(file, "rb");
    if (f == NULL) return -1;
    return LoadStateGz(f);
}

static uint32_t s_mem_cur_save_count = 0, mem_last_save;
static bool s_mem_wrapped = false;  // Whether we went past max count and restarted counting

void CreateRewindState() {
    if (g_config.RewindCount > 0) {
        SaveStateMem(mem_last_save = s_mem_cur_save_count++);

        if (s_mem_cur_save_count > g_config.RewindCount) {
            s_mem_cur_save_count = 0;
            s_mem_wrapped = true;
        }
    }
}

void RewindState() {
    s_mem_cur_save_count--;
    if (s_mem_cur_save_count > g_config.RewindCount && s_mem_wrapped) {
        s_mem_cur_save_count = g_config.RewindCount;
        s_mem_wrapped = false;
    } else if (s_mem_cur_save_count > g_config.RewindCount && !s_mem_wrapped) {
        s_mem_cur_save_count++;
        return;
    } else if (mem_last_save == s_mem_cur_save_count - 1) {
        s_mem_cur_save_count = 0;
        return;
    }
    LoadStateMem(s_mem_cur_save_count);
}

static GPUFreeze_t *s_gpufP = NULL;
static SPUFreeze_t *s_spufP = NULL;

int SaveStateMem(const uint32_t id) { return 0; }
int LoadStateMem(const uint32_t id) { return 0; }
void CleanupMemSaveStates() {}

int SaveStateGz(gzFile f, long *gzsize) {
    int Size;
    unsigned char pMemGpuPic[SZ_GPUPIC];

    // if (f == NULL) return -1;

    gzwrite(f, (void *)PcsxrHeader, sizeof(PcsxrHeader));
    gzwrite(f, (void *)&SaveVersion, sizeof(uint32_t));
    gzwrite(f, (void *)&g_config.HLE, sizeof(bool));

    if (gzsize) GPU_getScreenPic(pMemGpuPic);  // Not necessary with ephemeral saves
    gzwrite(f, pMemGpuPic, SZ_GPUPIC);

    if (g_config.HLE) psxBiosFreeze(1);

    gzwrite(f, g_psxM, 0x00200000);
    gzwrite(f, g_psxR, 0x00080000);
    gzwrite(f, g_psxH, 0x00010000);
    gzwrite(f, (void *)&g_psxRegs, sizeof(g_psxRegs));

    // gpu
    if (!s_gpufP) s_gpufP = (GPUFreeze_t *)malloc(sizeof(GPUFreeze_t));
    s_gpufP->ulFreezeVersion = 1;
    GPU_freeze(1, s_gpufP);
    gzwrite(f, s_gpufP, sizeof(GPUFreeze_t));

    // SPU Plugin cannot change during run, so we query size info just once per session
    if (!s_spufP) {
        s_spufP = (SPUFreeze_t *)malloc(offsetof(SPUFreeze_t, SPUPorts));  // only first 3 elements (up to Size)
        SPU_freeze(2, s_spufP);
        Size = s_spufP->Size;
        PCSX::system->SysPrintf("SPUFreezeSize %i/(%i)\n", Size, offsetof(SPUFreeze_t, SPUPorts));
        free(s_spufP);
        s_spufP = (SPUFreeze_t *)malloc(Size);
        s_spufP->Size = Size;

        if (s_spufP->Size <= 0) {
            gzclose(f);
            free(s_spufP);
            s_spufP = NULL;
            return 1;  // error
        }
    }
    // spu
    gzwrite(f, &(s_spufP->Size), 4);
    SPU_freeze(1, s_spufP);
    gzwrite(f, s_spufP, s_spufP->Size);

    sioFreeze(f, 1);
    cdrFreeze(f, 1);
    psxHwFreeze(f, 1);
    psxRcntFreeze(f, 1);
    mdecFreeze(f, 1);

    if (gzsize) *gzsize = gztell(f);
    gzclose(f);

    return 0;
}

int LoadStateGz(gzFile f) {
    SPUFreeze_t *_spufP;
    int Size;
    char header[sizeof(PcsxrHeader)];
    uint32_t version;
    bool hle;

    if (f == NULL) return -1;

    gzread(f, header, sizeof(header));
    gzread(f, &version, sizeof(uint32_t));
    gzread(f, &hle, sizeof(bool));

    // Compare header only "STv4 PCSXR" part no version
    if (strncmp(PcsxrHeader, header, PCSXR_HEADER_SZ) != 0 || version != SaveVersion || hle != g_config.HLE) {
        gzclose(f);
        return -1;
    }

    g_psxCpu->Reset();
    gzseek(f, SZ_GPUPIC, SEEK_CUR);

    gzread(f, g_psxM, 0x00200000);
    gzread(f, g_psxR, 0x00080000);
    gzread(f, g_psxH, 0x00010000);
    gzread(f, (void *)&g_psxRegs, sizeof(g_psxRegs));

    if (g_config.HLE) psxBiosFreeze(0);

    // gpu
    if (!s_gpufP) s_gpufP = (GPUFreeze_t *)malloc(sizeof(GPUFreeze_t));
    gzread(f, s_gpufP, sizeof(GPUFreeze_t));
    GPU_freeze(0, s_gpufP);

    // spu
    gzread(f, &Size, 4);
    _spufP = (SPUFreeze_t *)malloc(Size);
    gzread(f, _spufP, Size);
    SPU_freeze(0, _spufP);
    free(_spufP);

    sioFreeze(f, 0);
    cdrFreeze(f, 0);
    psxHwFreeze(f, 0);
    psxRcntFreeze(f, 0);
    mdecFreeze(f, 0);

    gzclose(f);

    return 0;
}

int CheckState(const char *file) {
    gzFile f;
    char header[sizeof(PcsxrHeader)];
    uint32_t version;
    bool hle;

    f = gzopen(file, "rb");
    if (f == NULL) return -1;

    gzread(f, header, sizeof(header));
    gzread(f, &version, sizeof(uint32_t));
    gzread(f, &hle, sizeof(bool));

    gzclose(f);

    // Compare header only "STv4 PCSXR" part no version
    if (strncmp(PcsxrHeader, header, PCSXR_HEADER_SZ) != 0 || version != SaveVersion || hle != g_config.HLE) return -1;

    return 0;
}

// NET Function Helpers

int SendPcsxInfo() {
    if (NET_recvData == NULL || NET_sendData == NULL) return 0;

    NET_sendData(&g_config.Xa, sizeof(g_config.Xa), PSE_NET_BLOCKING);
    NET_sendData(&g_config.SioIrq, sizeof(g_config.SioIrq), PSE_NET_BLOCKING);
    NET_sendData(&g_config.SpuIrq, sizeof(g_config.SpuIrq), PSE_NET_BLOCKING);
    NET_sendData(&g_config.RCntFix, sizeof(g_config.RCntFix), PSE_NET_BLOCKING);
    NET_sendData(&g_config.PsxType, sizeof(g_config.PsxType), PSE_NET_BLOCKING);
    NET_sendData(&g_config.Cpu, sizeof(g_config.Cpu), PSE_NET_BLOCKING);

    return 0;
}

int RecvPcsxInfo() {
    int tmp;

    if (NET_recvData == NULL || NET_sendData == NULL) return 0;

    NET_recvData(&g_config.Xa, sizeof(g_config.Xa), PSE_NET_BLOCKING);
    NET_recvData(&g_config.SioIrq, sizeof(g_config.SioIrq), PSE_NET_BLOCKING);
    NET_recvData(&g_config.SpuIrq, sizeof(g_config.SpuIrq), PSE_NET_BLOCKING);
    NET_recvData(&g_config.RCntFix, sizeof(g_config.RCntFix), PSE_NET_BLOCKING);
    NET_recvData(&g_config.PsxType, sizeof(g_config.PsxType), PSE_NET_BLOCKING);

    PCSX::system->SysUpdate();

    tmp = g_config.Cpu;
    NET_recvData(&g_config.Cpu, sizeof(g_config.Cpu), PSE_NET_BLOCKING);
    if (tmp != g_config.Cpu) {
        g_psxCpu->Shutdown();
        if (g_config.Cpu == CPU_INTERPRETER)
            g_psxCpu = &g_psxInt;
        else
            g_psxCpu = &g_psxRec;
        if (g_psxCpu->Init() == -1) {
            PCSX::system->SysClose();
            return -1;
        }
        g_psxCpu->Reset();
    }

    return 0;
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
    int i;
    for (i = 0; i < len; i++) {
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
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
    0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
    0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
    0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
    0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
    0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
    0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
    0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
    0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
    0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
    0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
    0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
    0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
    0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
    0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
    0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
    0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
    0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
    0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
    0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
    0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
    0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
    0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
};

uint16_t calcCrc(uint8_t *d, int len) {
    uint16_t crc = 0;
    int i;

    for (i = 0; i < len; i++) {
        crc = crctab[(crc >> 8) ^ d[i]] ^ (crc << 8);
    }

    return ~crc;
}
