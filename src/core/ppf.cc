/*  PPF/SBI Support for PCSX-Reloaded
 *  Copyright (c) 2009, Wei Mingzhi <whistler_wmz@users.sf.net>.
 *  Copyright (c) 2010, shalma.
 *
 *  PPF code based on P.E.Op.S CDR Plugin by Pete Bernert.
 *  Copyright (c) 2002, Pete Bernert.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "core/ppf.h"

#include "core/cdrom.h"
#include "core/psxemulator.h"

// using a linked data list, and address array
void PCSX::PPF::FillPPFCache() {
    PPF_DATA *p;
    PPF_CACHE *pc;
    int32_t lastaddr;

    p = s_ppfHead;
    lastaddr = -1;
    s_iPPFNum = 0;

    while (p != NULL) {
        if (p->addr != lastaddr) s_iPPFNum++;
        lastaddr = p->addr;
        p = p->pNext;
    }

    if (s_iPPFNum <= 0) return;

    pc = s_ppfCache = (PPF_CACHE *)malloc(s_iPPFNum * sizeof(PPF_CACHE));

    s_iPPFNum--;
    p = s_ppfHead;
    lastaddr = -1;

    while (p != NULL) {
        if (p->addr != lastaddr) {
            pc->addr = p->addr;
            pc->pNext = p;
            pc++;
        }
        lastaddr = p->addr;
        p = p->pNext;
    }
}

void PCSX::PPF::FreePPFCache() {
    PPF_DATA *p = s_ppfHead;
    void *pn;

    while (p != NULL) {
        pn = p->pNext;
        free(p);
        p = (PPF_DATA *)pn;
    }
    s_ppfHead = NULL;
    s_ppfLast = NULL;

    if (s_ppfCache != NULL) free(s_ppfCache);
    s_ppfCache = NULL;
}

void PCSX::PPF::CheckPPFCache(uint8_t *pB, uint8_t m, uint8_t s, uint8_t f) {
    PPF_CACHE *pcstart, *pcend, *pcpos;
    int addr = PCSX::CDRom::MSF2SECT(PCSX::CDRom::btoi(m), PCSX::CDRom::btoi(s), PCSX::CDRom::btoi(f)), pos, anz, start;

    if (s_ppfCache == NULL) return;

    pcstart = s_ppfCache;
    if (addr < pcstart->addr) return;
    pcend = s_ppfCache + s_iPPFNum;
    if (addr > pcend->addr) return;

    while (1) {
        if (addr == pcend->addr) {
            pcpos = pcend;
            break;
        }

        pcpos = pcstart + (pcend - pcstart) / 2;
        if (pcpos == pcstart) break;
        if (addr < pcpos->addr) {
            pcend = pcpos;
            continue;
        }
        if (addr > pcpos->addr) {
            pcstart = pcpos;
            continue;
        }
        break;
    }

    if (addr == pcpos->addr) {
        PPF_DATA *p = pcpos->pNext;
        while (p != NULL && p->addr == addr) {
            pos = p->pos - (PCSX::CDRom::CD_FRAMESIZE_RAW - PCSX::CDRom::DATA_SIZE);
            anz = p->anz;
            if (pos < 0) {
                start = -pos;
                pos = 0;
                anz -= start;
            } else
                start = 0;
            memcpy(pB + pos, (unsigned char *)(p + 1) + start, anz);
            p = p->pNext;
        }
    }
}

void PCSX::PPF::AddToPPF(int32_t ladr, int32_t pos, int32_t anz, uint8_t *ppfmem) {
    if (s_ppfHead == NULL) {
        s_ppfHead = (PPF_DATA *)malloc(sizeof(PPF_DATA) + anz);
        s_ppfHead->addr = ladr;
        s_ppfHead->pNext = NULL;
        s_ppfHead->pos = pos;
        s_ppfHead->anz = anz;
        memcpy(s_ppfHead + 1, ppfmem, anz);
        s_iPPFNum = 1;
        s_ppfLast = s_ppfHead;
    } else {
        PPF_DATA *p = s_ppfHead;
        PPF_DATA *plast = NULL;
        PPF_DATA *padd;

        if (ladr > s_ppfLast->addr || (ladr == s_ppfLast->addr && pos > s_ppfLast->pos)) {
            p = NULL;
            plast = s_ppfLast;
        } else {
            while (p != NULL) {
                if (ladr < p->addr) break;
                if (ladr == p->addr) {
                    while (p && ladr == p->addr && pos > p->pos) {
                        plast = p;
                        p = p->pNext;
                    }
                    break;
                }
                plast = p;
                p = p->pNext;
            }
        }

        padd = (PPF_DATA *)malloc(sizeof(PPF_DATA) + anz);
        padd->addr = ladr;
        padd->pNext = p;
        padd->pos = pos;
        padd->anz = anz;
        memcpy(padd + 1, ppfmem, anz);
        s_iPPFNum++;
        if (plast == NULL)
            s_ppfHead = padd;
        else
            plast->pNext = padd;

        if (padd->pNext == NULL) s_ppfLast = padd;
    }
}

void PCSX::PPF::BuildPPFCache() {
    FILE *ppffile;
    char buffer[12];
    char method, undo = 0, blockcheck = 0;
    int dizlen = 0, dizyn;
    unsigned char ppfmem[512];
    char szPPF[MAXPATHLEN];
    int count, seekpos, pos;
    uint32_t anz;  // use 32-bit to avoid stupid overflows
    int32_t ladr, off, anx;

    FreePPFCache();

    if (PCSX::g_emulator->m_cdromId[0] == '\0') return;

    // Generate filename in the format of SLUS_123.45
    buffer[0] = toupper(PCSX::g_emulator->m_cdromId[0]);
    buffer[1] = toupper(PCSX::g_emulator->m_cdromId[1]);
    buffer[2] = toupper(PCSX::g_emulator->m_cdromId[2]);
    buffer[3] = toupper(PCSX::g_emulator->m_cdromId[3]);
    buffer[4] = '_';
    buffer[5] = PCSX::g_emulator->m_cdromId[4];
    buffer[6] = PCSX::g_emulator->m_cdromId[5];
    buffer[7] = PCSX::g_emulator->m_cdromId[6];
    buffer[8] = '.';
    buffer[9] = PCSX::g_emulator->m_cdromId[7];
    buffer[10] = PCSX::g_emulator->m_cdromId[8];
    buffer[11] = '\0';

    sprintf(szPPF, "%s/%s", PCSX::g_emulator->settings.get<Emulator::SettingPpfDir>().string().c_str(), buffer);

    ppffile = fopen(szPPF, "rb");
    if (ppffile == NULL) return;

    memset(buffer, 0, 5);
    if (fread(buffer, 3, 1, ppffile) != 1) {
        throw("File read error.");
    }

    if (strcmp(buffer, "PPF") != 0) {
        PCSX::g_system->printf(_("Invalid PPF patch: %s.\n"), szPPF);
        fclose(ppffile);
        return;
    }

    fseek(ppffile, 5, SEEK_SET);
    method = fgetc(ppffile);

    switch (method) {
        case 0:  // ppf1
            fseek(ppffile, 0, SEEK_END);
            count = ftell(ppffile);
            count -= 56;
            seekpos = 56;
            break;

        case 1:  // ppf2
            fseek(ppffile, -8, SEEK_END);

            memset(buffer, 0, 5);
            if (fread(buffer, 4, 1, ppffile) != 1) {
                throw("File read error.");
            }

            if (strcmp(".DIZ", buffer) != 0) {
                dizyn = 0;
            } else {
                if (fread(&dizlen, 4, 1, ppffile) != 1) {
                    throw("File read error.");
                }
                dizlen = SWAP_LE32(dizlen);
                dizyn = 1;
            }

            fseek(ppffile, 0, SEEK_END);
            count = ftell(ppffile);

            if (dizyn == 0) {
                count -= 1084;
                seekpos = 1084;
            } else {
                count -= 1084;
                count -= 38;
                count -= dizlen;
                seekpos = 1084;
            }
            break;

        case 2:  // ppf3
            fseek(ppffile, 57, SEEK_SET);
            blockcheck = fgetc(ppffile);
            undo = fgetc(ppffile);

            fseek(ppffile, -6, SEEK_END);
            memset(buffer, 0, 5);
            if (fread(buffer, 4, 1, ppffile) != 1) {
                throw("File read error.");
            }
            dizlen = 0;

            if (strcmp(".DIZ", buffer) == 0) {
                fseek(ppffile, -2, SEEK_END);
                if (fread(&dizlen, 2, 1, ppffile) != 1) {
                    throw("File read error.");
                }
                dizlen = SWAP_LE32(dizlen);
                dizlen += 36;
            }

            fseek(ppffile, 0, SEEK_END);
            count = ftell(ppffile);
            count -= dizlen;

            if (blockcheck) {
                seekpos = 1084;
                count -= 1084;
            } else {
                seekpos = 60;
                count -= 60;
            }
            break;

        default:
            fclose(ppffile);
            PCSX::g_system->printf(_("Unsupported PPF version (%d).\n"), method + 1);
            return;
    }

    // now do the data reading
    do {
        fseek(ppffile, seekpos, SEEK_SET);
        if (fread(&pos, 4, 1, ppffile) != 1) {
            throw("File read error.");
        }
        pos = SWAP_LE32(pos);

        if (method == 2) {
            if (fread(buffer, 4, 1, ppffile) != 1) {  // skip 4 bytes on ppf3 (no int64 support here)
                throw("File read error.");
            }
        }

        anz = fgetc(ppffile);
        if (fread(ppfmem, anz, 1, ppffile) != 1) {
            throw("File read error.");
        }

        ladr = pos / PCSX::CDRom::CD_FRAMESIZE_RAW;
        off = pos % PCSX::CDRom::CD_FRAMESIZE_RAW;

        if (off + anz > PCSX::CDRom::CD_FRAMESIZE_RAW) {
            anx = off + anz - PCSX::CDRom::CD_FRAMESIZE_RAW;
            anz -= (unsigned char)anx;
            AddToPPF(ladr + 1, 0, anx, &ppfmem[anz]);
        }

        AddToPPF(ladr, off, anz, ppfmem);  // add to link list

        if (method == 2) {
            if (undo) anz += anz;
            anz += 4;
        }

        seekpos = seekpos + 5 + anz;
        count = count - 5 - anz;
    } while (count != 0);  // loop til end

    fclose(ppffile);

    FillPPFCache();  // build address array

    PCSX::g_system->printf(_("Loaded PPF %d.0 patch: %s.\n"), method + 1, szPPF);
}
