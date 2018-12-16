/*  Cheat Support for PCSX-Reloaded
 *  Copyright (c) 2009, Wei Mingzhi <whistler_wmz@users.sf.net>.
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

#include "core/cheat.h"
#include "core/psxcommon.h"
#include "core/psxmem.h"
#include "core/r3000a.h"

Cheat *g_cheats = NULL;
int g_numCheats = 0;
static int s_numCheatsAllocated = 0;

CheatCode *g_cheatCodes = NULL;
int g_numCodes = 0;
static int s_numCodesAllocated = 0;

s8 *g_prevM = NULL;
u32 *g_searchResults = NULL;
int g_numSearchResults = 0;
static int s_numSearchResultsAllocated = 0;

#define ALLOC_INCREMENT 100

void ClearAllCheats() {
    if (g_cheats != NULL) {
        for (int i = 0; i < g_numCheats; i++) {
            free(g_cheats[i].Descr);
        }
        free(g_cheats);
    }

    g_cheats = NULL;
    g_numCheats = 0;
    s_numCheatsAllocated = 0;

    if (g_cheatCodes != NULL) {
        free(g_cheatCodes);
    }

    g_cheatCodes = NULL;
    g_numCodes = 0;
    s_numCodesAllocated = 0;
}

// load cheats from the specific filename
void LoadCheats(const char *filename) {
    FILE *fp;
    char buf[256];
    int count = 0;
    unsigned int t1, t2;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        PCSX::system->SysPrintf(_("Could not load cheats from: %s\n"), filename);
        return;
    }

    ClearAllCheats();

    while (fgets(buf, 255, fp) != NULL) {
        buf[255] = '\0';
        trim(buf);

        // Skip comment or blank lines
        if (buf[0] == '#' || buf[0] == ';' || buf[0] == '/' || buf[0] == '\"' || buf[0] == '\0') continue;

        if (buf[0] == '[' && buf[strlen(buf) - 1] == ']') {
            if (g_numCheats > 0) g_cheats[g_numCheats - 1].n = count;

            if (g_numCheats >= s_numCheatsAllocated) {
                s_numCheatsAllocated += ALLOC_INCREMENT;

                if (g_cheats == NULL) {
                    assert(g_numCheats == 0);
                    assert(s_numCheatsAllocated == ALLOC_INCREMENT);
                    g_cheats = (Cheat *)malloc(sizeof(Cheat) * s_numCheatsAllocated);
                } else {
                    g_cheats = (Cheat *)realloc(g_cheats, sizeof(Cheat) * s_numCheatsAllocated);
                }
            }

            buf[strlen(buf) - 1] = '\0';
            count = 0;

            if (buf[1] == '*') {
                g_cheats[g_numCheats].Descr = strdup(buf + 2);
                g_cheats[g_numCheats].Enabled = 1;
            } else {
                g_cheats[g_numCheats].Descr = strdup(buf + 1);
                g_cheats[g_numCheats].Enabled = 0;
            }

            g_cheats[g_numCheats].First = g_numCodes;

            g_numCheats++;
            continue;
        }

        if (g_numCheats <= 0) continue;

        if (g_numCodes >= s_numCodesAllocated) {
            s_numCodesAllocated += ALLOC_INCREMENT;

            if (g_cheatCodes == NULL) {
                assert(g_numCodes == 0);
                assert(s_numCodesAllocated == ALLOC_INCREMENT);
                g_cheatCodes = (CheatCode *)malloc(sizeof(CheatCode) * s_numCodesAllocated);
            } else {
                g_cheatCodes = (CheatCode *)realloc(g_cheatCodes, sizeof(CheatCode) * s_numCodesAllocated);
            }
        }

        sscanf(buf, "%x %x", &t1, &t2);

        g_cheatCodes[g_numCodes].Addr = t1;
        g_cheatCodes[g_numCodes].Val = t2;

        g_numCodes++;
        count++;
    }

    if (g_numCheats > 0) g_cheats[g_numCheats - 1].n = count;

    fclose(fp);

    PCSX::system->SysPrintf(_("Cheats loaded from: %s\n"), filename);
}

// save all cheats to the specified filename
void SaveCheats(const char *filename) {
    FILE *fp;
    int i, j;

    fp = fopen(filename, "w");
    if (fp == NULL) {
        return;
    }

    for (i = 0; i < g_numCheats; i++) {
        // write the description
        if (g_cheats[i].Enabled)
            fprintf(fp, "[*%s]\n", g_cheats[i].Descr);
        else
            fprintf(fp, "[%s]\n", g_cheats[i].Descr);

        // write all cheat codes
        for (j = 0; j < g_cheats[i].n; j++) {
            fprintf(fp, "%.8X %.4X\n", g_cheatCodes[g_cheats[i].First + j].Addr, g_cheatCodes[g_cheats[i].First + j].Val);
        }

        fprintf(fp, "\n");
    }

    fclose(fp);

    PCSX::system->SysPrintf(_("Cheats saved to: %s\n"), filename);
}

// apply all enabled cheats
void ApplyCheats() {
    int i, j, k, endindex;

    for (i = 0; i < g_numCheats; i++) {
        if (!g_cheats[i].Enabled) {
            continue;
        }

        // process all cheat codes
        endindex = g_cheats[i].First + g_cheats[i].n;

        for (j = g_cheats[i].First; j < endindex; j++) {
            u8 type = (uint8_t)(g_cheatCodes[j].Addr >> 24);
            u32 addr = (g_cheatCodes[j].Addr & 0x001FFFFF);
            u16 val = g_cheatCodes[j].Val;
            u32 taddr;

            switch (type) {
                case CHEAT_CONST8:
                    psxMu8ref(addr) = (u8)val;
                    break;

                case CHEAT_CONST16:
                    psxMu16ref(addr) = SWAPu16(val);
                    break;

                case CHEAT_INC16:
                    psxMu16ref(addr) = SWAPu16(psxMu16(addr) + val);
                    break;

                case CHEAT_DEC16:
                    psxMu16ref(addr) = SWAPu16(psxMu16(addr) - val);
                    break;

                case CHEAT_INC8:
                    psxMu8ref(addr) += (u8)val;
                    break;

                case CHEAT_DEC8:
                    psxMu8ref(addr) -= (u8)val;
                    break;

                case CHEAT_SLIDE:
                    j++;
                    if (j >= endindex) break;

                    type = (uint8_t)(g_cheatCodes[j].Addr >> 24);
                    taddr = (g_cheatCodes[j].Addr & 0x001FFFFF);
                    val = g_cheatCodes[j].Val;

                    if (type == CHEAT_CONST8) {
                        for (k = 0; k < ((addr >> 8) & 0xFF); k++) {
                            psxMu8ref(taddr) = (u8)val;
                            taddr += (s8)(addr & 0xFF);
                            val += (s8)(g_cheatCodes[j - 1].Val & 0xFF);
                        }
                    } else if (type == CHEAT_CONST16) {
                        for (k = 0; k < ((addr >> 8) & 0xFF); k++) {
                            psxMu16ref(taddr) = SWAPu16(val);
                            taddr += (s8)(addr & 0xFF);
                            val += (s8)(g_cheatCodes[j - 1].Val & 0xFF);
                        }
                    }
                    break;

                case CHEAT_MEMCPY:
                    j++;
                    if (j >= endindex) break;

                    taddr = (g_cheatCodes[j].Addr & 0x001FFFFF);
                    for (k = 0; k < val; k++) {
                        psxMu8ref(taddr + k) = PSXMu8(addr + k);
                    }
                    break;

                case CHEAT_EQU8:
                    if (PSXMu8(addr) != (u8)val) j++;  // skip the next code
                    break;

                case CHEAT_NOTEQU8:
                    if (PSXMu8(addr) == (u8)val) j++;  // skip the next code
                    break;

                case CHEAT_LESSTHAN8:
                    if (PSXMu8(addr) >= (u8)val) j++;  // skip the next code
                    break;

                case CHEAT_GREATERTHAN8:
                    if (PSXMu8(addr) <= (u8)val) j++;  // skip the next code
                    break;

                case CHEAT_EQU16:
                    if (PSXMu16(addr) != val) j++;  // skip the next code
                    break;

                case CHEAT_NOTEQU16:
                    if (PSXMu16(addr) == val) j++;  // skip the next code
                    break;

                case CHEAT_LESSTHAN16:
                    if (PSXMu16(addr) >= val) j++;  // skip the next code
                    break;

                case CHEAT_GREATERTHAN16:
                    if (PSXMu16(addr) <= val) j++;  // skip the next code
                    break;
            }
        }
    }
}

int AddCheat(const char *descr, char *code) {
    int c = 1;
    char *p1, *p2;

    if (g_numCheats >= s_numCheatsAllocated) {
        s_numCheatsAllocated += ALLOC_INCREMENT;

        if (g_cheats == NULL) {
            assert(g_numCheats == 0);
            assert(s_numCheatsAllocated == ALLOC_INCREMENT);
            g_cheats = (Cheat *)malloc(sizeof(Cheat) * s_numCheatsAllocated);
        } else {
            g_cheats = (Cheat *)realloc(g_cheats, sizeof(Cheat) * s_numCheatsAllocated);
        }
    }

    g_cheats[g_numCheats].Descr = strdup(descr[0] ? descr : _("(Untitled)"));
    g_cheats[g_numCheats].Enabled = 0;
    g_cheats[g_numCheats].First = g_numCodes;
    g_cheats[g_numCheats].n = 0;

    p1 = code;
    p2 = code;

    while (c) {
        unsigned int t1, t2;

        while (*p2 != '\n' && *p2 != '\0') p2++;

        if (*p2 == '\0') c = 0;

        *p2 = '\0';
        p2++;

        t1 = 0;
        t2 = 0;
        sscanf(p1, "%x %x", &t1, &t2);

        if (t1 > 0x10000000) {
            if (g_numCodes >= s_numCodesAllocated) {
                s_numCodesAllocated += ALLOC_INCREMENT;

                if (g_cheatCodes == NULL) {
                    assert(g_numCodes == 0);
                    assert(s_numCodesAllocated == ALLOC_INCREMENT);
                    g_cheatCodes = (CheatCode *)malloc(sizeof(CheatCode) * s_numCodesAllocated);
                } else {
                    g_cheatCodes = (CheatCode *)realloc(g_cheatCodes, sizeof(CheatCode) * s_numCodesAllocated);
                }
            }

            g_cheatCodes[g_numCodes].Addr = t1;
            g_cheatCodes[g_numCodes].Val = t2;
            g_numCodes++;
            g_cheats[g_numCheats].n++;
        }

        p1 = p2;
    }

    if (g_cheats[g_numCheats].n == 0) {
        return -1;
    }

    g_numCheats++;
    return 0;
}

void RemoveCheat(int index) {
    assert(index >= 0 && index < g_numCheats);

    free(g_cheats[index].Descr);

    while (index < g_numCheats - 1) {
        g_cheats[index] = g_cheats[index + 1];
        index++;
    }

    g_numCheats--;
}

int EditCheat(int index, const char *descr, char *code) {
    int c = 1;
    int prev = g_numCodes;
    char *p1, *p2;

    assert(index >= 0 && index < g_numCheats);

    p1 = code;
    p2 = code;

    while (c) {
        unsigned int t1, t2;

        while (*p2 != '\n' && *p2 != '\0') p2++;

        if (*p2 == '\0') c = 0;

        *p2 = '\0';
        p2++;

        t1 = 0;
        t2 = 0;
        sscanf(p1, "%x %x", &t1, &t2);

        if (t1 > 0x10000000) {
            if (g_numCodes >= s_numCodesAllocated) {
                s_numCodesAllocated += ALLOC_INCREMENT;

                if (g_cheatCodes == NULL) {
                    assert(g_numCodes == 0);
                    assert(s_numCodesAllocated == ALLOC_INCREMENT);
                    g_cheatCodes = (CheatCode *)malloc(sizeof(CheatCode) * s_numCodesAllocated);
                } else {
                    g_cheatCodes = (CheatCode *)realloc(g_cheatCodes, sizeof(CheatCode) * s_numCodesAllocated);
                }
            }

            g_cheatCodes[g_numCodes].Addr = t1;
            g_cheatCodes[g_numCodes].Val = t2;
            g_numCodes++;
        }

        p1 = p2;
    }

    if (g_numCodes == prev) {
        return -1;
    }

    free(g_cheats[index].Descr);
    g_cheats[index].Descr = strdup(descr[0] ? descr : _("(Untitled)"));
    g_cheats[index].First = prev;
    g_cheats[index].n = g_numCodes - prev;

    return 0;
}

void FreeCheatSearchResults() {
    if (g_searchResults != NULL) {
        free(g_searchResults);
    }
    g_searchResults = NULL;

    g_numSearchResults = 0;
    s_numSearchResultsAllocated = 0;
}

void FreeCheatSearchMem() {
    if (g_prevM != NULL) {
        free(g_prevM);
    }
    g_prevM = NULL;
}

void CheatSearchBackupMemory() {
    if (g_prevM != NULL) {
        memcpy(g_prevM, g_psxM, 0x200000);
    }
}

static void CheatSearchInitBackupMemory() {
    if (g_prevM == NULL) {
        g_prevM = (s8 *)malloc(0x200000);
        CheatSearchBackupMemory();
    }
}

static void CheatSearchAddResult(u32 addr) {
    if (g_numSearchResults >= s_numSearchResultsAllocated) {
        s_numSearchResultsAllocated += ALLOC_INCREMENT;

        if (g_searchResults == NULL) {
            g_searchResults = (u32 *)malloc(sizeof(u32) * s_numSearchResultsAllocated);
        } else {
            g_searchResults = (u32 *)realloc(g_searchResults, sizeof(u32) * s_numSearchResultsAllocated);
        }
    }

    g_searchResults[g_numSearchResults++] = addr;
}

void CheatSearchEqual8(u8 val) {
    u32 i, j;

    CheatSearchInitBackupMemory();

    if (g_searchResults == NULL) {
        // search the whole memory
        for (i = 0; i < 0x200000; i++) {
            if (PSXMu8(i) == val) {
                CheatSearchAddResult(i);
            }
        }
    } else {
        // only search within the previous results
        j = 0;

        for (i = 0; i < g_numSearchResults; i++) {
            if (PSXMu8(g_searchResults[i]) == val) {
                g_searchResults[j++] = g_searchResults[i];
            }
        }

        g_numSearchResults = j;
    }
}

void CheatSearchEqual16(u16 val) {
    u32 i, j;

    CheatSearchInitBackupMemory();

    if (g_searchResults == NULL) {
        // search the whole memory
        for (i = 0; i < 0x200000; i += 2) {
            if (PSXMu16(i) == val) {
                CheatSearchAddResult(i);
            }
        }
    } else {
        // only search within the previous results
        j = 0;

        for (i = 0; i < g_numSearchResults; i++) {
            if (PSXMu16(g_searchResults[i]) == val) {
                g_searchResults[j++] = g_searchResults[i];
            }
        }

        g_numSearchResults = j;
    }
}

void CheatSearchEqual32(u32 val) {
    u32 i, j;

    CheatSearchInitBackupMemory();

    if (g_searchResults == NULL) {
        // search the whole memory
        for (i = 0; i < 0x200000; i += 4) {
            if (PSXMu32(i) == val) {
                CheatSearchAddResult(i);
            }
        }
    } else {
        // only search within the previous results
        j = 0;

        for (i = 0; i < g_numSearchResults; i++) {
            if (PSXMu32(g_searchResults[i]) == val) {
                g_searchResults[j++] = g_searchResults[i];
            }
        }

        g_numSearchResults = j;
    }
}

void CheatSearchNotEqual8(u8 val) {
    u32 i, j;

    CheatSearchInitBackupMemory();

    if (g_searchResults == NULL) {
        // search the whole memory
        for (i = 0; i < 0x200000; i++) {
            if (PSXMu8(i) != val) {
                CheatSearchAddResult(i);
            }
        }
    } else {
        // only search within the previous results
        j = 0;

        for (i = 0; i < g_numSearchResults; i++) {
            if (PSXMu8(g_searchResults[i]) != val) {
                g_searchResults[j++] = g_searchResults[i];
            }
        }

        g_numSearchResults = j;
    }
}

void CheatSearchNotEqual16(u16 val) {
    u32 i, j;

    CheatSearchInitBackupMemory();

    if (g_searchResults == NULL) {
        // search the whole memory
        for (i = 0; i < 0x200000; i += 2) {
            if (PSXMu16(i) != val) {
                CheatSearchAddResult(i);
            }
        }
    } else {
        // only search within the previous results
        j = 0;

        for (i = 0; i < g_numSearchResults; i++) {
            if (PSXMu16(g_searchResults[i]) != val) {
                g_searchResults[j++] = g_searchResults[i];
            }
        }

        g_numSearchResults = j;
    }
}

void CheatSearchNotEqual32(u32 val) {
    u32 i, j;

    CheatSearchInitBackupMemory();

    if (g_searchResults == NULL) {
        // search the whole memory
        for (i = 0; i < 0x200000; i += 4) {
            if (PSXMu32(i) != val) {
                CheatSearchAddResult(i);
            }
        }
    } else {
        // only search within the previous results
        j = 0;

        for (i = 0; i < g_numSearchResults; i++) {
            if (PSXMu32(g_searchResults[i]) != val) {
                g_searchResults[j++] = g_searchResults[i];
            }
        }

        g_numSearchResults = j;
    }
}

void CheatSearchRange8(u8 min, u8 max) {
    u32 i, j;

    CheatSearchInitBackupMemory();

    if (g_searchResults == NULL) {
        // search the whole memory
        for (i = 0; i < 0x200000; i++) {
            if (PSXMu8(i) >= min && PSXMu8(i) <= max) {
                CheatSearchAddResult(i);
            }
        }
    } else {
        // only search within the previous results
        j = 0;

        for (i = 0; i < g_numSearchResults; i++) {
            if (PSXMu8(g_searchResults[i]) >= min && PSXMu8(g_searchResults[i]) <= max) {
                g_searchResults[j++] = g_searchResults[i];
            }
        }

        g_numSearchResults = j;
    }
}

void CheatSearchRange16(u16 min, u16 max) {
    u32 i, j;

    CheatSearchInitBackupMemory();

    if (g_searchResults == NULL) {
        // search the whole memory
        for (i = 0; i < 0x200000; i += 2) {
            if (PSXMu16(i) >= min && PSXMu16(i) <= max) {
                CheatSearchAddResult(i);
            }
        }
    } else {
        // only search within the previous results
        j = 0;

        for (i = 0; i < g_numSearchResults; i++) {
            if (PSXMu16(g_searchResults[i]) >= min && PSXMu16(g_searchResults[i]) <= max) {
                g_searchResults[j++] = g_searchResults[i];
            }
        }

        g_numSearchResults = j;
    }
}

void CheatSearchRange32(u32 min, u32 max) {
    u32 i, j;

    CheatSearchInitBackupMemory();

    if (g_searchResults == NULL) {
        // search the whole memory
        for (i = 0; i < 0x200000; i += 4) {
            if (PSXMu32(i) >= min && PSXMu32(i) <= max) {
                CheatSearchAddResult(i);
            }
        }
    } else {
        // only search within the previous results
        j = 0;

        for (i = 0; i < g_numSearchResults; i++) {
            if (PSXMu32(g_searchResults[i]) >= min && PSXMu32(g_searchResults[i]) <= max) {
                g_searchResults[j++] = g_searchResults[i];
            }
        }

        g_numSearchResults = j;
    }
}

void CheatSearchIncreasedBy8(u8 val) {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PSXMu8(g_searchResults[i]) - PrevMu8(g_searchResults[i]) == val) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void CheatSearchIncreasedBy16(u16 val) {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PSXMu16(g_searchResults[i]) - PrevMu16(g_searchResults[i]) == val) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void CheatSearchIncreasedBy32(u32 val) {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PSXMu32(g_searchResults[i]) - PrevMu32(g_searchResults[i]) == val) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void CheatSearchDecreasedBy8(u8 val) {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu8(g_searchResults[i]) - PSXMu8(g_searchResults[i]) == val) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void CheatSearchDecreasedBy16(u16 val) {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu16(g_searchResults[i]) - PSXMu16(g_searchResults[i]) == val) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void CheatSearchDecreasedBy32(u32 val) {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu32(g_searchResults[i]) - PSXMu32(g_searchResults[i]) == val) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void CheatSearchIncreased8() {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu8(g_searchResults[i]) < PSXMu8(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void CheatSearchIncreased16() {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu16(g_searchResults[i]) < PSXMu16(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void CheatSearchIncreased32() {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu32(g_searchResults[i]) < PSXMu32(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void CheatSearchDecreased8() {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu8(g_searchResults[i]) > PSXMu8(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void CheatSearchDecreased16() {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu16(g_searchResults[i]) > PSXMu16(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void CheatSearchDecreased32() {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu32(g_searchResults[i]) > PSXMu32(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void CheatSearchDifferent8() {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu8(g_searchResults[i]) != PSXMu8(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void CheatSearchDifferent16() {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu16(g_searchResults[i]) != PSXMu16(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void CheatSearchDifferent32() {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu32(g_searchResults[i]) != PSXMu32(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void CheatSearchNoChange8() {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu8(g_searchResults[i]) == PSXMu8(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void CheatSearchNoChange16() {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu16(g_searchResults[i]) == PSXMu16(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void CheatSearchNoChange32() {
    u32 i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu32(g_searchResults[i]) == PSXMu32(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}
