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

#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"

void PCSX::Cheats::ClearAllCheats() {
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
void PCSX::Cheats::LoadCheats(const char *filename) {
    FILE *fp;
    char buf[256];
    int count = 0;
    unsigned int t1, t2;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        PCSX::g_system->printf(_("Could not load cheats from: %s\n"), filename);
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

    PCSX::g_system->printf(_("Cheats loaded from: %s\n"), filename);
}

// save all cheats to the specified filename
void PCSX::Cheats::SaveCheats(const char *filename) {
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
            fprintf(fp, "%.8X %.4X\n", g_cheatCodes[g_cheats[i].First + j].Addr,
                    g_cheatCodes[g_cheats[i].First + j].Val);
        }

        fprintf(fp, "\n");
    }

    fclose(fp);

    PCSX::g_system->printf(_("Cheats saved to: %s\n"), filename);
}

// apply all enabled cheats
void PCSX::Cheats::ApplyCheats() {
    int i, j, k, endindex;

    for (i = 0; i < g_numCheats; i++) {
        if (!g_cheats[i].Enabled) {
            continue;
        }

        // process all cheat codes
        endindex = g_cheats[i].First + g_cheats[i].n;

        for (j = g_cheats[i].First; j < endindex; j++) {
            uint8_t type = (uint8_t)(g_cheatCodes[j].Addr >> 24);
            uint32_t addr = (g_cheatCodes[j].Addr & 0x001FFFFF);
            uint16_t val = g_cheatCodes[j].Val;
            uint32_t taddr;

            switch (type) {
                case CHEAT_CONST8:
                    psxMu8ref(addr) = (uint8_t)val;
                    break;

                case CHEAT_CONST16:
                    psxMu16ref(addr) = SWAP_LEu16(val);
                    break;

                case CHEAT_INC16:
                    psxMu16ref(addr) = SWAP_LEu16(psxMu16(addr) + val);
                    break;

                case CHEAT_DEC16:
                    psxMu16ref(addr) = SWAP_LEu16(psxMu16(addr) - val);
                    break;

                case CHEAT_INC8:
                    psxMu8ref(addr) += (uint8_t)val;
                    break;

                case CHEAT_DEC8:
                    psxMu8ref(addr) -= (uint8_t)val;
                    break;

                case CHEAT_SLIDE:
                    j++;
                    if (j >= endindex) break;

                    type = (uint8_t)(g_cheatCodes[j].Addr >> 24);
                    taddr = (g_cheatCodes[j].Addr & 0x001FFFFF);
                    val = g_cheatCodes[j].Val;

                    if (type == CHEAT_CONST8) {
                        for (k = 0; k < ((addr >> 8) & 0xFF); k++) {
                            psxMu8ref(taddr) = (uint8_t)val;
                            taddr += (int8_t)(addr & 0xFF);
                            val += (int8_t)(g_cheatCodes[j - 1].Val & 0xFF);
                        }
                    } else if (type == CHEAT_CONST16) {
                        for (k = 0; k < ((addr >> 8) & 0xFF); k++) {
                            psxMu16ref(taddr) = SWAP_LEu16(val);
                            taddr += (int8_t)(addr & 0xFF);
                            val += (int8_t)(g_cheatCodes[j - 1].Val & 0xFF);
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
                    if (PSXMu8(addr) != (uint8_t)val) j++;  // skip the next code
                    break;

                case CHEAT_NOTEQU8:
                    if (PSXMu8(addr) == (uint8_t)val) j++;  // skip the next code
                    break;

                case CHEAT_LESSTHAN8:
                    if (PSXMu8(addr) >= (uint8_t)val) j++;  // skip the next code
                    break;

                case CHEAT_GREATERTHAN8:
                    if (PSXMu8(addr) <= (uint8_t)val) j++;  // skip the next code
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

int PCSX::Cheats::AddCheat(const char *descr, char *code) {
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

void PCSX::Cheats::RemoveCheat(int index) {
    assert(index >= 0 && index < g_numCheats);

    free(g_cheats[index].Descr);

    while (index < g_numCheats - 1) {
        g_cheats[index] = g_cheats[index + 1];
        index++;
    }

    g_numCheats--;
}

int PCSX::Cheats::EditCheat(int index, const char *descr, char *code) {
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

void PCSX::Cheats::FreeCheatSearchResults() {
    if (g_searchResults != NULL) {
        free(g_searchResults);
    }
    g_searchResults = NULL;

    g_numSearchResults = 0;
    s_numSearchResultsAllocated = 0;
}

void PCSX::Cheats::FreeCheatSearchMem() {
    if (g_prevM != NULL) {
        free(g_prevM);
    }
    g_prevM = NULL;
}

void PCSX::Cheats::CheatSearchBackupMemory() {
    if (g_prevM != NULL) {
        memcpy(g_prevM, PCSX::g_emulator->m_psxMem->g_psxM, 0x200000);
    }
}

void PCSX::Cheats::CheatSearchInitBackupMemory() {
    if (g_prevM == NULL) {
        g_prevM = (int8_t *)malloc(0x200000);
        CheatSearchBackupMemory();
    }
}

void PCSX::Cheats::CheatSearchAddResult(uint32_t addr) {
    if (g_numSearchResults >= s_numSearchResultsAllocated) {
        s_numSearchResultsAllocated += ALLOC_INCREMENT;

        if (g_searchResults == NULL) {
            g_searchResults = (uint32_t *)malloc(sizeof(uint32_t) * s_numSearchResultsAllocated);
        } else {
            g_searchResults = (uint32_t *)realloc(g_searchResults, sizeof(uint32_t) * s_numSearchResultsAllocated);
        }
    }

    g_searchResults[g_numSearchResults++] = addr;
}

void PCSX::Cheats::CheatSearchEqual8(uint8_t val) {
    uint32_t i, j;

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

void PCSX::Cheats::CheatSearchEqual16(uint16_t val) {
    uint32_t i, j;

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

void PCSX::Cheats::CheatSearchEqual32(uint32_t val) {
    uint32_t i, j;

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

void PCSX::Cheats::CheatSearchNotEqual8(uint8_t val) {
    uint32_t i, j;

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

void PCSX::Cheats::CheatSearchNotEqual16(uint16_t val) {
    uint32_t i, j;

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

void PCSX::Cheats::CheatSearchNotEqual32(uint32_t val) {
    uint32_t i, j;

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

void PCSX::Cheats::CheatSearchRange8(uint8_t min, uint8_t max) {
    uint32_t i, j;

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

void PCSX::Cheats::CheatSearchRange16(uint16_t min, uint16_t max) {
    uint32_t i, j;

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

void PCSX::Cheats::CheatSearchRange32(uint32_t min, uint32_t max) {
    uint32_t i, j;

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

void PCSX::Cheats::CheatSearchIncreasedBy8(uint8_t val) {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PSXMu8(g_searchResults[i]) - PrevMu8(g_searchResults[i]) == val) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void PCSX::Cheats::CheatSearchIncreasedBy16(uint16_t val) {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PSXMu16(g_searchResults[i]) - PrevMu16(g_searchResults[i]) == val) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void PCSX::Cheats::CheatSearchIncreasedBy32(uint32_t val) {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PSXMu32(g_searchResults[i]) - PrevMu32(g_searchResults[i]) == val) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void PCSX::Cheats::CheatSearchDecreasedBy8(uint8_t val) {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu8(g_searchResults[i]) - PSXMu8(g_searchResults[i]) == val) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void PCSX::Cheats::CheatSearchDecreasedBy16(uint16_t val) {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu16(g_searchResults[i]) - PSXMu16(g_searchResults[i]) == val) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void PCSX::Cheats::CheatSearchDecreasedBy32(uint32_t val) {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu32(g_searchResults[i]) - PSXMu32(g_searchResults[i]) == val) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void PCSX::Cheats::CheatSearchIncreased8() {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu8(g_searchResults[i]) < PSXMu8(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void PCSX::Cheats::CheatSearchIncreased16() {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu16(g_searchResults[i]) < PSXMu16(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void PCSX::Cheats::CheatSearchIncreased32() {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu32(g_searchResults[i]) < PSXMu32(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void PCSX::Cheats::CheatSearchDecreased8() {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu8(g_searchResults[i]) > PSXMu8(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void PCSX::Cheats::CheatSearchDecreased16() {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu16(g_searchResults[i]) > PSXMu16(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void PCSX::Cheats::CheatSearchDecreased32() {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu32(g_searchResults[i]) > PSXMu32(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void PCSX::Cheats::CheatSearchDifferent8() {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu8(g_searchResults[i]) != PSXMu8(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void PCSX::Cheats::CheatSearchDifferent16() {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu16(g_searchResults[i]) != PSXMu16(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void PCSX::Cheats::CheatSearchDifferent32() {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu32(g_searchResults[i]) != PSXMu32(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void PCSX::Cheats::CheatSearchNoChange8() {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu8(g_searchResults[i]) == PSXMu8(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void PCSX::Cheats::CheatSearchNoChange16() {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu16(g_searchResults[i]) == PSXMu16(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}

void PCSX::Cheats::CheatSearchNoChange32() {
    uint32_t i, j;

    assert(g_prevM != NULL);  // not possible for the first search

    j = 0;

    for (i = 0; i < g_numSearchResults; i++) {
        if (PrevMu32(g_searchResults[i]) == PSXMu32(g_searchResults[i])) {
            g_searchResults[j++] = g_searchResults[i];
        }
    }

    g_numSearchResults = j;
}
