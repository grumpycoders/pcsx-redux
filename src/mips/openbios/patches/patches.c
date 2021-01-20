/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#include <stdlib.h>

#include "common/compiler/stdint.h"
#include "common/hardware/pcsxhw.h"
#include "common/syscalls/syscalls.h"
#include "openbios/patches/hash.h"
#include "openbios/patches/patches.h"

int g_patch_permissive = 0;

struct patch {
    uint32_t hash;
    int (*execute)(uint32_t* ra);
    const char* name;
};

// The following has been automatically generated, do not edit.
// See generate.c if you need to make changes.

int patch_card2_execute(uint32_t* ra);
int patch_pad_execute(uint32_t* ra);
int patch_pad2_execute(uint32_t* ra);
int remove_ChgclrPAD_execute(uint32_t* ra);
int remove_ChgclrPAD2_execute(uint32_t* ra);
int send_pad_execute(uint32_t* ra);
int send_pad2_execute(uint32_t* ra);
int patch_card_execute(uint32_t* ra);
int patch_gte_execute(uint32_t* ra);
int patch_gte2_execute(uint32_t* ra);
int patch_gte3_execute(uint32_t* ra);

static const uint32_t generic_hash_mask_b0 = 0x7fc9d555;
static const uint32_t generic_hash_mask_c0 = 0x57345545;
static const unsigned generic_hash_len = 16;

static const struct patch B0patches[] = {
    {
        .hash = 0xb8ca5a6c,
        .execute = patch_card2_execute,
        .name = "_patch_card2#1",
    },
    {
        .hash = 0x8bfc2071,
        .execute = patch_pad_execute,
        .name = "_patch_pad#1",
    },
    {
        .hash = 0x2ede0b7c,
        .execute = patch_pad2_execute,
        .name = "_patch_pad#2",
    },
    {
        .hash = 0x4befb5f8,
        .execute = remove_ChgclrPAD_execute,
        .name = "_remove_ChgclrPAD#1",
    },
    {
        .hash = 0xb7f8f659,
        .execute = remove_ChgclrPAD2_execute,
        .name = "_remove_ChgclrPAD#2",
    },
    {
        .hash = 0x57b51520,
        .execute = send_pad_execute,
        .name = "_send_pad#1",
    },
    {
        .hash = 0xdfbfa583,
        .execute = send_pad2_execute,
        .name = "_send_pad#2",
    },
};

static const struct patch C0patches[] = {
    {
        .hash = 0x17062b2c,
        .execute = patch_card_execute,
        .name = "_patch_card#1",
    },
    {
        .hash = 0xcff40aeb,
        .execute = patch_gte_execute,
        .name = "_patch_gte#1",
    },
    {
        .hash = 0x0793d0e1,
        .execute = patch_gte2_execute,
        .name = "_patch_gte#2",
    },
    {
        .hash = 0x04f808dd,
        .execute = patch_gte3_execute,
        .name = "_patch_gte#3",
    },
};

void patch_hook(uint32_t* ra, enum patch_table table) {
    // already patched, bail out
    if ((ra[0] == 0) && (ra[1] == 0) && (ra[3] == 0)) return;

    uint32_t* hash_mask = NULL;

    struct patch* patches = NULL;
    unsigned size = 0;
    char t = 'x';
    switch (table) {
        case PATCH_TABLE_B0:
            patches = B0patches;
            size = sizeof(B0patches) / sizeof(struct patch);
            t = 'B';
            hash_mask = &generic_hash_mask_b0;
            break;
        case PATCH_TABLE_C0:
            patches = C0patches;
            size = sizeof(C0patches) / sizeof(struct patch);
            t = 'C';
            hash_mask = &generic_hash_mask_c0;
            break;
    }

    uint32_t h = patch_hash(ra, hash_mask, generic_hash_len);

    while (size--) {
        if (patches->hash == h) {
            romsyscall_printf("Found %c0 patch hash %08x \"%s\", issued from %p, executing...\n", t, h, patches->name, ra);
            if (!patches->execute(ra)) continue;
            ra[0] = 0;
            ra[1] = 0;
            syscall_flushCache();
            return;
        }
        patches++;
    }

    romsyscall_printf("Couldn't find %c0 patch hash %08x issued from %p!\n", t, h, ra);
    if (g_patch_permissive) {
        romsyscall_printf("Permissive mode activated, continuing.\n", t, h);
    } else {
        romsyscall_printf("Stopping.\n", t, h);
        enterCriticalSection();
        pcsx_debugbreak();
        while (1)
            ;
    }
}
