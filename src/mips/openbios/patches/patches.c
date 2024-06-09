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

#include "openbios/patches/patches.h"

#include <stdint.h>
#include <stdlib.h>

#include "common/hardware/pcsxhw.h"
#include "common/syscalls/syscalls.h"
#include "openbios/patches/hash.h"

int g_patch_permissive = 0;

struct patch {
    uint32_t hash;
    enum patch_behavior (*execute)(uint32_t* ra);
    const char* name;
};

// The following has been automatically generated, do not edit.
// See generate.c if you need to make changes.

enum patch_behavior patch_card_info_1_execute(uint32_t* ra);
enum patch_behavior patch_card2_1_execute(uint32_t* ra);
enum patch_behavior patch_card2_2_execute(uint32_t* ra);
enum patch_behavior patch_pad_1_execute(uint32_t* ra);
enum patch_behavior patch_pad_2_execute(uint32_t* ra);
enum patch_behavior patch_pad_3_execute(uint32_t* ra);
enum patch_behavior remove_ChgclrPAD_1_execute(uint32_t* ra);
enum patch_behavior remove_ChgclrPAD_2_execute(uint32_t* ra);
enum patch_behavior send_pad_1_execute(uint32_t* ra);
enum patch_behavior send_pad_2_execute(uint32_t* ra);
enum patch_behavior clear_card_1_execute(uint32_t* ra);
enum patch_behavior custom_handler_1_execute(uint32_t* ra);
enum patch_behavior initgun_1_execute(uint32_t* ra);
enum patch_behavior patch_card_1_execute(uint32_t* ra);
enum patch_behavior patch_card_2_execute(uint32_t* ra);
enum patch_behavior patch_gte_1_execute(uint32_t* ra);
enum patch_behavior patch_gte_2_execute(uint32_t* ra);
enum patch_behavior patch_gte_3_execute(uint32_t* ra);

static const uint32_t generic_hash_mask_b0 = 0xffc9a655;
static const uint32_t generic_hash_mask_c0 = 0x5aa45555;
static const unsigned generic_hash_len = 16;

static const struct patch B0patches[] = {
    {
        .hash = 0x5123f82a,
        .execute = patch_card_info_1_execute,
        .name = "_patch_card_info#1",
    },
    {
        .hash = 0x0bc81000,
        .execute = patch_card2_1_execute,
        .name = "_patch_card2#1",
    },
    {
        .hash = 0xc29df18f,
        .execute = patch_card2_2_execute,
        .name = "_patch_card2#2",
    },
    {
        .hash = 0xf803a6a6,
        .execute = patch_pad_1_execute,
        .name = "_patch_pad#1",
    },
    {
        .hash = 0x6dee1051,
        .execute = patch_pad_2_execute,
        .name = "_patch_pad#2",
    },
    {
        .hash = 0x012afc0a,
        .execute = patch_pad_3_execute,
        .name = "_patch_pad#3",
    },
    {
        .hash = 0xcef165ba,
        .execute = remove_ChgclrPAD_1_execute,
        .name = "_remove_ChgclrPAD#1",
    },
    {
        .hash = 0x5df8cc5d,
        .execute = remove_ChgclrPAD_2_execute,
        .name = "_remove_ChgclrPAD#2",
    },
    {
        .hash = 0xa1c49b0e,
        .execute = send_pad_1_execute,
        .name = "_send_pad#1",
    },
    {
        .hash = 0x561b6ad1,
        .execute = send_pad_2_execute,
        .name = "_send_pad#2",
    },
};

static const struct patch C0patches[] = {
    {
        .hash = 0x95c14c17,
        .execute = clear_card_1_execute,
        .name = "_clear_card#1",
    },
    {
        .hash = 0xf80aeee3,
        .execute = custom_handler_1_execute,
        .name = "custom_handler#1",
    },
    {
        .hash = 0x5753f599,
        .execute = initgun_1_execute,
        .name = "_initgun#1",
    },
    {
        .hash = 0x847eabf2,
        .execute = patch_card_1_execute,
        .name = "_patch_card#1",
    },
    {
        .hash = 0x2a81bbef,
        .execute = patch_card_2_execute,
        .name = "_patch_card#2",
    },
    {
        .hash = 0x61c914a1,
        .execute = patch_gte_1_execute,
        .name = "_patch_gte#1",
    },
    {
        .hash = 0xc223044d,
        .execute = patch_gte_2_execute,
        .name = "_patch_gte#2",
    },
    {
        .hash = 0xbf873c49,
        .execute = patch_gte_3_execute,
        .name = "_patch_gte#3",
    },
};

// end of auto generated code

void patch_hook(uint32_t* ra, enum patch_table table) {
    // already patched, bail out
    if ((ra[0] == 0) && (ra[1] == 0) && (ra[3] == 0)) return;

    const uint32_t* hash_mask = NULL;

    const struct patch* patches = NULL;
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
            romsyscall_printf("Found %c0 patch hash %08x \"%s\", issued from %p, executing...\n", t, h, patches->name,
                              ra);
            enum patch_behavior v = patches->execute(ra);
            if (v == PATCH_NOT_MATCHING) continue;
            if (v == PATCH_PASSTHROUGH) return;
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
