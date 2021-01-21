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

#include <stdio.h>

#include "common/compiler/stdint.h"
#include "openbios/patches/hash.h"

/* B0 */
uint32_t generate_hash_patch_card_info_1(uint32_t mask, unsigned len);
uint32_t generate_mask_patch_card_info_1();
uint32_t generate_hash_patch_card2_1(uint32_t mask, unsigned len);
uint32_t generate_mask_patch_card2_1();
uint32_t generate_hash_patch_card2_2(uint32_t mask, unsigned len);
uint32_t generate_mask_patch_card2_2();
uint32_t generate_hash_patch_pad_1(uint32_t mask, unsigned len);
uint32_t generate_mask_patch_pad_1();
uint32_t generate_hash_patch_pad_2(uint32_t mask, unsigned len);
uint32_t generate_mask_patch_pad_2();
uint32_t generate_hash_patch_pad_3(uint32_t mask, unsigned len);
uint32_t generate_mask_patch_pad_3();
uint32_t generate_hash_remove_ChgclrPAD_1(uint32_t mask, unsigned len);
uint32_t generate_mask_remove_ChgclrPAD_1();
uint32_t generate_hash_remove_ChgclrPAD_2(uint32_t mask, unsigned len);
uint32_t generate_mask_remove_ChgclrPAD_2();
uint32_t generate_hash_send_pad_1(uint32_t mask, unsigned len);
uint32_t generate_mask_send_pad_1();
uint32_t generate_hash_send_pad_2(uint32_t mask, unsigned len);
uint32_t generate_mask_send_pad_2();

/* C0 */
uint32_t generate_hash_patch_card_1(uint32_t mask, unsigned len);
uint32_t generate_mask_patch_card_1();
uint32_t generate_hash_patch_card_2(uint32_t mask, unsigned len);
uint32_t generate_mask_patch_card_2();
uint32_t generate_hash_patch_gte_1(uint32_t mask, unsigned len);
uint32_t generate_mask_patch_gte_1();
uint32_t generate_hash_patch_gte_2(uint32_t mask, unsigned len);
uint32_t generate_mask_patch_gte_2();
uint32_t generate_hash_patch_gte_3(uint32_t mask, unsigned len);
uint32_t generate_mask_patch_gte_3();

static const unsigned max_len = 16;

struct patch {
    uint32_t (*hash)(uint32_t mask, unsigned len);
    uint32_t (*mask)();
    const char* name;
    const char* execute;
};

static const struct patch b0[] = {
    {
        .hash = generate_hash_patch_card_info_1,
        .mask = generate_mask_patch_card_info_1,
        .name = "_patch_card_info#1",
        .execute = "patch_card_info_1_execute",
    },
    {
        .hash = generate_hash_patch_card2_1,
        .mask = generate_mask_patch_card2_1,
        .name = "_patch_card2#1",
        .execute = "patch_card2_1_execute",
    },
    {
        .hash = generate_hash_patch_card2_2,
        .mask = generate_mask_patch_card2_2,
        .name = "_patch_card2#2",
        .execute = "patch_card2_2_execute",
    },
    {
        .hash = generate_hash_patch_pad_1,
        .mask = generate_mask_patch_pad_1,
        .name = "_patch_pad#1",
        .execute = "patch_pad_1_execute",
    },
    {
        .hash = generate_hash_patch_pad_2,
        .mask = generate_mask_patch_pad_2,
        .name = "_patch_pad#2",
        .execute = "patch_pad_2_execute",
    },
    {
        .hash = generate_hash_patch_pad_3,
        .mask = generate_mask_patch_pad_3,
        .name = "_patch_pad#3",
        .execute = "patch_pad_3_execute",
    },
    {
        .hash = generate_hash_remove_ChgclrPAD_1,
        .mask = generate_mask_remove_ChgclrPAD_1,
        .name = "_remove_ChgclrPAD#1",
        .execute = "remove_ChgclrPAD_1_execute",
    },
    {
        .hash = generate_hash_remove_ChgclrPAD_2,
        .mask = generate_mask_remove_ChgclrPAD_2,
        .name = "_remove_ChgclrPAD#2",
        .execute = "remove_ChgclrPAD_2_execute",
    },
    {
        .hash = generate_hash_send_pad_1,
        .mask = generate_mask_send_pad_1,
        .name = "_send_pad#1",
        .execute = "send_pad_1_execute",
    },
    {
        .hash = generate_hash_send_pad_2,
        .mask = generate_mask_send_pad_2,
        .name = "_send_pad#2",
        .execute = "send_pad_2_execute",
    },
};

static const struct patch c0[] = {
    {
        .hash = generate_hash_patch_card_1,
        .mask = generate_mask_patch_card_1,
        .name = "_patch_card#1",
        .execute = "patch_card_1_execute",
    },
    {
        .hash = generate_hash_patch_card_2,
        .mask = generate_mask_patch_card_2,
        .name = "_patch_card#2",
        .execute = "patch_card_2_execute",
    },
    {
        .hash = generate_hash_patch_gte_1,
        .mask = generate_mask_patch_gte_1,
        .name = "_patch_gte#1",
        .execute = "patch_gte_1_execute",
    },
    {
        .hash = generate_hash_patch_gte_2,
        .mask = generate_mask_patch_gte_2,
        .name = "_patch_gte#2",
        .execute = "patch_gte_2_execute",
    },
    {
        .hash = generate_hash_patch_gte_3,
        .mask = generate_mask_patch_gte_3,
        .name = "_patch_gte#3",
        .execute = "patch_gte_3_execute",
    },
};

static uint32_t mergemasks(uint32_t m1, uint32_t m2) {
    uint32_t r = 0;
    unsigned s = 0;
    for (unsigned i = 0; i < 16; i++) {
        uint32_t sm1 = m1 & 3;
        uint32_t sm2 = m2 & 3;
        m1 >>= 2;
        m2 >>= 2;
        sm1 <<= s;
        sm2 <<= s;
        if (sm1 >= sm2) {
            r |= sm1;
        } else {
            r |= sm2;
        }
        s += 2;
    }
    return r;
}

int main() {
    const unsigned b0_len = sizeof(b0) / sizeof(b0[0]);
    const unsigned c0_len = sizeof(c0) / sizeof(c0[0]);

    uint32_t min_mask_b0 = 0;
    uint32_t min_mask_c0 = 0;

    for (unsigned i = 0; i < b0_len; i++) {
        min_mask_b0 = mergemasks(b0[i].mask(), min_mask_b0);
    }
    for (unsigned i = 0; i < c0_len; i++) {
        min_mask_c0 = mergemasks(c0[i].mask(), min_mask_c0);
    }

    printf("// The following has been automatically generated, do not edit.\n");
    printf("// See generate.c if you need to make changes.\n\n");
    for (unsigned i = 0; i < b0_len; i++) {
        printf("int %s(uint32_t* ra);\n", b0[i].execute);
    }
    for (unsigned i = 0; i < c0_len; i++) {
        printf("int %s(uint32_t* ra);\n", c0[i].execute);
    }
    printf("\n");
    printf("static const uint32_t generic_hash_mask_b0 = 0x%08x;\n", min_mask_b0);
    printf("static const uint32_t generic_hash_mask_c0 = 0x%08x;\n", min_mask_c0);
    printf("static const unsigned generic_hash_len = %i;\n\n", max_len);
    printf("static const struct patch B0patches[] = {\n");
    for (unsigned i = 0; i < b0_len; i++) {
        printf("    {\n");
        printf("        .hash = 0x%08x,\n", b0[i].hash(min_mask_b0, max_len));
        printf("        .execute = %s,\n", b0[i].execute);
        printf("        .name = \"%s\",\n", b0[i].name);
        printf("    },\n");
    }
    printf("};\n\n");
    printf("static const struct patch C0patches[] = {\n");
    for (unsigned i = 0; i < c0_len; i++) {
        printf("    {\n");
        printf("        .hash = 0x%08x,\n", c0[i].hash(min_mask_c0, max_len));
        printf("        .execute = %s,\n", c0[i].execute);
        printf("        .name = \"%s\",\n", c0[i].name);
        printf("    },\n");
    }
    printf("};\n\n");
}
