/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include "tester.h"
#include "flash.h"

struct rc4_key {
    unsigned char state[256];
    unsigned x, y;
};

/* expand a key (makes a rc4_key) */
void prepare_key(unsigned char *keydata, unsigned len, struct rc4_key *key)
{
    unsigned index1, index2, counter;
    unsigned char *state;

    state = key->state;

    for (counter = 0; counter < 256; counter++)
        state[counter] = counter;

    key->x = key->y = index1 = index2 = 0;

    for (counter = 0; counter < 256; counter++) {
        index2 = (keydata[index1] + state[counter] + index2) & 255;

        /* swap */
        state[counter] ^= state[index2];
        state[index2]  ^= state[counter];
        state[counter] ^= state[index2];

        index1 = (index1 + 1) % len;
    }
}

/* reversible encryption, will encode a buffer updating the key */
uint8_t rc4(struct rc4_key *key)
{
    unsigned x, y, xorIndex, counter;
    unsigned char *state;
    uint8_t ret;

    /* get local copies */
    x = key->x; y = key->y;
    state = key->state;

    x = (x + 1) & 255;
    y = (state[x] + y) & 255;

    /* swap */
    state[x] ^= state[y];
    state[y] ^= state[x];
    state[x] ^= state[y];

    xorIndex = (state[y] + state[x]) & 255;

    ret = state[xorIndex];

    key->x = x; key->y = y;

    return ret;
}

#define SIZE (2 * 1024 * 1024)

void main(void)
{
    volatile uint8_t * base;

    printf("\r\n\r\nSetting EXT1 to 8MB...\r\n\r\n");
    *((volatile uint32_t *) 0x1f801008) = (23 << 16) | 0x243f;

    base = (volatile uint8_t *) 0x1f400000;
    printf("\r\n\r\nDone... writing to sram now...\r\n\r\n");

    struct rc4_key key;

    prepare_key("Sram Test Vector", 16, &key);
    for (int i = 0; i < SIZE; i++) {
        base[i] = rc4(&key);
    }

    printf("\r\n\r\nDone... reading sram now...\r\n\r\n");

    prepare_key("Sram Test Vector", 16, &key);
    int good = 1;
    int count = 0;
    uintptr_t block = 0;
    for (int i = 0; i < SIZE; i++) {
        uint8_t c = rc4(&key);
        uint8_t r = base[i];
        if (c != r) {
            good = 0;
            count++;
            if (count < 16) {
                printf("Byte at %08x is mismatching: %02x instead of %02x\r\n", i, r, c);
            } else if (count == 16) {
                printf("Too many mismatches...\r\n\r\n");
            }
        }
    }

    if (good) {
        printf("\r\n\r\nSRAM good\r\n\r\n");
    } else {
        printf("\r\n\r\nSRAM not good: %i bytes are mismatching\r\n\r\n", count);
    }

    printf("\r\n\r\nDone... reading flash1 now...\r\n\r\n");
    base = (volatile uint8_t *) 0x1f000000;

{
    base[0xAAA] = 0xAA;
    base[0x555] = 0x55;
    base[0xAAA] = 0x90;
    uint8_t mid1 = base[0x00];
    uint8_t did1 = base[0x02];
    uint8_t mid2 = base[0x00];
    uint8_t did2 = base[0x02];
    uint8_t mid3 = base[0x00];
    uint8_t did3 = base[0x02];
    uint8_t mid4 = base[0x00];
    uint8_t did4 = base[0x02];

    base[0xAAA] = 0xF0;
    printf("\r\n\r\nflash tester\r\nMID: 0x%04X\r\nDID: 0x%04X\r\n", mid1, did1);
    printf("\r\n\r\nflash tester\r\nMID: 0x%04X\r\nDID: 0x%04X\r\n", mid2, did2);
    printf("\r\n\r\nflash tester\r\nMID: 0x%04X\r\nDID: 0x%04X\r\n", mid3, did3);
    printf("\r\n\r\nflash tester\r\nMID: 0x%04X\r\nDID: 0x%04X\r\n", mid4, did4);
    printf("\r\n\r\n[0] = %02x, [2] = %02x\r\n\r\n", base[0], base[2]);

    volatile uint8_t * rc4data = (volatile uint8_t *) 0x1f400000;

    printf("Erasing flash1...\r\n\r\n");
    Flash_ChipErase(base);

    printf("Programming flash1...\r\n\r\n");
    Flash_Program(base, 0, rc4data, 2 * 1024 * 1024);

    printf("Done... Reading back...\r\n\r\n");

    uint32_t i = 0;
    good = 1;
    count = 0;
    for (i = 0; i < 2 * 1024 * 1024; i++) {
        uint8_t c = rc4data[i];
        uint8_t r = base[i];
        if (c != r) {
            good = 0;
            count++;
            if (count < 16) {
                printf("Byte at %08x is mismatching: %02x instead of %02x\r\n", i, r, c);
            } else if (count == 16) {
                printf("Too many mismatches...\r\n\r\n");
            }
        }
    }

    if (good) {
        printf("\r\n\r\nFlash1 looks good\r\n\r\n");
    } else {
        printf("\r\n\r\nFlash1 not good: %i bytes are mismatching\r\n\r\n", count);
    }
}

    printf("\r\n\r\nDone... reading flash2 now...\r\n\r\n");
    base = (volatile uint8_t *) 0x1f200000;

{
    volatile uint8_t * bios = (volatile uint8_t *) 0xbfc00000;
    base[0xAAA] = 0xAA;
    base[0x555] = 0x55;
    base[0xAAA] = 0x90;
    uint8_t mid1 = base[0x00];
    uint8_t did1 = base[0x02];
    uint8_t mid2 = base[0x00];
    uint8_t did2 = base[0x02];
    uint8_t mid3 = base[0x00];
    uint8_t did3 = base[0x02];
    uint8_t mid4 = base[0x00];
    uint8_t did4 = base[0x02];

    base[0xAAA] = 0xF0;
    printf("\r\n\r\nflash tester\r\nMID: 0x%04X\r\nDID: 0x%04X\r\n", mid1, did1);
    printf("\r\n\r\nflash tester\r\nMID: 0x%04X\r\nDID: 0x%04X\r\n", mid2, did2);
    printf("\r\n\r\nflash tester\r\nMID: 0x%04X\r\nDID: 0x%04X\r\n", mid3, did3);
    printf("\r\n\r\nflash tester\r\nMID: 0x%04X\r\nDID: 0x%04X\r\n", mid4, did4);
    printf("\r\n\r\n[0] = %02x, [2] = %02x\r\n\r\n", base[0], base[2]);

    uint32_t i = 0;
    good = 1;
    count = 0;
    for (i = 0; i < 512 * 1024; i++) {
        uint8_t c = bios[i];
        uint8_t r = base[i];
        if (c != r) {
            good = 0;
            count++;
            if (count < 16) {
                printf("Byte at %08x is mismatching: %02x instead of %02x\r\n", i, r, c);
            } else if (count == 16) {
                printf("Too many mismatches...\r\n\r\n");
            }
        }
    }

    if (good) {
        printf("\r\n\r\nFlash2 looks good\r\n\r\n");
    } else {
        printf("\r\n\r\nFlash2 not good: %i bytes are mismatching\r\n\r\n", count);
    }
}

    base = (volatile uint8_t *) 0x1f600004;

    base[1] = 0x01;
    printf("\r\n\r\n[0] = %02x\r\n\r\n", base[0]);

    base[1] = 0x06;
    base[0] = 0x55;
    printf("\r\n\r\n[0] = %02x\r\n\r\n", base[0]);

    base[1] = 0x06;
    base[0] = 0xaa;
    printf("\r\n\r\n[0] = %02x\r\n\r\n", base[0]);

    base = (volatile uint8_t *) 0x1f600007;
    printf("\r\n\r\nbits = %02x\r\n\r\n", base[0]);
    base[0] = 0xff;
    printf("\r\n\r\nbits = %02x\r\n\r\n", base[0]);
    base[0] = 0x00;
    printf("\r\n\r\nbits = %02x\r\n\r\n", base[0]);
    base[0] = 0x55;
    printf("\r\n\r\nbits = %02x\r\n\r\n", base[0]);
    base[0] = 0xaa;
    printf("\r\n\r\nbits = %02x\r\n\r\n", base[0]);

    base = (volatile uint8_t *) 0x1f600006;

    int p = -1;
    while (1) {
        uint8_t b = base[0];
        base[0] = b;
        if (p != b) {
            printf("New switches values: %02x\r\n\r\n", b);
            p = b;
        }
    }
}
