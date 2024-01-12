
#include <stdint.h>
#include "font.h"
#include "gpu.h"
#include "ps1/gpucmd.h"

static const SpriteInfo fontSprites[] = {
    { .x =  6, .y =  0, .width = 2, .height = 9 }, // !
    { .x = 12, .y =  0, .width = 4, .height = 9 }, // "
    { .x = 18, .y =  0, .width = 6, .height = 9 }, // #
    { .x = 24, .y =  0, .width = 6, .height = 9 }, // $
    { .x = 30, .y =  0, .width = 6, .height = 9 }, // %
    { .x = 36, .y =  0, .width = 6, .height = 9 }, // &
    { .x = 42, .y =  0, .width = 2, .height = 9 }, // '
    { .x = 48, .y =  0, .width = 3, .height = 9 }, // (
    { .x = 54, .y =  0, .width = 3, .height = 9 }, // )
    { .x = 60, .y =  0, .width = 4, .height = 9 }, // *
    { .x = 66, .y =  0, .width = 6, .height = 9 }, // +
    { .x = 72, .y =  0, .width = 3, .height = 9 }, // ,
    { .x = 78, .y =  0, .width = 6, .height = 9 }, // -
    { .x = 84, .y =  0, .width = 2, .height = 9 }, // .
    { .x = 90, .y =  0, .width = 6, .height = 9 }, // /
    { .x =  0, .y =  9, .width = 6, .height = 9 }, // 0
    { .x =  6, .y =  9, .width = 6, .height = 9 }, // 1
    { .x = 12, .y =  9, .width = 6, .height = 9 }, // 2
    { .x = 18, .y =  9, .width = 6, .height = 9 }, // 3
    { .x = 24, .y =  9, .width = 6, .height = 9 }, // 4
    { .x = 30, .y =  9, .width = 6, .height = 9 }, // 5
    { .x = 36, .y =  9, .width = 6, .height = 9 }, // 6
    { .x = 42, .y =  9, .width = 6, .height = 9 }, // 7
    { .x = 48, .y =  9, .width = 6, .height = 9 }, // 8
    { .x = 54, .y =  9, .width = 6, .height = 9 }, // 9
    { .x = 60, .y =  9, .width = 2, .height = 9 }, // :
    { .x = 66, .y =  9, .width = 3, .height = 9 }, // ;
    { .x = 72, .y =  9, .width = 6, .height = 9 }, // <
    { .x = 78, .y =  9, .width = 6, .height = 9 }, // =
    { .x = 84, .y =  9, .width = 6, .height = 9 }, // >
    { .x = 90, .y =  9, .width = 6, .height = 9 }, // ?
    { .x =  0, .y = 18, .width = 6, .height = 9 }, // @
    { .x =  6, .y = 18, .width = 6, .height = 9 }, // A
    { .x = 12, .y = 18, .width = 6, .height = 9 }, // B
    { .x = 18, .y = 18, .width = 6, .height = 9 }, // C
    { .x = 24, .y = 18, .width = 6, .height = 9 }, // D
    { .x = 30, .y = 18, .width = 6, .height = 9 }, // E
    { .x = 36, .y = 18, .width = 6, .height = 9 }, // F
    { .x = 42, .y = 18, .width = 6, .height = 9 }, // G
    { .x = 48, .y = 18, .width = 6, .height = 9 }, // H
    { .x = 54, .y = 18, .width = 4, .height = 9 }, // I
    { .x = 60, .y = 18, .width = 5, .height = 9 }, // J
    { .x = 66, .y = 18, .width = 6, .height = 9 }, // K
    { .x = 72, .y = 18, .width = 6, .height = 9 }, // L
    { .x = 78, .y = 18, .width = 6, .height = 9 }, // M
    { .x = 84, .y = 18, .width = 6, .height = 9 }, // N
    { .x = 90, .y = 18, .width = 6, .height = 9 }, // O
    { .x =  0, .y = 27, .width = 6, .height = 9 }, // P
    { .x =  6, .y = 27, .width = 6, .height = 9 }, // Q
    { .x = 12, .y = 27, .width = 6, .height = 9 }, // R
    { .x = 18, .y = 27, .width = 6, .height = 9 }, // S
    { .x = 24, .y = 27, .width = 6, .height = 9 }, // T
    { .x = 30, .y = 27, .width = 6, .height = 9 }, // U
    { .x = 36, .y = 27, .width = 6, .height = 9 }, // V
    { .x = 42, .y = 27, .width = 6, .height = 9 }, // W
    { .x = 48, .y = 27, .width = 6, .height = 9 }, // X
    { .x = 54, .y = 27, .width = 6, .height = 9 }, // Y
    { .x = 60, .y = 27, .width = 6, .height = 9 }, // Z
    { .x = 66, .y = 27, .width = 3, .height = 9 }, // [
    { .x = 72, .y = 27, .width = 6, .height = 9 }, // Backslash
    { .x = 78, .y = 27, .width = 3, .height = 9 }, // ]
    { .x = 84, .y = 27, .width = 4, .height = 9 }, // ^
    { .x = 90, .y = 27, .width = 6, .height = 9 }, // _
    { .x =  0, .y = 36, .width = 3, .height = 9 }, // `
    { .x =  6, .y = 36, .width = 6, .height = 9 }, // a
    { .x = 12, .y = 36, .width = 6, .height = 9 }, // b
    { .x = 18, .y = 36, .width = 6, .height = 9 }, // c
    { .x = 24, .y = 36, .width = 6, .height = 9 }, // d
    { .x = 30, .y = 36, .width = 6, .height = 9 }, // e
    { .x = 36, .y = 36, .width = 5, .height = 9 }, // f
    { .x = 42, .y = 36, .width = 6, .height = 9 }, // g
    { .x = 48, .y = 36, .width = 5, .height = 9 }, // h
    { .x = 54, .y = 36, .width = 2, .height = 9 }, // i
    { .x = 60, .y = 36, .width = 4, .height = 9 }, // j
    { .x = 66, .y = 36, .width = 5, .height = 9 }, // k
    { .x = 72, .y = 36, .width = 2, .height = 9 }, // l
    { .x = 78, .y = 36, .width = 6, .height = 9 }, // m
    { .x = 84, .y = 36, .width = 5, .height = 9 }, // n
    { .x = 90, .y = 36, .width = 6, .height = 9 }, // o
    { .x =  0, .y = 45, .width = 6, .height = 9 }, // p
    { .x =  6, .y = 45, .width = 6, .height = 9 }, // q
    { .x = 12, .y = 45, .width = 6, .height = 9 }, // r
    { .x = 18, .y = 45, .width = 6, .height = 9 }, // s
    { .x = 24, .y = 45, .width = 5, .height = 9 }, // t
    { .x = 30, .y = 45, .width = 5, .height = 9 }, // u
    { .x = 36, .y = 45, .width = 6, .height = 9 }, // v
    { .x = 42, .y = 45, .width = 6, .height = 9 }, // w
    { .x = 48, .y = 45, .width = 6, .height = 9 }, // x
    { .x = 54, .y = 45, .width = 6, .height = 9 }, // y
    { .x = 60, .y = 45, .width = 5, .height = 9 }, // z
    { .x = 66, .y = 45, .width = 4, .height = 9 }, // {
    { .x = 72, .y = 45, .width = 2, .height = 9 }, // |
    { .x = 78, .y = 45, .width = 4, .height = 9 }, // }
    { .x = 84, .y = 45, .width = 6, .height = 9 }, // ~
    { .x = 90, .y = 45, .width = 6, .height = 9 }  // Invalid character
};

void printString(
    DMAChain *chain, const TextureInfo *font, int x, int y, int zIndex,
    const char *str
) {
    int currentX = x, currentY = y;

    uint32_t *ptr;

    // Iterate over every character in the string.
    for (; *str; str++) {
        char ch = *str;

        // Check if the character is "special" and shall be handled without
        // drawing any sprite, or if it's invalid and should be rendered as a
        // box with a question mark (character code 127).
        switch (ch) {
            case '\t':
                currentX += FONT_TAB_WIDTH - 1;
                currentX -= currentX % FONT_TAB_WIDTH;
                continue;

            case '\n':
                currentX  = x;
                currentY += FONT_LINE_HEIGHT;
                continue;

            case ' ':
                currentX += FONT_SPACE_WIDTH;
                continue;

            case '\x80' ... '\xff':
                ch = '\x7f';
                break;
        }

        // If the character was not a tab, newline or space, fetch its
        // respective entry from the sprite coordinate table.
        const SpriteInfo *sprite = &fontSprites[ch - FONT_FIRST_TABLE_CHAR];

        // Draw the character, summing the UV coordinates of the spritesheet in
        // VRAM to those of the sprite itself within the sheet. Enable blending
        // to make sure any semitransparent pixels in the font get rendered
        // correctly.
        ptr    = allocatePacket(chain, zIndex, 4);
        ptr[0] = gp0_rectangle(true, true, true);
        ptr[1] = gp0_xy(currentX, currentY);
        ptr[2] = gp0_uv(font->u + sprite->x, font->v + sprite->y, font->clut);
        ptr[3] = gp0_xy(sprite->width, sprite->height);

        // Move onto the next character.
        currentX += sprite->width;
    }

    // Finish by sending a texpage command to tell the GPU to use the font's
    // spritesheet (keep in mind that DMA sends ordering table packets in
    // last-to-first order). Note that the texpage command before a drawing
    // command can be omitted when reusing the same texture, so sending it here
    // just once is enough.
    ptr    = allocatePacket(chain, zIndex, 1);
    ptr[0] = gp0_texpage(font->page, false, false);
}
