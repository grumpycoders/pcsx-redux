/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

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

#pragma once

#include <stdint.h>

#include "constants.hh"
#include "pieces.hh"
#include "psyqo/fragments.hh"
#include "psyqo/gpu.hh"
#include "psyqo/primitives/rectangles.hh"
#include "rand.hh"

template <size_t COLUMNS, size_t ROWS>
struct Playfield {
    static constexpr size_t Columns = COLUMNS;
    static constexpr size_t Rows = ROWS;
    enum CellType : uint8_t { Empty, Cyan, Yellow, Purple, Blue, Orange, Red, Green };
    static constexpr unsigned BLOCK_SIZE = 10;
    static constexpr unsigned SCREEN_WIDTH = 320;
    static constexpr unsigned SCREEN_HEIGHT = 240;
    static constexpr unsigned LEFT = SCREEN_WIDTH / 2 - (BLOCK_SIZE * COLUMNS / 2);
    static constexpr unsigned TOP = SCREEN_HEIGHT / 2 - (BLOCK_SIZE * ROWS / 2);

    void clear() {
        for (size_t x = 0; x < COLUMNS; x++) {
            for (size_t y = 0; y < ROWS; y++) {
                m_cells[x][y] = Empty;
            }
        }
        m_fieldFragment.count = 0;
        m_blockFragment.count = 0;
    }

    void fillRandom(Rand& rand) {
        for (size_t x = 0; x < COLUMNS; x++) {
            for (size_t y = 0; y < ROWS; y++) {
                m_cells[x][y] = CellType(rand.rand<7>() + 1);
            }
        }
    }

    bool collision(unsigned block, int x, int y, unsigned rotation) {
        for (size_t i = 0; i < 4; i++) {
            for (size_t j = 0; j < 4; j++) {
                if (PIECES[block - 1][rotation][j][i] == 1) {
                    int xx = x + i;
                    int yy = y + j;
                    if ((xx < 0) || (yy < 0) || (xx >= COLUMNS) || (yy >= ROWS) || (m_cells[xx][yy] != Empty)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    void place(unsigned block, int x, int y, unsigned rotation) {
        for (size_t i = 0; i < 4; i++) {
            for (size_t j = 0; j < 4; j++) {
                if (PIECES[block - 1][rotation][j][i] == 1) {
                    m_cells[x + i][y + j] = CellType(block);
                }
            }
        }
    }

    int removeLines() {
        int lines = 0;
        for (size_t y = 0; y < ROWS; y++) {
            bool full = true;
            for (size_t x = 0; x < COLUMNS; x++) {
                if (m_cells[x][y] == Empty) {
                    full = false;
                    break;
                }
            }
            if (full) {
                for (size_t x = 0; x < COLUMNS; x++) {
                    m_cells[x][y] = Empty;
                }
                for (size_t yy = y; yy > 0; yy--) {
                    for (size_t x = 0; x < COLUMNS; x++) {
                        m_cells[x][yy] = m_cells[x][yy - 1];
                    }
                }
                y--;
                lines++;
            }
        }
        return lines;
    }

    struct Prologue {
        psyqo::Prim::Rectangle outerField;
        psyqo::Prim::Rectangle innerField;
    };
    struct Block {
        psyqo::Prim::Rectangle outer;
        psyqo::Prim::Rectangle8x8 inner;
    };

    psyqo::Fragments::FixedFragmentWithPrologue<Prologue, Block, ROWS * COLUMNS> m_fieldFragment;
    psyqo::Fragments::FixedFragment<psyqo::Prim::Rectangle8x8, 4> m_blockFragment;
    unsigned m_oldFieldFragmentCount;
    unsigned m_oldBlockFragmentCount;

    Playfield() {
        m_fieldFragment.prologue.outerField.position.x = LEFT - 2;
        m_fieldFragment.prologue.outerField.position.y = TOP;
        m_fieldFragment.prologue.outerField.size.x = BLOCK_SIZE * COLUMNS + 4;
        m_fieldFragment.prologue.outerField.size.y = BLOCK_SIZE * ROWS + 2;
        m_fieldFragment.prologue.outerField.setColor(DARKERGREY);
        m_fieldFragment.prologue.innerField.position.x = LEFT;
        m_fieldFragment.prologue.innerField.position.y = TOP;
        m_fieldFragment.prologue.innerField.size.x = BLOCK_SIZE * COLUMNS;
        m_fieldFragment.prologue.innerField.size.y = BLOCK_SIZE * ROWS;
        m_fieldFragment.prologue.innerField.setColor(DARKGREY);
        for (auto& block : m_fieldFragment.primitives) {
            block.outer.size.w = block.outer.size.h = BLOCK_SIZE;
        }
    }

    void emptyFragments() {
        m_oldFieldFragmentCount = m_fieldFragment.count;
        m_oldBlockFragmentCount = m_blockFragment.count;
        m_fieldFragment.count = 0;
        m_blockFragment.count = 0;
    }

    void restoreFragments() {
        m_fieldFragment.count = m_oldFieldFragmentCount;
        m_blockFragment.count = m_oldBlockFragmentCount;
    }

    void updateFieldFragment() {
        unsigned counter = 0;
        for (size_t x = 0; x < COLUMNS; ++x) {
            for (size_t y = 0; y < ROWS; ++y) {
                bool addme = true;
                auto& block = m_fieldFragment.primitives[counter];
                switch (m_cells[x][y]) {
                    case Empty:
                        addme = false;
                        break;
                    case Red:
                        block.outer.setColor(RED);
                        block.inner.setColor(HIRED);
                        break;
                    case Orange:
                        block.outer.setColor(ORANGE);
                        block.inner.setColor(HIORANGE);
                        break;
                    case Yellow:
                        block.outer.setColor(YELLOW);
                        block.inner.setColor(HIYELLOW);
                        break;
                    case Green:
                        block.outer.setColor(GREEN);
                        block.inner.setColor(HIGREEN);
                        break;
                    case Blue:
                        block.outer.setColor(BLUE);
                        block.inner.setColor(HIBLUE);
                        break;
                    case Cyan:
                        block.outer.setColor(CYAN);
                        block.inner.setColor(HICYAN);
                        break;
                    case Purple:
                        block.outer.setColor(PURPLE);
                        block.inner.setColor(HIPURPLE);
                        break;
                }
                if (addme) {
                    block.outer.position.x = LEFT + x * BLOCK_SIZE;
                    block.outer.position.y = TOP + y * BLOCK_SIZE;
                    block.inner.position.x = LEFT + x * BLOCK_SIZE + 1;
                    block.inner.position.y = TOP + y * BLOCK_SIZE + 1;
                    counter++;
                }
            }
        }
        m_fieldFragment.count = counter;
    }

    void updateBlockFragment(unsigned block, unsigned x, unsigned y, unsigned rotation) {
        if (block == 0) {
            m_blockFragment.count = 0;
            return;
        }
        unsigned counter = 0;
        for (size_t i = 0; i < 4; i++) {
            for (size_t j = 0; j < 4; j++) {
                if (PIECES[block - 1][rotation][j][i] == 1) {
                    auto& blockFragment = m_blockFragment.primitives[counter];
                    blockFragment.position.x = LEFT + x * BLOCK_SIZE + i * BLOCK_SIZE + 1;
                    blockFragment.position.y = TOP + y * BLOCK_SIZE + j * BLOCK_SIZE + 1;
                    blockFragment.setColor(PIECES_HICOLORS[block - 1]);
                    counter++;
                }
            }
        }
        m_blockFragment.count = counter;
    }

    void render(psyqo::GPU& gpu) {
        gpu.sendFragment(m_fieldFragment);
        gpu.sendFragment(m_blockFragment);
    }

  private:
    CellType m_cells[COLUMNS][ROWS];
};
