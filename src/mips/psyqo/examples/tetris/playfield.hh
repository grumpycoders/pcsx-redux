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

// The Playfield class will be responsible for holding the basic state
// of the playfield, and drawing it to the screen. It's technically
// variable sized, at compilation time, using the template arguments.
// The default Tetris configuration is 10 columns and 20 rows.
template <size_t COLUMNS, size_t ROWS>
struct Playfield {
    static constexpr size_t Columns = COLUMNS;
    static constexpr size_t Rows = ROWS;

  private:
    enum CellType : uint8_t { Empty, Cyan, Yellow, Purple, Blue, Orange, Red, Green };
    static constexpr unsigned BLOCK_SIZE = 10;
    static constexpr unsigned SCREEN_WIDTH = 320;
    static constexpr unsigned SCREEN_HEIGHT = 240;
    static constexpr unsigned LEFT = SCREEN_WIDTH / 2 - (BLOCK_SIZE * COLUMNS / 2);
    static constexpr unsigned TOP = SCREEN_HEIGHT / 2 - (BLOCK_SIZE * ROWS / 2);

    // First, we will have our game logic methods.
  public:
    // Empties the playfield. This needs to be called at initialization time only,
    // as it touches the fragments. This is the only method that is mutating the
    // fragments implicitly.
    void clear() {
        for (size_t x = 0; x < COLUMNS; x++) {
            for (size_t y = 0; y < ROWS; y++) {
                m_cells[x][y] = Empty;
            }
        }
        m_fieldFragment.count = 0;
        m_blockFragment.count = 0;
    }

    // Fills the playfield with random blocks.
    void fillRandom(Rand& rand) {
        for (size_t x = 0; x < COLUMNS; x++) {
            for (size_t y = 0; y < ROWS; y++) {
                m_cells[x][y] = CellType(rand.rand<7>() + 1);
            }
        }
    }

    // Returns true if the given block collisions with anything at the given position.
    bool collision(unsigned block, int x, int y, unsigned rotation) {
        for (size_t i = 0; i < 4; i++) {
            for (size_t j = 0; j < 4; j++) {
                if (PIECES[block - 1][rotation][j][i]) {
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

    // Cements a block into the playfield.
    void place(unsigned block, int x, int y, unsigned rotation) {
        for (size_t i = 0; i < 4; i++) {
            for (size_t j = 0; j < 4; j++) {
                if (PIECES[block - 1][rotation][j][i]) {
                    m_cells[x + i][y + j] = CellType(block);
                }
            }
        }
    }

    // Computes the amount of lines that are complete, and remove them.
    // Returns the number of removed lines.
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

    // Then, the drawing-related methods.
  private:
    // The playfield fragment contains a fixed prologue of two rectangles
    // to draw the background and exterior.
    struct Prologue {
        psyqo::Prim::Rectangle outerField;
        psyqo::Prim::Rectangle innerField;
    };
    // This represents one of the blocks drawn in the playfield.
    struct Block {
        psyqo::Prim::Rectangle outer;
        psyqo::Prim::Rectangle8x8 inner;
    };

    // We are using a `FixedFragmentWithPrologue` to store the playfield Fragment.
    // We have a maximum of `ROWS * COLUMNS` blocks to display, so that's the
    // maximu amount of elements we need in our fragment.
    psyqo::Fragments::FixedFragmentWithPrologue<Prologue, Block, ROWS * COLUMNS> m_fieldFragment;
    // The current block fragment is a fixed fragment with a maximum of 4 blocks.
    // There is a subtle difference in the way we're drawing the current tetromino
    // blocks, compared to the blocks on the playfield. The current block fragment
    // won't have contours, to try and symbolize a sort of cement that's added when
    // a tetromino is fused in the playfield.
    psyqo::Fragments::FixedFragment<psyqo::Prim::Rectangle8x8, 4> m_blockFragment;

    // The pause screen will hide the current playfield and block, setting the
    // fragments counts to 0, so we need to keep track of the previous values
    // to simply re-assign them when we're being unpaused.
    unsigned m_oldFieldFragmentCount;
    unsigned m_oldBlockFragmentCount;

  public:
    // In our constructor, we're initializing the pieces of the fragments
    // that will never change throughout the lifetime of the game.
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
        clear();
    }

    // This method is called when the game is paused. It simply empties
    // the fragments to hide the blocks.
    void emptyFragments() {
        m_oldFieldFragmentCount = m_fieldFragment.count;
        m_oldBlockFragmentCount = m_blockFragment.count;
        m_fieldFragment.count = 0;
        m_blockFragment.count = 0;
    }

    // This method is called when the game is unpaused. It simply re-assigns
    // the fragments to their previous values so everything is being
    // displayed again.
    void restoreFragments() {
        m_fieldFragment.count = m_oldFieldFragmentCount;
        m_blockFragment.count = m_oldBlockFragmentCount;
    }

    // This method needs to be called after the playfield has been changed in
    // any way. It will mutate the fragments to reflect the new playfield,
    // so it is not safe to call from a callback, but only from the `::frame()`
    // method of a scene.
    void updateFieldFragment() {
        unsigned counter = 0;
        // We simply walk over the whole playfield, and update the fragment
        // accordingly. The will count the number of actual blocks being
        // displayed in our fragment to assign it at the end of the loops.
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

    // This method needs to be called when the current tetromino has
    // changed in any way. This will mutate the fragments to reflect the
    // new current tetromino, so it is not safe to call from a callback,
    // but only from the `::frame()` method of a scene.
    void updateBlockFragment(unsigned block, unsigned x, unsigned y, unsigned rotation) {
        if (block == 0) {
            m_blockFragment.count = 0;
            return;
        }
        unsigned counter = 0;
        for (size_t i = 0; i < 4; i++) {
            for (size_t j = 0; j < 4; j++) {
                if (PIECES[block - 1][rotation][j][i]) {
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

    // This method will render the playfield and the current tetromino.
    // For now it sends the two fragments directly to the GPU, but
    // this will be updated to use a DMA chain instead later on.
    void render(psyqo::GPU& gpu) {
        gpu.sendFragment(m_fieldFragment);
        gpu.sendFragment(m_blockFragment);
    }

  private:
    CellType m_cells[COLUMNS][ROWS];
};
