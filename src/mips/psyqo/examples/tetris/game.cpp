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

#include "game.hh"

#include "psyqo/fragments.hh"

psyqo::Application* g_tetrisApplication = nullptr;

namespace {

static constexpr uint32_t INITIAL_SEED = 2891583007UL;
uint32_t s_seed;

uint32_t rand() {
    unsigned int a = s_seed;
    a ^= 61;
    a ^= a >> 16;
    a += a << 3;
    a ^= a >> 4;
    a *= 668265263UL;
    a ^= a >> 15;
    a *= 3148259783UL;
    s_seed = a;
    return a;
}

uint32_t rand7() { return rand() % 7; }

template <size_t COLUMNS, size_t ROWS>
struct Playfield {
    enum CellType : uint8_t { Empty, Red, Orange, Yellow, Green, Blue, Cyan, Purple };
    static constexpr unsigned BLOCK_SIZE = 10;
    static constexpr unsigned SCREEN_WIDTH = 320;
    static constexpr unsigned SCREEN_HEIGHT = 240;
    static constexpr unsigned LEFT = SCREEN_WIDTH / 2 - (BLOCK_SIZE * COLUMNS / 2);
    static constexpr unsigned TOP = SCREEN_HEIGHT / 2 - (BLOCK_SIZE * ROWS / 2);

    void clear() {
        for (size_t x = 0; x < COLUMNS; ++x) {
            for (size_t y = 0; y < ROWS; ++y) {
                m_cells[x][y] = Empty;
            }
        }
    }

    void fillRandom() {
        for (size_t x = 0; x < COLUMNS; ++x) {
            for (size_t y = 0; y < ROWS; ++y) {
                m_cells[x][y] = CellType(rand7() + 1);
            }
        }
    }

    struct Prologue {
        psyqo::Prim::Rectangle outerField;
        psyqo::Prim::Rectangle innerField;
    };
    struct Block {
        psyqo::Prim::Rectangle outer;
        psyqo::Prim::Rectangle8x8 inner;
    };

    psyqo::Fragments::FixedFragment<Prologue, Block, ROWS * COLUMNS> m_fieldFragment;

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

    void updateFragment() {
        unsigned counter = 0;
        for (size_t x = 0; x < COLUMNS; ++x) {
            for (size_t y = 0; y < ROWS; ++y) {
                bool send = true;
                auto& block = m_fieldFragment.primitives[counter];
                switch (m_cells[x][y]) {
                    case Empty:
                        send = false;
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
                if (send) {
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

    void render(psyqo::GPU& gpu, bool renderField = true) { gpu.sendFragment(m_fieldFragment); }

  private:
    CellType m_cells[COLUMNS][ROWS];
};

Playfield<10, 20> s_playfield;

const psyqo::Color PIECES_COLORS[7] = {CYAN, YELLOW, PURPLE, BLUE, ORANGE, RED, GREEN};
const psyqo::Color PIECES_HICOLORS[7] = {HICYAN, HIYELLOW, HIPURPLE, HIBLUE, HIORANGE, HIRED, HIGREEN};

}  // namespace

void MainGame::start(Scene::StartReason reason) {
    if (reason == Scene::StartReason::Create) {
        s_seed = INITIAL_SEED * g_tetrisApplication->gpu().now();
        s_playfield.clear();
        s_playfield.updateFragment();
        return;
    }
}

void MainGame::frame() {
    auto& gpu = g_tetrisApplication->gpu();
    gpu.clear();
    s_playfield.render(gpu);
}

void MainGame::teardown(Scene::TearDownReason reason) {}
