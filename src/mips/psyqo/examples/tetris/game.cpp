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

psyqo::Application* g_tetrisApplication = nullptr;

namespace {
template <size_t COLUMNS, size_t ROWS>
struct Playfield {
    enum CellType : uint8_t { Empty, Red, Orange, Yellow, Green, Blue, Cyan, Purple };

    void clear() {
        for (size_t x = 0; x < COLUMNS; ++x) {
            for (size_t y = 0; y < ROWS; ++y) {
                m_cells[x][y] = Empty;
            }
        }
    }

  private:
    CellType m_cells[COLUMNS][ROWS];
};

Playfield<10, 20> s_playfield;

const psyqo::Color PIECES_COLORS[7] = {CYAN, YELLOW, PURPLE, BLUE, ORANGE, RED, GREEN};
const psyqo::Color PIECES_HICOLORS[7] = {HICYAN, HIYELLOW, HIPURPLE, HIBLUE, HIORANGE, HIRED, HIGREEN};

}  // namespace

void MainGame::start(Scene::StartReason reason) {}

void MainGame::frame() {}

void MainGame::teardown(Scene::TearDownReason reason) {}
