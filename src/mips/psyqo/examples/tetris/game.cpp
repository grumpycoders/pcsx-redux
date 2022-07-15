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

MainGame g_mainGame;

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
const psyqo::Color PIECES_COLORS[7] = {CYAN, YELLOW, PURPLE, BLUE, ORANGE, RED, GREEN};
const psyqo::Color PIECES_HICOLORS[7] = {HICYAN, HIYELLOW, HIPURPLE, HIBLUE, HIORANGE, HIRED, HIGREEN};

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

    void fillRandom() {
        for (size_t x = 0; x < COLUMNS; x++) {
            for (size_t y = 0; y < ROWS; y++) {
                m_cells[x][y] = CellType(rand7() + 1);
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

Playfield<10, 20> s_playfield;

}  // namespace

void MainGame::tick() {
    if (m_currentBlock == 0) {
        createBlock();
        if (s_playfield.collision(m_currentBlock, m_blockX, m_blockY, m_blockRotation)) {
            m_gameOver = true;
            s_playfield.fillRandom();
            m_needsToUpdateFieldFragment = true;
        }
        m_needsToUpdateBlockFragment = true;
        return;
    }
    if (s_playfield.collision(m_currentBlock, m_blockX, m_blockY + 1, m_blockRotation)) {
        if (m_bottomHitOnce) {
            s_playfield.place(m_currentBlock, m_blockX, m_blockY, m_blockRotation);
            int lines = s_playfield.removeLines();
            switch (lines) {
                case 1:
                    m_score += 100;
                    break;
                case 2:
                    m_score += 300;
                    break;
                case 3:
                    m_score += 600;
                    break;
                case 4:
                    m_score += 1000;
                    break;
            }
            recomputePeriod();
            m_bottomHitOnce = false;
            m_currentBlock = 0;
            g_tetris.gpu().changeTimerPeriod(m_timer, m_period);
            m_needsToUpdateFieldFragment = true;
            m_needsToUpdateBlockFragment = true;
        } else {
            m_bottomHitOnce = true;
        }
    } else {
        m_blockY++;
        m_needsToUpdateBlockFragment = true;
    }
}

void MainGame::createBlock() {
    m_currentBlock = rand7() + 1;
    m_blockX = s_playfield.Columns / 2 - 2;
    m_blockY = 0;
    m_blockRotation = 0;
}

void MainGame::recomputePeriod() {
    int scoreRange = m_score / 20000;
    if (scoreRange > 10) {
        scoreRange = 10;
    }
    m_period = 1'000'000 - scoreRange * 100'000;
}

void MainGame::buttonEvent(const psyqo::SimplePad::Event& event) {
    if (event.type == psyqo::SimplePad::Event::ButtonPressed) {
        if (m_currentBlock == 0) {
            return;
        }
        switch (event.button) {
            case psyqo::SimplePad::Button::Left:
                moveLeft();
                break;
            case psyqo::SimplePad::Button::Right:
                moveRight();
                break;
            case psyqo::SimplePad::Button::Cross:
                rotateLeft();
                break;
            case psyqo::SimplePad::Button::Up:
            case psyqo::SimplePad::Button::Circle:
                rotateRight();
                break;
            case psyqo::SimplePad::Button::Triangle:
                while (!s_playfield.collision(m_currentBlock, m_blockX, m_blockY, m_blockRotation)) {
                    m_blockY++;
                }
                m_blockY--;
                g_tetris.gpu().changeTimerPeriod(m_timer, 0, true);
                m_bottomHitOnce = true;
                break;
            case psyqo::SimplePad::Button::Down:
                g_tetris.gpu().changeTimerPeriod(m_timer, 100'000, true);
                break;
            default:
                break;
        }
    } else if (event.type == psyqo::SimplePad::Event::ButtonReleased) {
        switch (event.button) {
            case psyqo::SimplePad::Button::Down:
                g_tetris.gpu().changeTimerPeriod(m_timer, m_period);
                break;
            case psyqo::SimplePad::Button::Start:
                m_paused = true;
                break;
            default:
                break;
        }
    }
}

void MainGame::moveLeft() {
    if (s_playfield.collision(m_currentBlock, m_blockX - 1, m_blockY, m_blockRotation)) {
        return;
    }
    m_blockX--;
    m_needsToUpdateBlockFragment = true;
}

void MainGame::moveRight() {
    if (s_playfield.collision(m_currentBlock, m_blockX + 1, m_blockY, m_blockRotation)) {
        return;
    }
    m_blockX++;
    m_needsToUpdateBlockFragment = true;
}

void MainGame::rotateLeft() {
    unsigned rotation = m_blockRotation;
    if (rotation == 0) {
        rotation = 3;
    } else {
        rotation--;
    }
    rotate(rotation);
}

void MainGame::rotateRight() {
    unsigned rotation = m_blockRotation;
    if (rotation == 3) {
        rotation = 0;
    } else {
        rotation++;
    }
    rotate(rotation);
}

void MainGame::rotate(unsigned rotation) {
    int shiftX = 0;
    if (s_playfield.collision(m_currentBlock, m_blockX, m_blockY, rotation)) {
        if (m_blockX > s_playfield.Columns / 2 - 2) {
            shiftX = -1;
        } else {
            shiftX = 1;
        }
        if (s_playfield.collision(m_currentBlock, m_blockX + shiftX, m_blockY, rotation)) {
            return;
        }
        m_blockX += shiftX;
    }
    m_blockRotation = rotation;
    m_needsToUpdateBlockFragment = true;
}

void MainGame::start(Scene::StartReason reason) {
    auto& gpu = g_tetris.gpu();
    if (reason == Scene::StartReason::Create) {
        s_seed = INITIAL_SEED * gpu.now();
        s_playfield.clear();
        m_period = 1'000'000;
        m_score = 0;
        m_currentBlock = 0;
        m_timer = gpu.armPeriodicTimer(m_period, [this](uint32_t) { tick(); });
        m_needsToUpdateBlockFragment = true;
        m_needsToUpdateFieldFragment = true;
        tick();
    } else {
        gpu.resumeTimer(m_timer);
    }
    g_tetris.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) { buttonEvent(event); });
}

void MainGame::render() {
    auto& gpu = g_tetris.gpu();
    gpu.clear();
    s_playfield.render(gpu);
    g_tetris.m_font.printf(gpu, {.x = 0, .y = 0}, WHITE, "Score: %i", m_score);
}

namespace {

class Pause final : public psyqo::Scene {
    void start(Scene::StartReason reason) override {
        s_playfield.emptyFragments();
        g_tetris.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) {
            if (event.type != psyqo::SimplePad::Event::ButtonReleased) return;
            if (event.button == psyqo::SimplePad::Start) m_unpause = true;
        });
    }
    void frame() override {
        g_mainGame.render();
        g_tetris.m_font.print(g_tetris.gpu(), "PAUSED", {.x = 0, .y = 2 * 16}, WHITE);
        g_tetris.m_font.print(g_tetris.gpu(), "Press", {.x = 0, .y = 4 * 16}, WHITE);
        g_tetris.m_font.print(g_tetris.gpu(), "Start", {.x = 0, .y = 5 * 16}, WHITE);
        g_tetris.m_font.print(g_tetris.gpu(), "to unpause", {.x = 0, .y = 6 * 16}, WHITE);
        if (m_unpause) {
            m_unpause = false;
            popScene();
        }
    }
    void teardown(Scene::TearDownReason reason) override {
        s_playfield.restoreFragments();
        g_tetris.m_input.setOnEvent(nullptr);
    }
    bool m_unpause = false;
};
Pause s_pause;

class GameOver final : public psyqo::Scene {
    void start(Scene::StartReason reason) override {
        g_tetris.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) {
            if (event.type != psyqo::SimplePad::Event::ButtonReleased) return;
            if (event.button == psyqo::SimplePad::Start) m_unpause = true;
        });
    }
    void frame() override {
        g_mainGame.render();
        g_tetris.m_font.print(g_tetris.gpu(), "GAME OVER", {.x = 0, .y = 2 * 16}, WHITE);
        g_tetris.m_font.print(g_tetris.gpu(), "Press", {.x = 0, .y = 4 * 16}, WHITE);
        g_tetris.m_font.print(g_tetris.gpu(), "Start", {.x = 0, .y = 5 * 16}, WHITE);
        g_tetris.m_font.print(g_tetris.gpu(), "to exit", {.x = 0, .y = 6 * 16}, WHITE);
        if (m_unpause) {
            m_unpause = false;
            popScene();
            popScene();
        }
    }
    void teardown(Scene::TearDownReason reason) override { g_tetris.m_input.setOnEvent(nullptr); }
    bool m_unpause = false;
};
GameOver s_gameOver;

}  // namespace

void MainGame::frame() {
    if (m_needsToUpdateFieldFragment) {
        m_needsToUpdateFieldFragment = false;
        s_playfield.updateFieldFragment();
    }
    if (m_needsToUpdateBlockFragment) {
        m_needsToUpdateBlockFragment = false;
        s_playfield.updateBlockFragment(m_currentBlock, m_blockX, m_blockY, m_blockRotation);
    }
    render();
    if (m_gameOver) {
        m_gameOver = false;
        pushScene(&s_gameOver);
    }
    if (m_paused) {
        m_paused = false;
        pushScene(&s_pause);
    }
}

void MainGame::teardown(Scene::TearDownReason reason) {
    auto& gpu = g_tetris.gpu();
    if (reason == Scene::TearDownReason::Destroy) {
        gpu.cancelTimer(m_timer);
    } else {
        gpu.pauseTimer(m_timer);
    }
    g_tetris.m_input.setOnEvent(nullptr);
}
