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

#include "tetris.hh"

void MainGame::tick() {
    if (m_currentBlock == 0) {
        createBlock();
        if (g_tetris.m_playfield.collision(m_currentBlock, m_blockX, m_blockY, m_blockRotation)) {
            m_gameOver = true;
            g_tetris.m_playfield.fillRandom(g_tetris.m_rand);
            m_needsToUpdateFieldFragment = true;
        }
        m_needsToUpdateBlockFragment = true;
        return;
    }
    if (g_tetris.m_playfield.collision(m_currentBlock, m_blockX, m_blockY + 1, m_blockRotation)) {
        if (m_bottomHitOnce) {
            g_tetris.m_playfield.place(m_currentBlock, m_blockX, m_blockY, m_blockRotation);
            int lines = g_tetris.m_playfield.removeLines();
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
    m_currentBlock = g_tetris.m_rand.rand<7>() + 1;
    m_blockX = g_tetris.m_playfield.Columns / 2 - 2;
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
                while (!g_tetris.m_playfield.collision(m_currentBlock, m_blockX, m_blockY, m_blockRotation)) {
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
    if (g_tetris.m_playfield.collision(m_currentBlock, m_blockX - 1, m_blockY, m_blockRotation)) {
        return;
    }
    m_blockX--;
    m_needsToUpdateBlockFragment = true;
}

void MainGame::moveRight() {
    if (g_tetris.m_playfield.collision(m_currentBlock, m_blockX + 1, m_blockY, m_blockRotation)) {
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
    if (g_tetris.m_playfield.collision(m_currentBlock, m_blockX, m_blockY, rotation)) {
        if (m_blockX > g_tetris.m_playfield.Columns / 2 - 2) {
            shiftX = -1;
        } else {
            shiftX = 1;
        }
        if (g_tetris.m_playfield.collision(m_currentBlock, m_blockX + shiftX, m_blockY, rotation)) {
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
        g_tetris.m_rand.seed(gpu.now());
        g_tetris.m_playfield.clear();
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
    g_tetris.m_playfield.render(gpu);
    g_tetris.m_font.printf(gpu, {{.x = 0, .y = 0}}, WHITE, "Score: %i", m_score);
}

void MainGame::frame() {
    if (m_needsToUpdateFieldFragment) {
        m_needsToUpdateFieldFragment = false;
        g_tetris.m_playfield.updateFieldFragment();
    }
    if (m_needsToUpdateBlockFragment) {
        m_needsToUpdateBlockFragment = false;
        g_tetris.m_playfield.updateBlockFragment(m_currentBlock, m_blockX, m_blockY, m_blockRotation);
    }
    render();
    if (m_gameOver) {
        m_gameOver = false;
        pushScene(&g_tetris.m_gameOver);
    }
    if (m_paused) {
        m_paused = false;
        pushScene(&g_tetris.m_pause);
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
