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

// This method will be called by the periodic timer. The period will
// vary depending on the score of the game, or when the player
// presses buttons like speed up or drop. There is a few moments when
// this method will be called manually in order to trigger a tick
// logic immediately.
void MainGame::tick() {
    // If we don't have any current tetromino, we create one, and verify our
    // game over condition.
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
    // Hitting something on a tick will cause the block to fuse with the playfield.
    if (g_tetris.m_playfield.collision(m_currentBlock, m_blockX, m_blockY + 1, m_blockRotation)) {
        g_tetris.m_playfield.place(m_currentBlock, m_blockX, m_blockY, m_blockRotation);
        // We check for completed lines, and update the player's score accordingly.
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
        g_tetris.m_sound.playDrop(lines);
        // Maybe the score changed and we need to update the period of our timer.
        recomputePeriod();
        // We will have one tick without a block on the screen.
        m_currentBlock = 0;
        if (!g_tetris.m_input.isButtonPressed(psyqo::SimplePad::Pad::Pad1, psyqo::SimplePad::Button::Down)) {
            // If the user keeps the button down pressed, we won't update the period of the timer.
            // The reason we want to update the period back otherwise is maybe the score update
            // changed it.
            g_tetris.gpu().changeTimerPeriod(m_timer, m_period);
        }
        // As we fused, we need to update both fragments of our playfield.
        m_needsToUpdateFieldFragment = true;
        m_needsToUpdateBlockFragment = true;
    } else {
        // If we don't hit anything, we just move the block down.
        m_blockY++;
        m_needsToUpdateBlockFragment = true;
    }
}

// This helper instantiates a new tetromino on the top of the playfield.
void MainGame::createBlock() {
    m_currentBlock = g_tetris.m_rand.rand<7>() + 1;
    m_blockX = g_tetris.m_playfield.Columns / 2 - 2;
    m_blockY = 0;
    m_blockRotation = 0;
}

// Computes the period of our timer according to the player's score.
void MainGame::recomputePeriod() {
    // Every 2000 points, the period of the timer will be decreased by 0.1s.
    int scoreRange = m_score / 2000;
    if (scoreRange >= 10) {
        // We won't go below 0.1s per tick.
        scoreRange = 9;
    }
    m_period = 1'000'000 - scoreRange * 100'000;
}

// This method is called by our event handler, as it's too complex to be
// inlined. It handles the input of the player, and updates the game
// accordingly.
void MainGame::buttonEvent(const psyqo::SimplePad::Event& event) {
    if (event.pad != psyqo::SimplePad::Pad::Pad1) return;
    if (event.type == psyqo::SimplePad::Event::ButtonPressed) {
        // If there's no current block, we don't care about any button presses.
        // We still care about button releases, which is a different condition
        // further down in this method.
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
                // When the player presses the triangle button, we will drop the
                // tetromino as fast as possible to its lowest possible position.
                // We call the tick method to trigger the game logic code, but
                // we also update the timer's period to reset its deadline to
                // avoid the new tetromino to appear too quickly.
                while (!g_tetris.m_playfield.collision(m_currentBlock, m_blockX, m_blockY, m_blockRotation)) {
                    m_blockY++;
                }
                m_blockY--;
                g_tetris.gpu().changeTimerPeriod(m_timer, m_period, true);
                tick();
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
                // When the user releases the down button, we will update the
                // period of the timer back to its normal value.
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

// Helpers to handle moving the tetromino around.
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

// The rotation logic is identical regardless of the rotation direction, so we have
// another helper method to handle the rotation.
void MainGame::rotateLeft() {
    unsigned rotation = m_blockRotation;
    if (rotation == 0) {
        rotation = 3;
    } else {
        rotation--;
    }
    rotate(rotation);
    g_tetris.m_sound.playFlip(-g_tetris.m_rand.rand<2>());
}

void MainGame::rotateRight() {
    unsigned rotation = m_blockRotation;
    if (rotation == 3) {
        rotation = 0;
    } else {
        rotation++;
    }
    rotate(rotation);
    g_tetris.m_sound.playFlip(g_tetris.m_rand.rand<2>());
}

// When rotating, we try to jiggle the block around a bit to make it fit.
// We could jiggle it a lot, but that would maybe making it too easy for the player.
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

// When the scene is created from the main menu, we want to
// initialize everything. Otherwise, we simply want to resume
// the timer that was paused during `teardown`.
void MainGame::start(Scene::StartReason reason) {
    auto& gpu = g_tetris.gpu();
    if (reason == Scene::StartReason::Create) {
        // Shuffle our random number generator a bit.
        g_tetris.m_rand.seed(gpu.now());
        // Make sure the playfield is reset.
        g_tetris.m_playfield.clear();
        // Reset the state properly.
        m_period = 1'000'000;
        m_score = 0;
        m_currentBlock = 0;
        m_needsToUpdateBlockFragment = true;
        m_needsToUpdateFieldFragment = true;
        // Register the timer, and trigger a tick immediately to
        // make sure a tetromino is being created.
        m_timer = gpu.armPeriodicTimer(m_period, [this](uint32_t) { tick(); });
        tick();
    } else {
        gpu.resumeTimer(m_timer);
    }
    g_tetris.m_input.setOnEvent([this](const psyqo::SimplePad::Event& event) { buttonEvent(event); });
}

// Our `render` method is very simple at the end of the day. We're only going to
// send the playfield's fragments to the GPU. The fragments are only updated when
// the state of the game changes, so our main loop will be mostly idle most of the time.
void MainGame::render() {
    auto& gpu = g_tetris.gpu();
    gpu.clear();
    g_tetris.m_playfield.render(gpu);
    // Note this call will always update its fragment at all
    // times, which is wasteful. This API might change in the future.
    g_tetris.m_font.printf(gpu, {{.x = 0, .y = 0}}, WHITE, "Score: %i", m_score);
}

void MainGame::frame() {
    // When we need to draw a frame, first we're going to update our fragments, if necessary.
    if (m_needsToUpdateFieldFragment) {
        m_needsToUpdateFieldFragment = false;
        g_tetris.m_playfield.updateFieldFragment();
    }
    if (m_needsToUpdateBlockFragment) {
        m_needsToUpdateBlockFragment = false;
        g_tetris.m_playfield.updateBlockFragment(m_currentBlock, m_blockX, m_blockY, m_blockRotation);
    }
    // Then we render them at all times. The `render` function will also clear the screen.
    render();
    // And finally, we update our states.
    if (m_gameOver) {
        m_gameOver = false;
        pushScene(&g_tetris.m_gameOver);
    }
    if (m_paused) {
        m_paused = false;
        pushScene(&g_tetris.m_pause);
    }
}

// When the scene is teared down, we either pause the timer, or we destroy it,
// depending on the direction of the teardown. We also unregister the input callback.
void MainGame::teardown(Scene::TearDownReason reason) {
    auto& gpu = g_tetris.gpu();
    if (reason == Scene::TearDownReason::Destroy) {
        gpu.cancelTimer(m_timer);
    } else {
        gpu.pauseTimer(m_timer);
    }
    g_tetris.m_input.setOnEvent(nullptr);
}
