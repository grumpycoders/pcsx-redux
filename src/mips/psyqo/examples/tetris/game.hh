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

#include "psyqo/scene.hh"
#include "psyqo/simplepad.hh"

// The main game scene is the most complex of all the scenes
// in this example. It is responsible for processing the logic
// of the game and reacting to all the events. It will hold
// a periodic timer sending tick events to advance the state
// of the game.
class MainGame final : public psyqo::Scene {
  public:
    // The `render` method is public in order to be called
    // from the pause and game over scenes.
    void render();

  private:
    // These three methods are our familiar methods for
    // the PSYQo framework to function.
    void start(Scene::StartReason reason) override;
    void frame() override;
    void teardown(Scene::TearDownReason reason) override;

    // The `tick` method is called by the periodic timer.
    // It is responsible for updating the state of the game.
    // The logic is too complex to be added in-place within
    // the timer registration. We will also call it manually
    // in order to get certain events processed early.
    void tick();
    // The `buttonEvent` method is called by the input
    // callback when the user changes a button state.
    // The logic is too complex to be added in-place within
    // the input callback.
    void buttonEvent(const psyqo::SimplePad::Event& event);

    // These are helper methods for the game logic.
    void createBlock();
    void moveLeft();
    void moveRight();
    void rotateLeft();
    void rotateRight();
    // The `rotation` parameter is the absolute rotation
    // value between 0 and 3.
    void rotate(unsigned rotation);
    // This method is responsible for updating the timer
    // period according to the user score.
    void recomputePeriod();

    // This is the id of the timer we're registering.
    unsigned m_timer;
    // The current score of the player. It will influence
    // the speed of the game.
    unsigned m_score;
    // The current interval between ticks.
    uint32_t m_period;
    // This is basically a constant to set the periodic timer
    // with when the player presses down. It could be an actual
    // constant too, but this allows us to easily adjust it
    // using debug primitives.
    uint32_t m_fastPeriod;
    // The current tetromino, between 1 and 7, or 0 if none,
    // and its rotation between 0 and 3.
    uint8_t m_currentBlock, m_blockRotation;
    // The tetromino's location.
    int8_t m_blockX, m_blockY;
    // The various state transitions.
    bool m_gameOver = false;
    bool m_paused = false;
    bool m_needsToUpdateFieldFragment = false;
    bool m_needsToUpdateBlockFragment = false;
};
