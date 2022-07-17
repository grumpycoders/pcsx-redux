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

#include "credits.hh"
#include "game.hh"
#include "gameover.hh"
#include "mainmenu.hh"
#include "options.hh"
#include "pause.hh"
#include "playfield.hh"
#include "psyqo/application.hh"
#include "psyqo/font.hh"
#include "psyqo/simplepad.hh"
#include "rand.hh"
#include "sound.hh"
#include "splash.hh"

// This is our top application class. It's what will run as the software starts.
// See tetris.cpp for details on the main function and the details on the
// methods implementations.

class Tetris final : public psyqo::Application {
    // These two methods are called by the PSYQo framework.
    void prepare() override;
    void createScene() override;

    // We keep track of how many times we've been called to
    // avoid initializing the hardware multiple times.
    bool m_initialized = false;

  public:
    // A helper used in multiple scenes to draw the main logo.
    void renderTetrisLogo();
    // A helper used in multiple scenes to get a blinking color.
    psyqo::Color getBlink(unsigned scale = 1);

    // We're going to use the SimplePad interface to handle the input.
    psyqo::SimplePad m_input;
    // The font renderer. We instantiate it with the defaut amount of
    // fragments, but we're not actually using that many.
    psyqo::Font<> m_font;

    // Everything else here is the Tetris implementation details.

    // We're going to use a global random number generator, stored here.
    Rand m_rand;

    // The splash screen scene. It'll be the first thing to be displayed.
    SplashScreen m_splash;
    // The main menu scene. It comes right after the splash screen.
    MainMenu m_mainMenu;
    // The options scene. It's one of the main menu entries.
    Options m_options;
    // The credits scene. It's one of the main menu entries.
    Credits m_credits;
    // The main game. Started from the main scene. It's the most
    // complex one in the whole example.
    MainGame m_mainGame;
    // The pause scene. It will be pushed on top of the main game scene.
    Pause m_pause;
    // The game over scene. It will be pushed on top of the main game scene.
    GameOver m_gameOver;

    // The sound engine.
    Sound m_sound;

    // This represents the global playfield state. It's a completely custom
    // class, implemented in the playfield.hh file.
    Playfield<10, 20> m_playfield;

  private:
    // The global timer used by the mod player.
    unsigned m_musicTimer;
};

// We're only going to use a single global to hold everything. It'll
// be defined in tetris.cpp, and this is its definition for all the
// other modules in this project.
extern Tetris g_tetris;
