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
#include "splash.hh"

class Tetris final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

    bool m_initialized = false;

  public:
    void renderTetrisLogo(psyqo::GPU& gpu);
    psyqo::Color getBlink(psyqo::GPU& gpu, unsigned scale = 1);

    psyqo::SimplePad m_input;
    psyqo::Font<> m_font;

    Rand m_rand;

    SplashScreen m_splash;
    MainMenu m_mainMenu;
    Options m_options;
    Credits m_credits;
    MainGame m_mainGame;
    Pause m_pause;
    GameOver m_gameOver;

    Playfield<10, 20> m_playfield;
};

extern Tetris g_tetris;
