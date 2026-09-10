/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

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

// Conway's Game of Life on a wrapping board, with no platform dependencies at
// all. This makes it possible to run the simulation in a test harness.

#pragma once

#include <stdint.h>

namespace life {

// 24x24 is the largest board that still leaves the cubes individually legible
// at 320x240, and 576 cells is comfortably inside the per-frame GTE budget even
// in the first dense generation of a fresh soup.
static constexpr unsigned kGridW = 24;
static constexpr unsigned kGridH = 24;
static constexpr unsigned kCellCount = kGridW * kGridH;

// A board is one byte per cell, 0 or 1. A bitboard would be smaller but
// considerably less readable, and 576 bytes is not the constraint here.
struct Board {
    uint8_t cells[kCellCount];

    uint8_t at(unsigned x, unsigned y) const { return cells[y * kGridW + x]; }
    void set(unsigned x, unsigned y, uint8_t v) { cells[y * kGridW + x] = v; }

    void clear() {
        for (unsigned i = 0; i < kCellCount; i++) cells[i] = 0;
    }

    unsigned population() const {
        unsigned n = 0;
        for (unsigned i = 0; i < kCellCount; i++) n += cells[i];
        return n;
    }

    bool operator==(const Board& other) const {
        for (unsigned i = 0; i < kCellCount; i++) {
            if (cells[i] != other.cells[i]) return false;
        }
        return true;
    }
    bool operator!=(const Board& other) const { return !(*this == other); }
};

// The board wraps, so the field has no edges to collect debris against and a
// glider runs forever instead of walking off into nothing. Wrapping is done with
// a conditional rather than a modulo because the offsets are only ever +/-1:
// (x + kGridW - 1) % kGridW is the correct form for a modular decrement, but on
// an R3000 the compare is cheaper than the divide and this runs 576 * 8 times a
// generation.
static inline unsigned wrapDec(unsigned v, unsigned n) { return v == 0 ? n - 1 : v - 1; }
static inline unsigned wrapInc(unsigned v, unsigned n) { return v + 1 == n ? 0 : v + 1; }

static inline unsigned neighbours(const Board& b, unsigned x, unsigned y) {
    unsigned xm = wrapDec(x, kGridW), xp = wrapInc(x, kGridW);
    unsigned ym = wrapDec(y, kGridH), yp = wrapInc(y, kGridH);
    return b.at(xm, ym) + b.at(x, ym) + b.at(xp, ym) + b.at(xm, y) + b.at(xp, y) + b.at(xm, yp) + b.at(x, yp) +
           b.at(xp, yp);
}

static inline void step(const Board& in, Board* out) {
    for (unsigned y = 0; y < kGridH; y++) {
        for (unsigned x = 0; x < kGridW; x++) {
            unsigned n = neighbours(in, x, y);
            uint8_t alive = in.at(x, y);
            out->set(x, y, (n == 3 || (alive && n == 2)) ? 1 : 0);
        }
    }
}

// xorshift32.
struct Rng {
    uint32_t state;
    explicit Rng(uint32_t seed) : state(seed ? seed : 0x1d872b41) {}
    uint32_t next() {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    }
};

// Fills the board with a random soup at roughly `percent` density.
static inline void soup(Board* b, Rng* rng, unsigned percent) {
    for (unsigned i = 0; i < kCellCount; i++) {
        b->cells[i] = (rng->next() % 100u) < percent ? 1 : 0;
    }
}

static constexpr unsigned kSoupDensityPercent = 32;
// A board that has come back to a state it held two generations ago is in a
// still-life or period-2 attractor and nothing further will happen to it. Give
// it a few generations of grace anyway: a large board can be locally periodic
// while another region is still running, and the two-generation test cannot
// tell those two apart from one sample.
static constexpr unsigned kStableGenerationsBeforeReseed = 6;

// The whole simulation, including the policy for deciding a board is finished.
// That policy lives here rather than in the renderer because it is the part
// most likely to be wrong in a way nobody notices - a detector that never fires
// looks exactly like a board that never settles, and both of those look like a
// working demo until you sit and watch it for five minutes.
struct Sim {
    Board board;
    Board scratch;
    // The board as it was two generations ago. Comparing against the PREVIOUS
    // generation only catches still lifes, and a board of nothing but blinkers
    // would then run for ever while nothing about it ever changed again.
    Board twoAgo;
    Rng rng;
    unsigned generation = 0;
    unsigned population = 0;
    unsigned stableFor = 0;
    unsigned reseeds = 0;

    explicit Sim(uint32_t seed) : rng(seed) { reseed(); }

    void reseed() {
        soup(&board, &rng, kSoupDensityPercent);
        twoAgo.clear();
        population = board.population();
        generation = 0;
        stableFor = 0;
        reseeds++;
    }

    void advance() {
        step(board, &scratch);
        bool repeated = (scratch == twoAgo);
        twoAgo = board;
        board = scratch;
        population = board.population();
        generation++;

        if (population == 0) {
            reseed();
            return;
        }
        if (repeated) {
            if (++stableFor >= kStableGenerationsBeforeReseed) reseed();
        } else {
            stableFor = 0;
        }
    }
};

}  // namespace life
