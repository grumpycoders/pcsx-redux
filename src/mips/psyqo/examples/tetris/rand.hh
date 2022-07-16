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

// An extremely simple random number generator that is absolutely
// not cryptographically secure, and not very good.
class Rand {
  public:
    // Gets a 32-bits random number, except the value 0.
    uint32_t rand();

    // Gets a random number between 0 and RANGE, exclusive.
    template <uint32_t RANGE>
    uint32_t rand() {
        return rand() % RANGE;
    }

    // Initializes the random number generator. Optional, but
    // recommended to avoid the same sequence every time. Use
    // for example the `now` function of the `GPU` class to
    // pass as a seed argument. Due to the way it works,
    // the random number generator will break if seed == 0.
    void seed(uint32_t seed);

  private:
    static constexpr uint32_t INITIAL_SEED = 2891583007UL;
    uint32_t m_seed = INITIAL_SEED;
};
