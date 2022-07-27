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

#include "sound.hh"

extern "C" {
#include "modplayer/modplayer.h"
}

void Sound::playClick() {
    MOD_PlaySoundEffect(4, 28, 30, m_volume);
}

void Sound::playFlip(int pitch) {
    MOD_PlaySoundEffect(5, 27, 30 + pitch, m_volume);
}

void Sound::playDrop(unsigned int volume) {
    auto vol = m_volume;
    MOD_PlaySoundEffect(6, 30, 30, vol);
    if (volume >= 1) {
        MOD_PlaySoundEffect(7, 30, 30, vol);
    }
    if (volume >= 2) {
        MOD_PlaySoundEffect(8, 30, 30, vol);
    }
    if (volume >= 3) {
        MOD_PlaySoundEffect(9, 30, 30, vol);
    }
    if (volume >= 4) {
        MOD_PlaySoundEffect(10, 30, 30, vol);
        MOD_PlaySoundEffect(11, 30, 30, vol);
        MOD_PlaySoundEffect(12, 30, 30, vol);
    }
}
