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

#include <EASTL/functional.h>
#include <EASTL/utility.h>
#include <stdint.h>

#include "common/hardware/gpu.h"

namespace psyqo {

class GPU {
  public:
    enum Resolution { W256, W320, W368, W512, W640 };
    enum VideoMode { AUTO, NTSC, PAL };
    enum ColorMode { C15BITS, C24BITS };
    struct Configuration {
        Configuration &setResolution(Resolution resolution) {
            if (resolution == Resolution::W368) {
                config.hResolution = HR_EXTENDED;
                config.hResolutionExtended = HRE_368;
            } else {
                config.hResolutionExtended = HRE_NORMAL;
                switch (resolution) {
                    case Resolution::W256:
                        config.hResolution = HR_256;
                        break;
                    case Resolution::W320:
                        config.hResolution = HR_320;
                        break;
                    case Resolution::W512:
                        config.hResolution = HR_512;
                        break;
                    case Resolution::W640:
                        config.hResolution = HR_640;
                        break;
                }
            }
            return *this;
        }
        Configuration &setVideoMode(VideoMode videoMode) {
            switch (videoMode) {
                case VideoMode::AUTO:
                    config.videoMode = (*((char *)0xbfc7ff52) == 'E') ? VM_PAL : VM_NTSC;
                    break;
                case VideoMode::NTSC:
                    config.videoMode = VM_NTSC;
                    break;
                case VideoMode::PAL:
                    config.videoMode = VM_PAL;
                    break;
            }
            return *this;
        }
        Configuration &setColorMode(ColorMode colorMode) {
            switch (colorMode) {
                case ColorMode::C15BITS:
                    config.colorDepth = CD_15BITS;
                    break;
                case ColorMode::C24BITS:
                    config.colorDepth = CD_24BITS;
                    break;
            }
            return *this;
        }
        Configuration &setInterlace(bool interlace) {
            config.videoInterlace = interlace ? VI_ON : VI_OFF;
            return *this;
        }

      private:
        DisplayModeConfig config = {};
        friend class GPU;
    };
    void initialize(const Configuration &config);
    void onVsync(eastl::function<void(void)> &&callback) { m_vsync = eastl::move(callback); }
    uint32_t getFrameCount() { return m_frameCount; }
    void clear(Color bg = {{0, 0, 0}});

  private:
    eastl::function<void(void)> m_vsync = nullptr;
    int m_width = 0;
    int m_height = 0;
    uint32_t m_frameCount = 0;
    uint32_t m_previousFrameCount = 0;
    int m_parity = 0;
    bool m_interlaced = false;
    void flip();
    friend class Application;
};

}  // namespace psyqo
