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

struct psyqo::GPU::Configuration {
    Configuration &set(Resolution resolution) {
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
    Configuration &set(VideoMode videoMode) {
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
    Configuration &set(ColorMode colorMode) {
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
    Configuration &set(Interlace interlace) {
        config.videoInterlace = interlace == Interlace::INTERLACED ? VI_ON : VI_OFF;
        return *this;
    }

  private:
    enum HResolution {
        HR_EXTENDED,
        HR_256 = 0,
        HR_320 = 1,
        HR_512 = 2,
        HR_640 = 3,
    };

    enum VResolution {
        VR_240 = 0,
        VR_480 = 1,
    };

    enum VMode {
        VM_NTSC = 0,
        VM_PAL = 1,
    };

    enum ColorDepth {
        CD_15BITS = 0,
        CD_24BITS = 1,
    };

    enum VideoInterlace {
        VI_OFF = 0,
        VI_ON = 1,
    };

    enum HResolutionExtended {
        HRE_NORMAL = 0,
        HRE_368 = 1,
    };

    struct DisplayModeConfig {
        enum HResolution hResolution;
        enum VResolution vResolution;
        enum VMode videoMode;
        enum ColorDepth colorDepth;
        enum VideoInterlace videoInterlace;
        enum HResolutionExtended hResolutionExtended;
    };

    DisplayModeConfig config = {};
    friend class GPU;
};
