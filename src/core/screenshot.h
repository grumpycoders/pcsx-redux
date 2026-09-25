#pragma once

#include <string>
#include <sstream>
#include <ctime>

#include "core/gpu.h"
#include "clip/clip.h"

namespace PCSX::ScreenShot {
    std::string getDateString();
    clip::image convertScreenshotToImage(PCSX::GPU::ScreenShot&& screenshot);
    bool writeImagePNG(std::string filename, clip::image&& img);
}
