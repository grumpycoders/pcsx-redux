#include "core/screenshot.h"

clip::image PCSX::ScreenShot::convertScreenshotToImage(PCSX::GPU::ScreenShot&& screenshot) {
    clip::image_spec spec;
    spec.width = screenshot.width;
    spec.height = screenshot.height;
    if (screenshot.bpp == PCSX::GPU::ScreenShot::BPP_16) {
        spec.bits_per_pixel = 16;
        spec.bytes_per_row = screenshot.width * 2;
        spec.red_mask = 0x1f;  // 0x7c00;
        spec.green_mask = 0x3e0;
        spec.blue_mask = 0x7c00;  // 0x1f;
        spec.alpha_mask = 0;
        spec.red_shift = 0;  // 10;
        spec.green_shift = 5;
        spec.blue_shift = 10;  // 0;
        spec.alpha_shift = 0;
    } else {
        spec.bits_per_pixel = 24;
        spec.bytes_per_row = screenshot.width * 3;
        spec.red_mask = 0xff0000;
        spec.green_mask = 0xff00;
        spec.blue_mask = 0xff;
        spec.alpha_mask = 0;
        spec.red_shift = 16;
        spec.green_shift = 8;
        spec.blue_shift = 0;
        spec.alpha_shift = 0;
    }
    clip::image img(screenshot.data.data(), spec);
    return img.to_rgba8888();
}

bool PCSX::ScreenShot::writeImagePNG(std::string filename, clip::image&& img) { return img.export_to_png(filename); }

std::string PCSX::ScreenShot::getDateString() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    auto local_time = std::localtime(&in_time_t);

    std::stringstream ss;
    constexpr const char* SCREENSHOT_DATE_FORMAT = "%Y-%m-%d-%H-%M-%S";
    ss << std::put_time(local_time, SCREENSHOT_DATE_FORMAT);

    std::string datetime_string = ss.str();

    return datetime_string;
}
