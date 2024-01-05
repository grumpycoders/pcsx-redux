/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

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

#include "common/syscalls/syscalls.h"
#include "psyqo/application.hh"
#include "psyqo/fixed-point.hh"
#include "psyqo/gpu.hh"
#include "psyqo/primitives/common.hh"
#include "psyqo/primitives/sprites.hh"
#include "psyqo/scene.hh"
#include "psyqo/trigonometry.hh"

using namespace psyqo::trig_literals;
using namespace psyqo::fixed_point_literals;

namespace {

// This example will showcase how to use textures, but it won't come from a file. Instead, we will
// procedurally generate a texture, and then use it. This is a fairly simple example, but it should
// be enough to get started with textures in general.

class Texture final : public psyqo::Application {
    void prepare() override;
    void createScene() override;
};

class TextureScene final : public psyqo::Scene {
    void start(Scene::StartReason reason) override;
    void frame() override;
    uint8_t computePixel(uint8_t x, uint8_t y);
    // We use trigonometry to generate the texture procedurally.
    psyqo::Trig<> m_trig;
    // The final rendering will be animated, using a clut rotation.
    uint8_t m_anim = 0;
};

Texture texture;
TextureScene textureScene;

}  // namespace

void Texture::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void Texture::createScene() { pushScene(&textureScene); }

// The algorithm we're using to procedurally generate a texture is basically your standard
// plasma effect. Here is how this is supposed to look like: https://www.shadertoy.com/view/XfBGzK
// The resulting texture will be 8bpp, and will be used as a sort of heatmap, where the color
// represents the value of the function at that point. The texture will be 256x256 pixels. We will
// use a CLUT rotation to animate the texture, and make it look like it's a wave moving across.

// This computes a single pixel of the texture, based off its x, y coordinates, pretty much like a
// shader would. The result is a 8-bit value, which is the "height" of the pixel.
uint8_t TextureScene::computePixel(uint8_t x_, uint8_t y_) {
    psyqo::Angle x(x_ * 8, psyqo::Angle::RAW);
    psyqo::Angle y(y_ * 8, psyqo::Angle::RAW);
    // These coefficients have been chosen so that the resulting range of values for `v` is
    // exactly [-4, 4]. This is so that we can use the `integer` method of the fixed-point
    // class to convert the value to an 8-bit integer, by multiplying by 32 and adding 128,
    // in order to get a value in the range [0, 255]. We also clamp the value to make sure
    // it doesn't go out of bounds.
    //
    // All of the inner coefficients have been chosen in a way that makes the resulting
    // texture repeat properly on its edges.
    //
    // While the math is not particularly complicated, it will involve a fair amount of
    // table lookups and multiplications, so it's not going to be particularly fast.
    auto v = m_trig.sin(x) + 0.8_fp * m_trig.sin(x * 2) + 0.3_fp * m_trig.cos(x * 3) * m_trig.sin(x * 5) +
             m_trig.sin(y * 2) + 0.7_fp * m_trig.cos(y * 8) +
             0.2_fp * m_trig.sin(y * 4) * m_trig.cos(y * 11) * m_trig.sin(x * 8);
    return eastl::clamp(v.integer<32>() + 128, int32_t(0), int32_t(255));
}

void TextureScene::start(Scene::StartReason reason) {
    // We are going to upload the texture to 512, 0.
    // We manually send data to the GPU without DMA, because using temporary memory
    // for this is a waste. The computation time is extremely high, compared to the
    // time it takes to send the data to the GPU, so any gains from using DMA would
    // be negligible. If uploading a texture which is in RAM, it's better to use DMA,
    // using the `uploadToVRAM` method of the GPU class instead of manually sending
    // the data like we do here.
    psyqo::Rect region = {.pos = {{.x = 512, .y = 0}}, .size = {{.w = 128, .h = 256}}};
    psyqo::Prim::VRAMUpload upload;
    upload.region = region;
    gpu().sendPrimitive(upload);
    for (unsigned y = 0; y < 256; y++) {
        for (unsigned x = 0; x < 256; x += 4) {
            uint32_t d = 0;
            for (unsigned i = 0; i < 4; i++) {
                uint32_t c = computePixel(x + i, y);
                d >>= 8;
                c <<= 24;
                d |= c;
            }
            gpu().sendRaw(d);
        }
    }
    // Then, we need to create the CLUTs. Since the input texture is 8bpp, we need a CLUT with 256
    // entries. If we want to move the wave line across all possible values of the generated texture,
    // we technically need 256 CLUTs, but we can get away with just 16, and abuse the fact that the
    // GPU allows to select a CLUT every 16 pixels. This means that we can just leverage a single
    // 496x16 CLUT region, and pick the proper start index for the CLUT based on where within the
    // animation we are. This is a significant memory saving.
    region = {.pos = {{.x = 512, .y = 256}}, .size = {{.w = 496, .h = 16}}};
    upload.region = region;
    gpu().sendPrimitive(upload);
    for (unsigned y = 240; y < 256; y++) {
        for (unsigned x = 0; x < 496; x += 2) {
            uint32_t d = 0;
            for (unsigned i = 0; i < 2; i++) {
                auto tx = x + i;
                // These values are basically a grey-scale linear gradient, around the position
                // of the line.
                uint32_t c = 0xbdef;
                if (tx == y) c = 0xffff;
                if (tx == (y + 1)) c = 0xef7b;
                if (tx == (y - 1)) c = 0xef7b;
                if (tx == (y + 2)) c = 0xdef7;
                if (tx == (y - 2)) c = 0xdef7;
                if (tx == (y + 3)) c = 0xce73;
                if (tx == (y - 3)) c = 0xce73;
                d >>= 16;
                c <<= 16;
                d |= c;
            }
            gpu().sendRaw(d);
        }
    }
    // Finally, we need to flush the cache, because we have uploaded new texture and CLUT data.
    psyqo::Prim::FlushCache fc;
    gpu().sendPrimitive(fc);
}

void TextureScene::frame() {
    // It is time to render the texture. We are going to clear the screen first.
    gpu().clear();

    // Setting up the texture page. We are using 8bpp, so we need to set the 8bpp flag.
    // We also need to set the page to 8, 0, because the texture is at 512, 0 in the VRAM.
    // We also need to enable drawing within the display area, because otherwise the texture
    // will not be rendered in our display area.
    psyqo::Prim::TPage tpage;
    tpage.attr.setPageX(8).setPageY(0).set(psyqo::Prim::TPageAttr::Tex8Bits).enableDisplayArea();
    gpu().sendPrimitive(tpage);

    // We are going to use a sprite, because it's the simplest primitive that allows us to
    // specify a texture. Its size will be 256x256, and it will be positioned at 32, -8. It's
    // ironically too large to fit on the screen, as we only have 240 lines.
    // Our sprite will be a solid blue color, which will be modulated by the texture. This means
    // we can easily change the color of the texture by changing the color of the sprite. We could
    // also use polygons, and leverage gouraud shading, in order to add some material-like
    // properties to the texture.
    psyqo::Prim::Sprite sprite(psyqo::Color{{.r = 0x01, .g = 0x38, .b = 0x7f}});
    sprite.position = {{.x = 32, .y = -8}};
    sprite.size = {{.w = 256, .h = 256}};
    uint8_t anim = m_anim++;
    // In order to animate the texture, we need to select the proper CLUT from the 16 we generated.
    // We shift our X position depending on the animation step, in order to create the illusion of
    // having 256 CLUTs.
    sprite.texInfo = {.u = 0,
                      .v = 0,
                      .clut = psyqo::Prim::ClutIndex(
                          psyqo::Vertex{{.x = int16_t(512 + (anim & 0xf0)), .y = int16_t(271 - (anim & 0x0f))}})};

    // Finally, we can send the sprite to the GPU.
    gpu().sendPrimitive(sprite);
}

int main() { return texture.run(); }
