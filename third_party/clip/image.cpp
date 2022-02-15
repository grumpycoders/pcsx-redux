
// Clip Library
// Copyright (c) 2015-2018 David Capello
//
// This file is released under the terms of the MIT license.
// Read LICENSE.txt for more information.

#include <stdint.h>

#include <bitset>
#include <vector>

#include "clip.h"
#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_STATIC
#define STBI_ASSERT(x) assert(x)
#define STBI_NO_HDR
#define STBI_NO_LINEAR
#define STBI_NO_STDIO
#define STBI_ONLY_PNG
#include "stb/stb_image.h"

#define STB_IMAGE_WRITE_IMPLEMENTATION
#define STB_IMAGE_WRITE_STATIC
#define STBIW_WINDOWS_UTF8
#include "stb/stb_image_write.h"

namespace clip {

image::image()
  : m_own_data(false),
    m_data(nullptr)
{
}

image::image(const image_spec& spec)
  : m_own_data(true),
    m_data(new char[spec.bytes_per_row*spec.height]),
    m_spec(spec) {
}

image::image(const void* data, const image_spec& spec)
  : m_own_data(false),
    m_data((char*)data),
    m_spec(spec) {
}

image::image(const image& image)
  : m_own_data(false),
    m_data(nullptr),
    m_spec(image.m_spec) {
  copy_image(image);
}

image::image(image&& image)
  : m_own_data(false),
    m_data(nullptr) {
  move_image(std::move(image));
}

image::~image() {
  reset();
}

image& image::operator=(const image& image) {
  copy_image(image);
  return *this;
}

image& image::operator=(image&& image) {
  move_image(std::move(image));
  return *this;
}

void image::reset() {
  if (m_own_data) {
    delete[] m_data;
    m_own_data = false;
    m_data = nullptr;
  }
}

void image::copy_image(const image& image) {
  reset();

  m_spec = image.spec();
  std::size_t n = m_spec.bytes_per_row*m_spec.height;

  m_own_data = true;
  m_data = new char[n];
  std::copy(image.data(),
            image.data()+n,
            m_data);
}

void image::move_image(image&& image) {
  std::swap(m_own_data, image.m_own_data);
  std::swap(m_data, image.m_data);
  std::swap(m_spec, image.m_spec);
}

bool image::export_to_png(const std::string& filename) const {
  if (!is_rgba8888()) return to_rgba8888().export_to_png(filename);
  return stbi_write_png(
    filename.c_str(),
    m_spec.width,
    m_spec.height,
    m_spec.bits_per_pixel / 8,
    data(),
    m_spec.bytes_per_row);
}

bool image::export_to_png(std::vector<uint8_t> &output) const {
  if (!is_rgba8888()) return to_rgba8888().export_to_png(output);
  return stbi_write_png_to_func(
    [](void *context, void *data_, int size) {
      uint8_t * data = reinterpret_cast<uint8_t*>(data_);
      std::vector<uint8_t> *output = reinterpret_cast<std::vector<uint8_t>*>(context);
      output->insert(output->end(), data, data + size);
    },
    &output,
    m_spec.width,
    m_spec.height,
    m_spec.bits_per_pixel / 8,
    data(),
    m_spec.bytes_per_row);
}

bool image::import_from_png(const uint8_t *data, size_t size) {
  int w, h, bpp;
  stbi_uc *pixels = stbi_load_from_memory(data, size, &w, &h, &bpp, 4);
  if (!pixels) return false;
  if (bpp != 4) {
    stbi_image_free(pixels);
    return false;
  }

  reset();

  m_spec.width = w;
  m_spec.height = h;
  m_spec.bits_per_pixel = 32;
  m_spec.bytes_per_row = w * 4;
  m_spec.red_mask = 0xff;
  m_spec.green_mask = 0xff00;
  m_spec.blue_mask = 0xff0000;
  m_spec.alpha_mask = 0xff000000;
  m_spec.red_shift = 0;
  m_spec.green_shift = 8;
  m_spec.blue_shift = 16;
  m_spec.alpha_shift = 24;

  m_own_data = true;
  m_data = new char[m_spec.bytes_per_row*m_spec.height];
  std::copy(pixels,
            pixels+m_spec.bytes_per_row*m_spec.height,
            m_data);

  stbi_image_free(pixels);
  return true;
}

image image::to_bgra8888() const {
  const auto& spec = m_spec;
  if (is_bgra8888()) return *this;
  clip::image_spec newspec;
  newspec.bits_per_pixel = 32;
  newspec.red_mask = 0xff0000;
  newspec.green_mask = 0xff00;
  newspec.blue_mask = 0xff;
  newspec.alpha_mask = 0xff000000;
  newspec.red_shift = 0;
  newspec.green_shift = 8;
  newspec.blue_shift = 16;
  newspec.alpha_shift = 24;
  newspec.width = spec.width;
  newspec.height = spec.height;
  newspec.bytes_per_row = newspec.width * 4;
  image ret(newspec);
  uint32_t* dst = reinterpret_cast<uint32_t*>(ret.data());
  uint32_t* src = (uint32_t*)data();
  const auto conv = [](uint32_t in, std::bitset<32> mask, uint32_t shift) -> uint8_t {
    if (mask.count() == 0) return 0xff;
    uint8_t r = (in & mask.to_ulong()) >> shift;
    if (mask.count() == 8) return r;
    double t = static_cast<double>(r);
    t /= (1 << mask.count()) - 1;
    t *= 255;
    return static_cast<uint8_t>(t);
  };
  for (int y=0; y<spec.height; ++y) {
    auto src_line_start = src;
    for (int x=0; x<spec.width; ++x) {
      uint32_t c = *src;
      *dst = (conv(c, spec.red_mask,   spec.red_shift  ) << 16) |
             (conv(c, spec.green_mask, spec.green_shift) <<  8) |
             (conv(c, spec.blue_mask,  spec.blue_shift )      ) |
             (conv(c, spec.alpha_mask, spec.alpha_shift) << 24);
      ++dst;
      ++src;
    }
    src = (uint32_t*)(((uint8_t*)src_line_start) + spec.bytes_per_row);
  }
  return ret;
}

image image::to_rgba8888() const {
  const auto& spec = m_spec;
  if (is_rgba8888()) return *this;
  clip::image_spec newspec;
  newspec.bits_per_pixel = 32;
  newspec.red_mask = 0xff;
  newspec.green_mask = 0xff00;
  newspec.blue_mask = 0xff0000;
  newspec.alpha_mask = 0xff000000;
  newspec.red_shift = 0;
  newspec.green_shift = 8;
  newspec.blue_shift = 16;
  newspec.alpha_shift = 24;
  newspec.width = spec.width;
  newspec.height = spec.height;
  newspec.bytes_per_row = newspec.width * 4;
  image ret(newspec);
  uint32_t* dst = reinterpret_cast<uint32_t*>(ret.data());
  uint32_t* src = (uint32_t*)data();
  const auto conv = [](uint32_t in, std::bitset<32> mask, uint32_t shift) -> uint8_t {
    if (mask.count() == 0) return 0xff;
    uint8_t r = (in & mask.to_ulong()) >> shift;
    if (mask.count() == 8) return r;
    double t = static_cast<double>(r);
    t /= (1 << mask.count()) - 1;
    t *= 255;
    return static_cast<uint8_t>(t);
  };
  for (int y=0; y<spec.height; ++y) {
    auto src_line_start = src;
    for (int x=0; x<spec.width; ++x) {
      uint32_t c = *src;
      *dst = (conv(c, spec.red_mask,   spec.red_shift  )      ) |
             (conv(c, spec.green_mask, spec.green_shift) <<  8) |
             (conv(c, spec.blue_mask,  spec.blue_shift ) << 16) |
             (conv(c, spec.alpha_mask, spec.alpha_shift) << 24);
      ++dst;
      ++src;
    }
    src = (uint32_t*)(((uint8_t*)src_line_start) + spec.bytes_per_row);
  }
  return ret;
}
} // namespace clip
