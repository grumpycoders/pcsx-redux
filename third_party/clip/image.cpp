// Clip Library
// Copyright (c) 2015-2018 David Capello
//
// This file is released under the terms of the MIT license.
// Read LICENSE.txt for more information.

#include <stdint.h>

#include <vector>

#include "clip.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
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
  return stbi_write_png(filename.c_str(), m_spec.width, m_spec.height, m_spec.bits_per_pixel / 8, data(), m_spec.bytes_per_row);
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
  image ret(newspec);
  uint32_t* dst = reinterpret_cast<uint32_t*>(ret.data());
  uint32_t* src = (uint32_t*)data();
  for (int y=0; y<spec.height; ++y) {
    auto src_line_start = src;
    for (int x=0; x<spec.width; ++x) {
      uint32_t c = *src;
      *dst = ((((c & spec.red_mask  ) >> spec.red_shift  ) << 16) |
              (((c & spec.green_mask) >> spec.green_shift) <<  8) |
              (((c & spec.blue_mask ) >> spec.blue_shift )      ) |
              (((c & spec.alpha_mask) >> spec.alpha_shift) << 24));
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
  image ret(newspec);
  uint32_t* dst = reinterpret_cast<uint32_t*>(ret.data());
  uint32_t* src = (uint32_t*)data();
  for (int y=0; y<spec.height; ++y) {
    auto src_line_start = src;
    for (int x=0; x<spec.width; ++x) {
      uint32_t c = *src;
      *dst = ((((c & spec.red_mask  ) >> spec.red_shift  )) |
              (((c & spec.green_mask) >> spec.green_shift) <<  8) |
              (((c & spec.blue_mask ) >> spec.blue_shift ) << 16) |
              (((c & spec.alpha_mask) >> spec.alpha_shift) << 24));
      ++dst;
      ++src;
    }
    src = (uint32_t*)(((uint8_t*)src_line_start) + spec.bytes_per_row);
  }
  return ret;
}
} // namespace clip
