// Clip Library - wasm/emscripten backend
// Copyright (c) 2026 David Capello
//
// This source file is distributed under MIT license,
// please read LICENSE.txt for more information.

// A browser has no synchronous clipboard: the Async Clipboard API cannot be
// read from inside a blocking call, and clip's interface is synchronous
// throughout. So this backend is a process-local clipboard - copy and paste
// work within the application, and nothing crosses to the host.
//
// That is deliberately NOT a silent no-op. It does exactly what it claims for
// every operation the app performs on itself; what is missing is host
// integration, which needs an async path clip does not have. Extending this
// file with an emscripten_run_script bridge for set_data is the obvious next
// step if one-way copy-to-host is wanted.

#ifdef __EMSCRIPTEN__

#include <map>
#include <string>
#include <vector>

#include "clip.h"
#include "clip_lock_impl.h"

namespace clip {

namespace {

struct LocalClipboard {
  std::map<format, std::vector<char>> data;
  bool has_image = false;
  image img;
  image_spec spec;
};

LocalClipboard& board() {
  static LocalClipboard b;
  return b;
}

format g_next_custom_format = 100;
std::map<std::string, format>& custom_formats() {
  static std::map<std::string, format> m;
  return m;
}

}  // anonymous namespace

lock::impl::impl(void*) : m_locked(true) {}
lock::impl::~impl() {}

bool lock::impl::clear() {
  board().data.clear();
  board().has_image = false;
  return true;
}

bool lock::impl::is_convertible(format f) const {
  if (f == image_format()) return board().has_image;
  return board().data.find(f) != board().data.end();
}

bool lock::impl::set_data(format f, const char* buf, size_t len) {
  board().data[f].assign(buf, buf + len);
  return true;
}

bool lock::impl::get_data(format f, char* buf, size_t len) const {
  auto it = board().data.find(f);
  if (it == board().data.end()) return false;
  const size_t n = len < it->second.size() ? len : it->second.size();
  for (size_t i = 0; i < n; ++i) buf[i] = it->second[i];
  // clip's callers size the buffer from get_data_length(), which counts the
  // terminator for text, so only pad when there is room left over.
  if (n < len) buf[n] = 0;
  return true;
}

size_t lock::impl::get_data_length(format f) const {
  auto it = board().data.find(f);
  if (it == board().data.end()) return 0;
  return it->second.size();
}

bool lock::impl::set_image(const image& image) {
  board().img = image;
  board().spec = image.spec();
  board().has_image = true;
  return true;
}

bool lock::impl::get_image(image& output_img) const {
  if (!board().has_image) return false;
  output_img = board().img;
  return true;
}

bool lock::impl::get_image_spec(image_spec& spec) const {
  if (!board().has_image) return false;
  spec = board().spec;
  return true;
}

format register_format(const std::string& name) {
  auto& m = custom_formats();
  auto it = m.find(name);
  if (it != m.end()) return it->second;
  return m[name] = g_next_custom_format++;
}

}  // namespace clip

#endif
