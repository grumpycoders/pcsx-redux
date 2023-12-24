/*

MIT License

Copyright (c) 2023 PCSX-Redux authors

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

#include <EASTL/string_view.h>
#include <EASTL/vector.h>
#include <stdint.h>

#include "psyqo/gpu.hh"
#include "psyqo/iso9660-parser.hh"
#include "psyqo/task.hh"

namespace psyqo::paths {

/**
 * @brief A class that reads files from the CDRom.
 *
 * @details This class provides a PSYQo path to read files from the CDRom.
 * The way to use it is to instantiate the class somewhere persistent, and
 * then call readFile() with a callback. The callback will be called with
 * the data of the file, or an empty vector if the file could not be read.
 * This is going to allocate memory in different places. Only one file can
 * be read at a time, but it is safe to call readFile() again from the
 * callback.
 */

class CDRomLoader {
  public:
    /**
     * @brief Reads a file from the CDRom.
     *
     * @param path The path to the file to read. The view must be persistent
     * until the callback is called.
     * @param gpu The GPU class used by the application, in order to set timers.
     * @param parser The ISO9660Parser to use for reading the file.
     * @param callback The callback to call when the file is read. The callback
     * will be called with the data of the file, or an empty vector if the file
     * could not be read.
     */
    void readFile(eastl::string_view path, GPU& gpu, ISO9660Parser& parser,
                  eastl::function<void(eastl::vector<uint8_t>&&)>&& callback) {
        setupQueue(path, gpu, parser, eastl::move(callback));
        m_queue.run();
    }

  private:
    void setupQueue(eastl::string_view path, GPU& gpu, ISO9660Parser& parser,
                    eastl::function<void(eastl::vector<uint8_t>&&)>&& callback);
    eastl::function<void(eastl::vector<uint8_t>&&)> m_callback;
    psyqo::TaskQueue m_queue;
    ISO9660Parser::ReadRequest m_request;
    eastl::vector<uint8_t> m_data;
    bool m_pending = false;
};

}  // namespace psyqo::paths
