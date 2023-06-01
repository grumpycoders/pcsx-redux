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

#include "psyqo-paths/cdrom-loader.hh"

#include "psyqo/kernel.hh"

void psyqo::paths::CDRomLoader::setupQueue(eastl::string_view path, GPU& gpu, psyqo::ISO9660Parser& parser,
                                        eastl::function<void(eastl::vector<uint8_t>&&)>&& callback) {
    Kernel::assert(!m_pending, "Only one file can be read at a time");
    m_pending = true;
    m_callback = eastl::move(callback);
    m_queue.startWith([](auto task) { task->resolve(); });
    if (!parser.initialized()) {
        m_queue.then(parser.scheduleInitialize());
    }
    m_queue.then(parser.scheduleGetDirentry(path, &m_request.entry))
        .then([this](auto task) {
            uint32_t size = (m_request.entry.size + 2047) & ~2048;
            m_data.resize(size);
            m_request.buffer = m_data.data();
            task->resolve();
        })
        .then(parser.scheduleReadRequest(&m_request))
        .butCatch([this](auto task) {
            m_request.entry.size = 0;
        })
        .finally([this](auto task) {
            m_pending = false;
            m_data.resize(m_request.entry.size);
            m_callback(eastl::move(m_data));
            m_callback = nullptr;
        });
}
