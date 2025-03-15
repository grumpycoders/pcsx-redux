/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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

#include <stdint.h>

#include "common/util/bitfield.hh"

namespace Utilities {

/**
 * @brief A class that manages a buffer of data.
 *
 * @details The Buffer class is a template class that manages a buffer of data
 * of type T. It behaves similarly to a std::vector, providing the same kind of
 * accessors, with some key differences: when resizing the buffer, it will use
 * C's realloc() function to resize the buffer, with the guarantee that the data
 * is not moved if the size is the same or less, as POSIX realloc does. Also, the
 * buffer can be created from an external pointer, in which case the buffer will
 * consider the data to be external and will not try to free or reallocate it.
 * This is useful for when the data is for instance a static array or a pointer
 * allocated by a different allocator.
 *
 * @tparam T The type of the data in the buffer.
 * @tparam Allocator The allocator to use for allocating, deallocating,
 * reallocating and copying the data. The allocator must provide the
 * following functions:
 * - allocate(size_t size): Allocates a buffer of size bytes and returns
 *  a pointer to the buffer.
 * - deallocate(void* data): Deallocates the buffer pointed to by data.
 * - reallocate(void* data, size_t size): Reallocates the buffer pointed to by
 * data to size bytes and returns a pointer to the buffer. The behavior needs
 * to be the same as realloc() in C, meaning that if the size is the same or
 * less, the data is not moved. If the size is greater, the data may be moved
 * to a new location. If the size is 0, the data is deallocated and a null
 * pointer is returned.
 * - copy(void* dest, const void* src, size_t size): Copies size bytes from
 * src to dest. The behavior needs to be the same as memcpy() in C.
 */
template <typename T, class Allocator>
class Buffer {
    typedef BitSpan<uint32_t, 24> SizeField;
    typedef BitSpan<bool> IsExternalField;
    typedef BitField<SizeField, IsExternalField> Size;

  public:
    Buffer() { m_size.clear(); }
    Buffer(size_t size) {
        m_size.clear();
        resize(size);
    }
    Buffer(T* data, size_t size) {
        m_data = data;
        m_size.set<SizeField>(size);
        m_size.set<IsExternalField>(true);
    }
    Buffer(const Buffer& other) {
        uint32_t size = other.m_size.get<SizeField>();
        m_size.set<SizeField>(size);
        m_size.set<IsExternalField>(false);
        m_data = Allocator::template allocate<T>(size);
        Allocator::copy(m_data, other.m_data, size);
    }
    Buffer(Buffer&& other) noexcept : m_data(other.m_data), m_size(other.m_size) {
        other.m_data = nullptr;
        other.m_size.clear();
    }
    ~Buffer() {
        if (!m_size.get<IsExternalField>()) {
            Allocator::deallocate(m_data);
        }
    }

    Buffer& operator=(const Buffer& other) {
        if (this != &other) {
            uint32_t size = other.m_size.get<SizeField>();
            if (m_size.get<IsExternalField>()) {
                m_data = Allocator::template allocate<T>(size);
            } else {
                m_data = Allocator::template reallocate<T>(m_data, size);
            }
            Allocator::copy(m_data, other.m_data, size);
            m_size.set<SizeField>(size);
            m_size.set<IsExternalField>(false);
        }
        return *this;
    }
    Buffer& operator=(Buffer&& other) noexcept {
        if (this != &other) {
            if (!m_size.get<IsExternalField>()) {
                Allocator::deallocate(m_data);
            }
            m_data = other.m_data;
            m_size = other.m_size;
            other.m_data = nullptr;
            other.m_size.clear();
        }
        return *this;
    }

    void clear() {
        if (!m_size.get<IsExternalField>()) {
            Allocator::deallocate(m_data);
        }
        m_data = nullptr;
        m_size.clear();
    }

    void resize(size_t size) {
        if (!m_size.get<IsExternalField>()) {
            m_data = Allocator::template reallocate<T>(m_data, size);
        }
        m_size.set<SizeField>(size);
    }

    T* data() { return m_data; }
    const T* data() const { return m_data; }
    size_t size() const { return m_size.get<SizeField>(); }
    T& operator[](size_t index) { return m_data[index]; }
    const T& operator[](size_t index) const { return m_data[index]; }
    T* begin() { return m_data; }
    T* end() { return m_data + m_size.get<SizeField>(); }
    const T* begin() const { return m_data; }
    const T* end() const { return m_data + m_size.get<SizeField>(); }
    bool empty() const { return size() == 0; }

  private:
    T* m_data = nullptr;
    Size m_size;
};

}  // namespace Utilities
