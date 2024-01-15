/*

MIT License

Copyright (c) 2020 PCSX-Redux authors

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

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <limits>
#include <string>
#include <string_view>
#include <variant>

#include "fmt/format.h"

namespace PCSX {

class Slice {
  public:
    Slice() {}
    template <size_t L>
    Slice(const char (&data)[L]) {
        borrow(data, L - 1);
    }
    Slice(const Slice &other) { copyFrom(other); }
    Slice(Slice &&other) noexcept { moveFrom(std::move(other)); }
    Slice(const std::string &str) { m_data = str; }
    Slice(std::string &&str) { m_data = std::move(str); }
    std::string asString() const {
        if (std::holds_alternative<std::string>(m_data)) {
            return std::get<std::string>(m_data);
        }
        return {static_cast<const char *>(data()), size()};
    }
    Slice &operator=(const Slice &other) {
        copyFrom(other);
        return *this;
    }
    Slice &operator=(Slice &&other) noexcept {
        moveFrom(std::move(other));
        return *this;
    }
    Slice &operator+=(const Slice &other) {
        concatenate(other);
        return *this;
    }
    void concatenate(const Slice &other) {
        auto newSize = size() + other.size();
        if (m_data.index() == 0) {
            copy(other.data(), other.size());
        } else if (std::holds_alternative<Owned>(m_data)) {
            auto &data = std::get<Owned>(m_data);
            data.ptr = realloc(data.ptr, newSize);
            memcpy(((uint8_t *)data.ptr) + size(), other.data(), other.size());
            data.size += other.size();
        } else if (std::holds_alternative<std::string>(m_data)) {
            auto &data = std::get<std::string>(m_data);
            auto oldSize = data.size();
            data.resize(newSize);
            memcpy(((uint8_t *)data.data()) + oldSize, other.data(), other.size());
        } else {
            uint8_t *newData = (uint8_t *)malloc(newSize);
            memcpy(newData, data(), size());
            memcpy(newData + size(), other.data(), other.size());
            acquire(newData, newSize);
        }
    }
    void resize(uint32_t newSize) {
        if (m_data.index() == 0) {
            m_data = Owned{newSize, malloc(newSize)};
        } else if (std::holds_alternative<Owned>(m_data)) {
            auto &data = std::get<Owned>(m_data);
            data.ptr = realloc(data.ptr, newSize);
            data.size = newSize;
        } else if (std::holds_alternative<std::string>(m_data)) {
            auto &data = std::get<std::string>(m_data);
            data.resize(newSize);
        } else {
            uint8_t *newData = (uint8_t *)malloc(newSize);
            memcpy(newData, data(), std::min(size(), newSize));
            acquire(newData, newSize);
        }
    }
    void copy(const Slice &other) {
        if (std::holds_alternative<std::string>(other.m_data)) {
            m_data = other.m_data;
        } else {
            copy(other.data(), other.size());
        }
    }
    void copy(const std::string &str) { m_data = str; }
    void copy(const void *data, uint32_t size) {
        void *dest;
        if (size <= INLINED_SIZE) {
            m_data = Inlined{size};
            dest = std::get<Inlined>(m_data).inlined;
        } else {
            m_data.emplace<Owned>(size, malloc(size));
            dest = std::get<Owned>(m_data).ptr;
        }
        memcpy(dest, data, size);
    }
    void acquire(std::string &&str) { m_data = std::move(str); }
    void acquire(void *data, uint32_t size) { m_data = Owned{size, data}; }
    void borrow(const Slice &other, uint32_t from = 0, uint32_t amount = std::numeric_limits<uint32_t>::max()) {
        const uint8_t *ptr = static_cast<const uint8_t *>(other.data());
        uint32_t size = other.size();
        if (from >= size) {
            m_data = std::monostate();
            return;
        }
        ptr += from;
        size -= from;
        borrow(ptr, std::min(amount, size));
    }
    template <size_t L>
    void borrow(const char (&data)[L]) {
        m_data = Borrowed{L - 1, data};
    }
    void borrow(const void *data, uint32_t size) { m_data = Borrowed{size, data}; }
    template <typename T = void>
    const T *data() const {
        const void *ret = nullptr;
        if (std::holds_alternative<std::string>(m_data)) {
            ret = std::get<std::string>(m_data).data();
        } else if (std::holds_alternative<Inlined>(m_data)) {
            ret = std::get<Inlined>(m_data).inlined;
        } else if (std::holds_alternative<Owned>(m_data)) {
            ret = std::get<Owned>(m_data).ptr;
        } else if (std::holds_alternative<Borrowed>(m_data)) {
            ret = std::get<Borrowed>(m_data).ptr;
        }
        return static_cast<const T *>(ret);
    }
    template <typename T = void>
    T *mutableData() {
        void *ret = nullptr;
        if (std::holds_alternative<std::string>(m_data)) {
            ret = std::get<std::string>(m_data).data();
        } else if (std::holds_alternative<Inlined>(m_data)) {
            ret = std::get<Inlined>(m_data).inlined;
        } else if (std::holds_alternative<Owned>(m_data)) {
            ret = std::get<Owned>(m_data).ptr;
        } else if (std::holds_alternative<Borrowed>(m_data)) {
            throw std::runtime_error("Cannot modify borrowed data");
        }
        return static_cast<T *>(ret);
    }
    const uint32_t size() const {
        if (std::holds_alternative<std::string>(m_data)) {
            return uint32_t(std::get<std::string>(m_data).size());
        } else if (std::holds_alternative<Inlined>(m_data)) {
            return std::get<Inlined>(m_data).size;
        } else if (std::holds_alternative<Owned>(m_data)) {
            return std::get<Owned>(m_data).size;
        } else if (std::holds_alternative<Borrowed>(m_data)) {
            return std::get<Borrowed>(m_data).size;
        }
        return 0;
    }
    std::string toHexString() const {
        const uint8_t *buf = (const uint8_t *)data();
        std::string ret;
        for (unsigned lineOffset = 0; lineOffset < size(); lineOffset += 16) {
            ret += fmt::format("{:06x}: ", lineOffset);
            for (unsigned offset = 0; offset < 16; offset++) {
                if (lineOffset + offset < size()) {
                    ret += fmt::format("{:02x} ", buf[lineOffset + offset]);
                } else {
                    ret += "   ";
                }
            }
            ret += " ";
            for (unsigned offset = 0; offset < 16; offset++) {
                if (lineOffset + offset < size()) {
                    ret += fmt::format("{}", isprint(buf[lineOffset + offset]) ? (char)buf[lineOffset + offset] : '.');
                }
            }
            ret += "\n";
        }
        return ret;
    }

    uint8_t getByte(size_t offset) const {
        if (offset >= size()) throw std::runtime_error("getByte called with an out of range offset");
        return reinterpret_cast<const uint8_t *>(data())[offset];
    }

    void reset() { m_data = std::monostate(); }

    std::string_view asStringView() const { return {data<char>(), size()}; }

  private:
    void copyFrom(const Slice &other) {
        if (std::holds_alternative<Owned>(other.m_data)) {
            copy(other.data(), other.size());
        } else {
            m_data = other.m_data;
        }
    }
    void moveFrom(Slice &&other) {
        m_data = std::move(other.m_data);
        if (std::holds_alternative<Owned>(other.m_data)) {
            std::get<Owned>(other.m_data).ptr = nullptr;
        }
        other.m_data = std::monostate();
    }
    static constexpr size_t INLINED_SIZE = 28;
    struct Inlined {
        uint32_t size;
        uint8_t inlined[INLINED_SIZE];
    };
    struct Owned {
        ~Owned() { free(ptr); }
        Owned(uint32_t size, void *ptr) : size(size), ptr(ptr) {}
        Owned(const Owned &other) { abort(); }
        Owned(Owned &&other) : size(other.size), ptr(other.ptr) { other.ptr = nullptr; }
        Owned &operator=(const Owned &other) {
            abort();
            return *this;
        }
        Owned &operator=(Owned &&other) {
            if (ptr) free(ptr);
            ptr = other.ptr;
            size = other.size;
            other.ptr = nullptr;
            return *this;
        }
        uint32_t size;
        void *ptr;
    };
    struct Borrowed {
        uint32_t size;
        const void *ptr;
    };
    std::variant<std::monostate, std::string, Inlined, Owned, Borrowed> m_data;
};

}  // namespace PCSX
