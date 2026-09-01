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

#include <stdint.h>

namespace psyqo::Hardware {

enum class WriteQueue {
    Use = true,
    Bypass = false,
};

template <uint32_t offset, uint32_t BaseAddress, typename T>
struct BasicAccess {
    static volatile T& access(int index = 0) { return *reinterpret_cast<volatile T*>(BaseAddress + offset + index); }
    static volatile T* accessPtr(int index = 0) { return reinterpret_cast<volatile T*>(BaseAddress + offset + index); }
};

template <uint32_t offset, typename T = uint32_t, WriteQueue writeQueue = WriteQueue::Use,
          typename Access = BasicAccess<offset, writeQueue == WriteQueue::Use ? 0x1f801000 : 0xbf801000, T>>
struct Register {
    static constexpr uint32_t BaseAddress = writeQueue == WriteQueue::Use ? 0x1f801000 : 0xbf801000;
    void throwAway() const { *Access::accessPtr(); }
    operator T() const { return access(); }
    T operator=(T value) const {
        access() = value;
        return value;
    }
    T operator|=(T value) const {
        T tmp = access();
        tmp |= value;
        access() = tmp;
        return tmp;
    }
    T operator&=(T value) const {
        T tmp = access();
        tmp &= value;
        access() = tmp;
        return tmp;
    }
    T operator^=(T value) const {
        T tmp = access();
        tmp ^= value;
        access() = tmp;
        return tmp;
    }
    T operator++() const {
        T tmp = access();
        tmp++;
        access() = tmp;
        return tmp;
    }
    T operator++(int) const {
        T tmp = access();
        T ret = tmp;
        tmp++;
        access() = tmp;
        return ret;
    }
    T operator--() const {
        T tmp = access();
        tmp--;
        access() = tmp;
        return tmp;
    }
    T operator--(int) const {
        T tmp = access();
        T ret = tmp;
        tmp--;
        access() = tmp;
        return ret;
    }
    T operator+=(T value) const {
        T tmp = access();
        tmp += value;
        access() = tmp;
        return tmp;
    }
    T operator-=(T value) const {
        T tmp = access();
        tmp -= value;
        access() = tmp;
        return tmp;
    }
    T operator*=(T value) const {
        T tmp = access();
        tmp *= value;
        access() = tmp;
        return tmp;
    }
    T operator/=(T value) const {
        T tmp = access();
        tmp /= value;
        access() = tmp;
        return tmp;
    }
    T operator%=(T value) const {
        T tmp = access();
        tmp %= value;
        access() = tmp;
        return tmp;
    }
    T operator<<=(T value) const {
        T tmp = access();
        tmp <<= value;
        access() = tmp;
        return tmp;
    }
    T operator>>=(T value) const {
        T tmp = access();
        tmp >>= value;
        access() = tmp;
        return tmp;
    }
    T operator+(T value) const { return access() + value; }
    T operator-(T value) const { return access() - value; }
    T operator*(T value) const { return access() * value; }
    T operator/(T value) const { return access() / value; }
    T operator%(T value) const { return access() % value; }
    T operator<<(T value) const { return access() << value; }
    T operator>>(T value) const { return access() >> value; }
    T operator&(T value) const { return access() & value; }
    T operator|(T value) const { return access() | value; }
    T operator^(T value) const { return access() ^ value; }
    T operator~() const { return ~access(); }
    T operator!() const { return !access(); }
    T operator&&(T value) const { return access() && value; }
    T operator||(T value) const { return access() || value; }
    bool operator==(T value) const { return access() == value; }
    bool operator!=(T value) const { return access() != value; }
    bool operator<(T value) const { return access() < value; }
    bool operator>(T value) const { return access() > value; }
    bool operator<=(T value) const { return access() <= value; }
    bool operator>=(T value) const { return access() >= value; }
    T operator[](int index) const { return access(index); }

    volatile T& access(int index = 0) const { return Access::access(index); }
};

}  // namespace psyqo::Hardware
