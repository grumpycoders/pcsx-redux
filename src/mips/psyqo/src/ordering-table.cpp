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

#include "psyqo/ordering-table.hh"

#include <EASTL/algorithm.h>

void psyqo::OrderingTableBase::clear(uint32_t* table, size_t size) {
    table[0] = 0xffffff;
    for (size_t i = 1; i <= size; i++) {
        table[i] = reinterpret_cast<uint32_t>(&table[i - 1]) & 0xffffff;
    }
}

void psyqo::OrderingTableBase::insert(uint32_t* table, int32_t size, uint32_t* head, uint32_t shiftedFragmentSize, int32_t z) {
    z = eastl::clamp(z, int32_t(0), size) + 1;
    *head = shiftedFragmentSize | table[z];
    table[z] = reinterpret_cast<uint32_t>(head) & 0xffffff;
}
