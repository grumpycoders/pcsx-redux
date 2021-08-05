/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

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

#include <string_view>

extern "C" {
#include "common/syscalls/syscalls.h"
}

class Hello {
  public:
    Hello() {}
    // Using the default virtual destructor will try to use
    // the delete operator, which will try and use free().
    // See the cxxglue.c file for more information.
    virtual ~Hello() = default;
    void print();

  private:
    virtual std::string_view getName() = 0;
};

class HelloWorld : public Hello {
    virtual std::string_view getName() final override;
};

void Hello::print() {
    auto name = getName();
    ramsyscall_printf("Hello %s!\n", name.data());
}

std::string_view HelloWorld::getName() { return "World"; }

int main() {
    HelloWorld hw;
    hw.print();
    while (1)
        ;
}
