// Copyright (c) 2013 Austin T. Clements. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

#include <stdio.h>
#include <stdlib.h>

#include <system_error>

#include "elf++.hh"

using namespace std;

ELFPP_BEGIN_NAMESPACE

class file_loader : public loader {
    void *base = nullptr;
    size_t lim;

  public:
    file_loader(const std::string &fname) {
        FILE *file = fopen(fname.c_str(), "rb");
        if (!file) throw system_error(errno, system_category(), "opening file");
        fseek(file, 0, SEEK_END);
        off_t end = ftell(file);
        fseek(file, 0, SEEK_SET);
        if (end == (off_t)-1) throw system_error(errno, system_category(), "finding file length");
        lim = end;

        base = malloc(end);
        size_t r = fread(base, 1, end, file);

        if (r != end) throw system_error(errno, system_category(), "reading");
        fclose(file);
    }

    ~file_loader() { free(base); }

    const void *load(off_t offset, size_t size) {
        if (offset + size > lim) throw range_error("offset exceeds file size");
        return (const char *)base + offset;
    }
};

std::shared_ptr<loader> create_file_loader(const std::string &fname) { return make_shared<file_loader>(fname); }

ELFPP_END_NAMESPACE
