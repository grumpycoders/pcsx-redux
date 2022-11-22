/*

MIT License

Copyright (c) 2022 Nicolas "Pixel" Noble

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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

struct CueScheduler;

struct CueFile {
    void (*destroy)(struct CueFile *);
    void (*close)(struct CueFile *, struct CueScheduler *, void (*)(struct CueFile *, struct CueScheduler *));
    void (*size)(struct CueFile *, struct CueScheduler *, void (*)(struct CueFile *, struct CueScheduler *, uint64_t));
    void (*read)(struct CueFile *, struct CueScheduler *, uint32_t amount, uint64_t cursor, uint8_t *buffer,
                 void (*)(struct CueFile *, struct CueScheduler *, int error, uint32_t amount, uint8_t *buffer));
    void (*write)(struct CueFile *, struct CueScheduler *, uint32_t amount, uint64_t cursor, const uint8_t *buffer,
                  void (*)(struct CueFile *, struct CueScheduler *, int error, uint32_t amount));
    int references;
    const char *cfilename;
    char *filename;
    void *user;
    void *opaque;
};

void File_schedule_close(struct CueFile *, struct CueScheduler *, void (*)(struct CueFile *, struct CueScheduler *));
void File_schedule_size(struct CueFile *, struct CueScheduler *, uint64_t size,
                        void (*)(struct CueFile *, struct CueScheduler *, uint64_t));
void File_schedule_read(struct CueFile *, struct CueScheduler *, int error, uint32_t amount, uint8_t *buffer,
                        void (*)(struct CueFile *, struct CueScheduler *, int error, uint32_t amount, uint8_t *buffer));
void File_schedule_write(struct CueFile *, struct CueScheduler *, int error, uint32_t amount,
                         void (*)(struct CueFile *, struct CueScheduler *, int error, uint32_t amount));

#ifdef __cplusplus
}
#endif
