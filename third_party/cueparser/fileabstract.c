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

#include "cueparser/fileabstract.h"

#include <stdint.h>
#include <stdlib.h>

#include "cueparser/scheduler.h"

static void closure_generic_free(struct CueClosure *closure) { free(closure); }

struct close_Closure {
    struct CueScheduler *scheduler;
    void (*destroy)(struct CueClosure *);
    void (*call)(struct CueClosure *);
    struct CueClosure *next;
    struct CueFile *file;
    void (*cb)(struct CueFile *, struct CueScheduler *);
};

static void close_closure_call(struct CueClosure *closure_) {
    struct close_Closure *closure = (struct close_Closure *)closure_;
    closure->cb(closure->file, closure->scheduler);
}

void File_schedule_close(struct CueFile *file, struct CueScheduler *scheduler,
                         void (*cb)(struct CueFile *, struct CueScheduler *)) {
    struct close_Closure *closure = malloc(sizeof(struct close_Closure));
    closure->destroy = closure_generic_free;
    closure->call = close_closure_call;
    closure->file = file;
    closure->cb = cb;
    Scheduler_schedule(scheduler, (struct CueClosure *)closure);
}

struct size_Closure {
    struct CueScheduler *scheduler;
    void (*destroy)(struct CueClosure *);
    void (*call)(struct CueClosure *);
    struct CueClosure *next;
    struct CueFile *file;
    uint64_t size;
    void (*cb)(struct CueFile *, struct CueScheduler *, uint64_t);
};

static void size_closure_call(struct CueClosure *closure_) {
    struct size_Closure *closure = (struct size_Closure *)closure_;
    closure->cb(closure->file, closure->scheduler, closure->size);
}

void File_schedule_size(struct CueFile *file, struct CueScheduler *scheduler, uint64_t size,
                        void (*cb)(struct CueFile *, struct CueScheduler *, uint64_t)) {
    struct size_Closure *closure = malloc(sizeof(struct size_Closure));
    closure->destroy = closure_generic_free;
    closure->call = size_closure_call;
    closure->file = file;
    closure->size = size;
    closure->cb = cb;
    Scheduler_schedule(scheduler, (struct CueClosure *)closure);
}

struct read_Closure {
    struct CueScheduler *scheduler;
    void (*destroy)(struct CueClosure *);
    void (*call)(struct CueClosure *);
    struct CueClosure *next;
    struct CueFile *file;
    int error;
    uint32_t amount;
    uint8_t *buffer;
    void (*cb)(struct CueFile *, struct CueScheduler *, int error, uint32_t amount, uint8_t *buffer);
};
static void read_closure_call(struct CueClosure *closure_) {
    struct read_Closure *closure = (struct read_Closure *)closure_;
    closure->cb(closure->file, closure->scheduler, closure->error, closure->amount, closure->buffer);
}

void File_schedule_read(struct CueFile *file, struct CueScheduler *scheduler, int error, uint32_t amount,
                        uint8_t *buffer,
                        void (*cb)(struct CueFile *, struct CueScheduler *, int error, uint32_t amount,
                                   uint8_t *buffer)) {
    struct read_Closure *closure = malloc(sizeof(struct read_Closure));
    closure->destroy = closure_generic_free;
    closure->call = read_closure_call;
    closure->file = file;
    closure->error = error;
    closure->amount = amount;
    closure->buffer = buffer;
    closure->cb = cb;
    Scheduler_schedule(scheduler, (struct CueClosure *)closure);
}

struct write_Closure {
    struct CueScheduler *scheduler;
    void (*destroy)(struct CueClosure *);
    void (*call)(struct CueClosure *);
    struct CueClosure *next;
    struct CueFile *file;
    int error;
    uint32_t amount;
    void (*cb)(struct CueFile *, struct CueScheduler *, int error, uint32_t amount);
};

static void write_closure_call(struct CueClosure *closure_) {
    struct write_Closure *closure = (struct write_Closure *)closure_;
    closure->cb(closure->file, closure->scheduler, closure->error, closure->amount);
}

void File_schedule_write(struct CueFile *file, struct CueScheduler *scheduler, int error, uint32_t amount,
                         void (*cb)(struct CueFile *, struct CueScheduler *, int error, uint32_t amount)) {
    struct write_Closure *closure = malloc(sizeof(struct write_Closure));
    closure->destroy = closure_generic_free;
    closure->call = write_closure_call;
    closure->file = file;
    closure->error = error;
    closure->amount = amount;
    closure->cb = cb;
    Scheduler_schedule(scheduler, (struct CueClosure *)closure);
}
