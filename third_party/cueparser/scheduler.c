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

#include "cueparser/scheduler.h"

#include <stdlib.h>

#ifndef CUSTOM_SCHEDULER
int Scheduler_hasPendingEvents(struct CueScheduler *scheduler) { return 0; }
void Scheduler_processEvents(struct CueScheduler *scheduler) {}
#endif

void Scheduler_construct(struct CueScheduler *scheduler) { scheduler->top = NULL; }

void Scheduler_schedule(struct CueScheduler *scheduler, struct CueClosure *closure) {
    closure->scheduler = scheduler;
    closure->next = scheduler->top;
    scheduler->top = closure;
}

void Scheduler_run(struct CueScheduler *scheduler) {
    while (scheduler->top || Scheduler_hasPendingEvents(scheduler)) {
        Scheduler_run_once(scheduler);
        Scheduler_processEvents(scheduler);
    }
}

void Scheduler_run_once(struct CueScheduler *scheduler) {
    struct CueClosure *closure = scheduler->top;
    scheduler->top = NULL;
    while (closure) {
        struct CueClosure *next = closure->next;
        closure->call(closure);
        closure->destroy(closure);
        closure = next;
    }
}

void Scheduler_run_one(struct CueScheduler *scheduler) {
    struct CueClosure *closure = scheduler->top;
    scheduler->top = closure->next;
    closure->call(closure);
    closure->destroy(closure);
}
