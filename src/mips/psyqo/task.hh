/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

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

#include <EASTL/fixed_vector.h>
#include <EASTL/functional.h>


namespace psyqo {

class TaskQueue;

class TaskQueue {
  public:
    class Task;
    TaskQueue &run(Task &&);
    TaskQueue &run(eastl::function<void(Task *)> && fun) { return run(Task(eastl::move(fun))); }
    TaskQueue &then(Task &&);
    TaskQueue &then(eastl::function<void(Task *)> && fun) { return then(Task(eastl::move(fun))); }
    TaskQueue &butCatch(eastl::function<void(TaskQueue *)> &&);
    TaskQueue &finally(eastl::function<void(TaskQueue *)> &&);
    void rerun();

    class Task {
      public:
        Task(eastl::function<void(Task *)> &&fun) : m_runner(eastl::move(fun)) {}
        Task(Task &&) = default;
        Task(const Task &) = delete;
        Task &operator=(Task &&) = default;
        Task &operator=(const Task &) = delete;
        void resolve() { m_taskQueue->runNext(); }
        void reject() { m_taskQueue->runCatch(); }

      private:
        eastl::function<void(Task *)> m_runner;
        TaskQueue *m_taskQueue;
        friend class TaskQueue;
    };

  private:
    void runNext();
    void runCatch();

    eastl::fixed_vector<Task, 16> m_queue;
    eastl::function<void(TaskQueue *)> m_catch;
    eastl::function<void(TaskQueue *)> m_finally;
    unsigned m_index = 0;
    friend class Task;
};

}  // namespace psyqo
