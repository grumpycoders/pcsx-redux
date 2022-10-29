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

/**
 * @brief A task queue for processing tasks sequentially.
 *
 * @details This class is used to process a sequence of tasks one after the other.
 * The design is loosely inspired by the JavaScript Promise API. A task is
 * effectively a lambda function. A queue can be run multiple times, and can also
 * be embedded within another queue.
 *
 */

class TaskQueue {
  public:
    class Task;

    /**
     * @brief Resets the queue.
     *
     * @details This method resets the queue to its initial state.
     * Calling this method while the queue is running is undefined behavior.
     */
    void reset();

    /**
     * @brief Enqueues a task for execution.
     *
     * @details This method will enqueue a task for execution, while resetting
     * the queue first. This means that any previously enqueued tasks will be
     * removed first. Any exception handler or finally handler will also be
     * cleared out. Calling this while the queue is running is undefined
     * behavior.
     *
     */
    TaskQueue &startWith(Task &&);
    TaskQueue &startWith(eastl::function<void(Task *)> &&fun) { return startWith(Task(eastl::move(fun))); }

    /**
     * @brief Enqueues a task for execution.
     *
     * @details This method will enqueue a task for execution. The task will
     * be executed after all previously enqueued tasks have been executed.
     * Calling this while the queue is running is undefined behavior.
     */
    TaskQueue &then(Task &&);
    TaskQueue &then(eastl::function<void(Task *)> &&fun) { return then(Task(eastl::move(fun))); }

    /**
     * @brief Sets the exception handler.
     *
     * @details This method will set the exception handler. The exception
     * handler will be called if any of the tasks in the queue throws an
     * exception. The exception handler will be called with the task queue
     * as its argument. Calling this while the queue is running is undefined
     * behavior.
     *
     */
    TaskQueue &butCatch(eastl::function<void(TaskQueue *)> &&);

    /**
     * @brief Sets the finally handler.
     *
     * @details This method will set the finally handler. The finally handler
     * will be called after all tasks in the queue have been executed, or
     * after the exception handler. The finally handler will be called with
     * the task queue as its argument. Calling this while the queue is running
     * is undefined behavior.
     *
     */
    TaskQueue &finally(eastl::function<void(TaskQueue *)> &&);

    /**
     * @brief Runs the task queue.
     *
     * @details This method will start running the queue. The queue will
     * continue to run until all tasks have been executed, or until an
     * exception is thrown. This method can be called multiple times, in
     * order to execute the whole queue multiple times. Calling this
     * while the queue is already running is undefined behavior.
     *
     */
    void run();

    /**
     * @brief Schedules the task queue to another task queue.
     *
     * @details This method will enable embedding the queue into another
     * one. Exceptions will be cascading.
     */
    Task schedule();

    /**
     * @brief Queries the status of the queue.
     *
     * @return true if the queue is running, false otherwise.
     */
    bool isRunning() const { return m_running; }

    /**
     * @brief The Task class.
     *
     * @details This class is the holder for a task to execute within the queue.
     * It can be constructed with a lambda, or be moved. It effectively acts
     * as a promise, but without data attached to it.
     *
     */
    class Task {
      public:
        /**
         * @brief Construct a new Task object
         *
         * @param fun The lambda to execute for this task. It will receive the task
         * as its argument.
         */
        explicit Task(eastl::function<void(Task *)> &&fun) : m_runner(eastl::move(fun)) {}
        Task(Task &&) = default;
        Task(const Task &) = delete;
        Task &operator=(Task &&) = default;
        Task &operator=(const Task &) = delete;

        /**
         * @brief Resolves this task.
         *
         * @details This method is to be called by the task's lambda function to
         * resolve the task. It will continue to the next task in the queue, or
         * call the finally handler if there are no more tasks.
         *
         */
        void resolve() { m_taskQueue->runNext(); }

        /**
         * @brief Rejects this task.
         *
         * @details This method is to be called by the task's lambda function to
         * reject the task. It will call the exception handler, and then the
         * finally handler.
         *
         */
        void reject() { m_taskQueue->runCatch(); }

        /**
         * @brief Resolves or rejects this task.
         *
         * @details This method is to be called by the task's lambda function to
         * resolve or reject the task. It is a convenience method that will
         * either call resolve() or reject() depending on the value of the
         * first argument.
         *
         */
        void complete(bool success) {
            if (success) {
                resolve();
            } else {
                reject();
            }
        }

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
    Task *m_parent = nullptr;
    unsigned m_index = 0;
    bool m_running = false;
    friend class Task;
};

}  // namespace psyqo
