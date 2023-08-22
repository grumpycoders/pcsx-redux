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

#include "psyqo/application.hh"

namespace psyqo {

class GPU;

/**
 * @brief The Scene class.
 *
 * @details This class is the base class for all scenes. Rendering is supposed
 * to be done by the scenes. Only one scene can be active at a time. There is
 * a helper stack system for managing the scenes. See the `Application` class
 * for more information.
 */
class Scene {
  public:
    enum class StartReason { Create, Resume };
    /**
     * @brief Starts the scene.
     *
     * @details This method will be called when the scene is started. It is
     * meant to set the environment in a suitable manner. A scene starts when
     * it becomes the active scene, either when being pushed or when the
     * previous scene is popped. The argument will indicate whether the scene
     * is started because it just got pushed, or because another one is getting
     * popped.
     * @param reason The reason why the scene is started. Create or Resume.
     */
    virtual void start(StartReason reason) {}

    /**
     * @brief Renders a frame.
     *
     * @details This method will be called when the scene is active, every time
     * a new frame is to be rendered.
     */
    virtual void frame() {}

    enum class TearDownReason { Destroy, Pause };
    /**
     * @brief Tears down the scene.
     *
     * @details This method will be called when the scene is no longer the
     * active scene. It is meant to clean up the environment, basically
     * reversing the effects of `start`. The argument will indicate whether
     * the scene is being popped, or if another scene is pushed on the stack.
     * @param reason The reason why the scene is being torn down. DESTROY or PAUSE.
     */
    virtual void teardown(TearDownReason reason) {}

    virtual ~Scene() = default;

  protected:
    /**
     * @brief Alias for `Application::pushScene`.
     */
    void pushScene(Scene* scene) { m_parent->pushScene(scene); }

    /**
     * @brief Alias for `Application::popScene`.
     */
    Scene* popScene() { return m_parent->popScene(); }

    /**
     * @brief Alias for `Application::gpu()`.
     */
    psyqo::GPU& gpu() { return m_parent->gpu(); }

  private:
    Application* m_parent;

    friend class Application;
};

}  // namespace psyqo
