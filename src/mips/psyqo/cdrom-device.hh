/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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
#include <stdint.h>

#include <concepts>
#include <coroutine>
#include <cstdint>
#include <type_traits>

#include "psyqo/cdrom-commandbuffer.hh"
#include "psyqo/cdrom.hh"
#include "psyqo/msf.hh"
#include "psyqo/task.hh"

namespace psyqo {

class GPU;

namespace Concepts {

template <typename T, typename = void>
struct CDRomDeviceStateEnumHasIdle : std::false_type {};

template <typename T>
struct CDRomDeviceStateEnumHasIdle<T, std::enable_if_t<T::IDLE == T(0)>> : std::true_type {};

template <typename T>
concept IsCDRomDeviceStateEnum =
    std::is_enum_v<T> && std::is_same_v<uint8_t, std::underlying_type_t<T>> && CDRomDeviceStateEnumHasIdle<T>::value;

}  // namespace Concepts

/**
 * @brief A specialization of the CDRom interface.
 *
 * @details This class is a specialization of the CDRom interface, which
 * provides a way to read from the physical CDRom drive of the console.
 * All of the methods in this class are asynchronous, and will call the
 * provided callback when the operation is complete. The class also
 * provides a blocking variant for some of the methods, which can be
 * used to perform the operation synchronously. Note that the blocking
 * variants are only provided for methods that are expected to complete
 * quickly, and should not be used in performance-critical code, as they
 * can still block the system for several milliseconds. The callbacks
 * will be called from the main thread, and have a boolean parameter
 * that indicates whether the operation was successful. Last but not
 * least, the class provides a coroutine-friendly API, which allows
 * the use of the `co_await` keyword to suspend the coroutine until
 * the operation is complete.
 *
 */
class CDRomDevice final : public CDRom {
  public:
    typedef eastl::fixed_vector<uint8_t, 16, false> Response;
    struct PlaybackLocation {
        MSF relative;
        MSF absolute;
        unsigned track;
        unsigned index;
    };

    struct ResetAwaiter {
        ResetAwaiter(CDRomDevice &device) : m_device(device) {}
        bool await_ready() const { return false; }
        template <typename U>
        void await_suspend(std::coroutine_handle<U> handle) {
            m_device.reset([handle, this](bool result) {
                m_result = result;
                handle.resume();
            });
        }
        bool await_resume() { return m_result; }

      private:
        CDRomDevice &m_device;
        bool m_result;
    };

    struct GetTOCSizeAwaiter {
        GetTOCSizeAwaiter(CDRomDevice &device) : m_device(device) {}
        bool await_ready() const { return false; }
        template <typename U>
        void await_suspend(std::coroutine_handle<U> handle) {
            m_device.getTOCSize(&m_result, [handle, this](bool success) {
                m_success = success;
                handle.resume();
            });
        }
        unsigned await_resume() { return m_success ? m_result : 0; }

      private:
        CDRomDevice &m_device;
        unsigned m_result;
        bool m_success;
    };

    struct ReadTOCAwaiter {
        ReadTOCAwaiter(CDRomDevice &device, MSF *toc, unsigned size) : m_device(device), m_toc(toc), m_size(size) {}
        bool await_ready() const { return false; }
        template <typename U>
        void await_suspend(std::coroutine_handle<U> handle) {
            m_device.readTOC(m_toc, m_size, [handle, this](bool result) {
                m_result = result;
                handle.resume();
            });
        }
        bool await_resume() { return m_result; }

      private:
        CDRomDevice &m_device;
        MSF *m_toc;
        unsigned m_size;
        bool m_result;
    };

    struct MuteAwaiter {
        MuteAwaiter(CDRomDevice &device) : m_device(device) {}
        bool await_ready() const { return false; }
        template <typename U>
        void await_suspend(std::coroutine_handle<U> handle) {
            m_device.mute([handle, this](bool result) {
                m_result = result;
                handle.resume();
            });
        }
        bool await_resume() { return m_result; }

      private:
        CDRomDevice &m_device;
        bool m_result;
    };

    struct UnmuteAwaiter {
        UnmuteAwaiter(CDRomDevice &device) : m_device(device) {}
        bool await_ready() const { return false; }
        template <typename U>
        void await_suspend(std::coroutine_handle<U> handle) {
            m_device.unmute([handle, this](bool result) {
                m_result = result;
                handle.resume();
            });
        }
        bool await_resume() { return m_result; }

      private:
        CDRomDevice &m_device;
        bool m_result;
    };

    struct GetPlaybackLocationAwaiter {
        GetPlaybackLocationAwaiter(CDRomDevice &device) : m_device(device) {}
        bool await_ready() const { return false; }
        template <typename U>
        void await_suspend(std::coroutine_handle<U> handle) {
            m_device.getPlaybackLocation([handle, this](PlaybackLocation *location) {
                m_location = location;
                handle.resume();
            });
        }
        PlaybackLocation *await_resume() { return m_location; }

      private:
        CDRomDevice &m_device;
        PlaybackLocation *m_location;
    };

  private:
    struct ActionBase {
        const char *name() const { return m_name; }

      protected:
        ActionBase(const char *const name) : m_name(name) {}
        virtual ~ActionBase() = default;

        virtual bool dataReady(const Response &response);
        virtual bool complete(const Response &response);
        virtual bool acknowledge(const Response &response);
        virtual bool end(const Response &response);

        void setCallback(eastl::function<void(bool)> &&callback);
        void queueCallbackFromISR(bool success);
        void setSuccess(bool success);
        // This isn't really a great way to do this, but it's the best I can come up with
        // that doesn't involve friending a bunch of classes.
        PlaybackLocation *getPendingLocationPtr() const;
        void queueGetLocationCallback(bool success = true);

        friend class CDRomDevice;
        CDRomDevice *m_device = nullptr;
        const char *const m_name = nullptr;
    };

  public:
    virtual ~CDRomDevice();

    /**
     * @brief Prepares the CDRom subsystem.
     *
     * @details This method prepares the kernel and the system for the
     * CDRom subsystem. It should be called once from the application's
     * `prepare` method.
     *
     */
    void prepare();

    /**
     * @brief Resets the CDRom controller.
     *
     * @details This method will reset the CDRom controller. It technically
     * does not need to be called, but it is a good idea to call it when
     * the application starts, in order to ensure that the controller
     * is in a known state.
     *
     */
    void reset(eastl::function<void(bool)> &&callback);
    TaskQueue::Task scheduleReset();
    bool resetBlocking(GPU &);
    ResetAwaiter reset() { return {*this}; }

    /**
     * @brief Reads sectors from the CDRom.
     *
     * @details This method will read a number of sectors from the CDRom
     * drive. The sectors will be read into the provided buffer. Note that
     * only one read operation can be active at a time, and that the
     * `ISO9660Parser` class will call this method to read the filesystem
     * structure, so care must be taken to ensure no other read operation
     * is active when the parser is used.
     *
     * @param sector The sector to start reading from.
     * @param count The number of sectors to read.
     * @param buffer The buffer to read the sectors into.
     * @param callback The callback to call when the read is complete.
     *
     */
    void readSectors(uint32_t sector, uint32_t count, void *buffer, eastl::function<void(bool)> &&callback) override;
    bool readSectorsBlocking(uint32_t sector, uint32_t count, void *buffer, GPU &);

    /**
     * @brief Gets the size of the Table of Contents from the CDRom. Note that
     * while the blocking variant is available because it is a fairly short
     * operation with the CDRom controller, it can still block the system
     * for roughly 2ms, which is a long time in the context of a 33MHz CPU.
     *
     * @param size The pointer to store the size of the TOC.
     * @param callback The callback to call when the size is retrieved.
     */
    void getTOCSize(unsigned *size, eastl::function<void(bool)> &&callback);
    TaskQueue::Task scheduleGetTOCSize(unsigned *size);
    unsigned getTOCSizeBlocking(GPU &);
    GetTOCSizeAwaiter getTOCSize() { return {*this}; }

    /**
     * @brief Reads the Table of Contents from the CDRom.
     *
     * @details This method will read the Table of Contents from the CDRom
     * drive. The TOC will be read into the provided buffer. Note that
     * a CD-Rom can have up to 99 tracks, and the TOC will be read into the
     * provided buffer starting at index 1 for the first track. Any tracks
     * that are not present on the CD will not have their MSF structure
     * filled in, so the application should ensure that the buffer is
     * initialized to zero before calling this method. The blocking variant
     * may take a total of 200ms to complete, depending on the number of
     * tracks on the CD.
     *
     * @param toc The buffer to read the TOC into.
     * @param size The size of the buffer. Should be 100 to hold all possible tracks.
     * @param callback The callback to call when the read is complete.
     */
    void readTOC(MSF *toc, unsigned size, eastl::function<void(bool)> &&callback);
    TaskQueue::Task scheduleReadTOC(MSF *toc, unsigned size);
    bool readTOCBlocking(MSF *toc, unsigned size, GPU &);
    ReadTOCAwaiter readTOC(MSF *toc, unsigned size) { return {*this, toc, size}; }

    /**
     * @brief Mutes the CD audio for both CDDA and CDXA.
     *
     * @param callback The callback to call when the mute operation is complete.
     */
    void mute(eastl::function<void(bool)> &&callback);
    TaskQueue::Task scheduleMute();
    void muteBlocking(GPU &);
    MuteAwaiter mute() { return MuteAwaiter(*this); }

    /**
     * @brief Unmutes the CD audio for both CDDA and CDXA.
     *
     * @param callback The callback to call when the unmute operation is complete.
     */
    void unmute(eastl::function<void(bool)> &&callback);
    TaskQueue::Task scheduleUnmute();
    void unmuteBlocking(GPU &);
    UnmuteAwaiter unmute() { return {*this}; }

    /**
     * @brief Begins playing CDDA audio from a given starting point.
     *
     * @details This method will begin playing CDDA audio from a given
     * starting point. The starting point is either a track number or
     * an MSF value. Unlike other APIs here, upon success, the callback
     * will be called *twice*: once when the playback actually started,
     * and once when the playback is complete or paused, which can be
     * after the end of the track, at the end of the disc if the last
     * track is reached, or if the playback is paused or stopped using
     * the `pauseCDDA` or `stopCDDA` methods. The first callback will
     * be called with `true` if the playback started successfully,
     * and `false` if it failed. In the case of failure, the second
     * callback will not be called. The Track variant will stop playback
     * at the end of the track, while the Disc variant will stop playback
     * at the end of the disc. The resume method can be used to resume
     * playback after a pause. Its callback argument will function
     * similarly to the callback argument of the `playCDDA` methods.
     *
     * @param start The starting point for playback.
     * @param stopAtEndOfTrack If true, playback will stop at the end of the track.
     * @param callback The callback to call when playback is complete.
     */
    void playCDDATrack(MSF start, eastl::function<void(bool)> &&callback);
    void playCDDATrack(unsigned track, eastl::function<void(bool)> &&callback);
    void playCDDADisc(MSF start, eastl::function<void(bool)> &&callback);
    void playCDDADisc(unsigned track, eastl::function<void(bool)> &&callback);
    void resumeCDDA(eastl::function<void(bool)> &&callback);

    /**
     * @brief Pauses CDDA playback.
     *
     * @details This method will request a pause of the CDDA playback.
     * The callback which was provided to the `playCDDA` method will be
     * called with `true` when the playback is paused successfully.
     * This method can only be called when the CDDA playback is in
     * progress, as indicated by a first successful call of the `playCDDA`
     * callback, and will fail if not. Pausing the playback will not
     * stop the CDRom drive motor, which means that another `playCDDA`
     * call start playing faster than if the motor was stopped.
     */
    void pauseCDDA();

    /**
     * @brief Stops CDDA playback.
     *
     * @details This method will request a stop of the CDDA playback.
     * It functions similarly to the `pauseCDDA` method, but will stop
     * the CDRom drive motor, which means that another `playCDDA` call
     * will take longer to start playing than if the motor was not stopped.
     */
    void stopCDDA();

    /**
     * @brief Get the Playback location of the CDDA audio.
     *
     * @details This method will request the current playback location
     * of the CDDA audio. The callback will be called with a pointer to
     * a `PlaybackLocation` structure, which will contain the relative
     * and absolute MSF values, the current track number, and the current
     * index. The callback will be called with a null pointer if the
     * location could not be retrieved.
     *
     * @param location If provided, the location will be stored here.
     * @param callback The callback to call when the location is retrieved.
     */
    void getPlaybackLocation(PlaybackLocation *location, eastl::function<void(PlaybackLocation *)> &&callback);
    void getPlaybackLocation(eastl::function<void(PlaybackLocation *)> &&callback);
    TaskQueue::Task scheduleGetPlaybackLocation(PlaybackLocation *location);
    GetPlaybackLocationAwaiter getPlaybackLocation() { return {*this}; }

    /**
     * @brief Set the Volume of the CDDA audio.
     *
     * @details This method will set the volume of the CDDA audio. The
     * volume is set using four values, which represent the volume of
     * the left channel to the left speaker, the right channel to the
     * left speaker, the left channel to the right speaker, and the
     * right channel to the right speaker. The given output value
     * should be in the range of 0 to 128, where 0 is silence and 128
     * is full volume. The values for a given output speaker will be
     * added together, so clipping can occur if the sum of the values
     * is greater than 128. The method can be used at any time, unlike
     * the mute/unmute methods, which can only be used when the drive
     * is idle. The normal volume setting is 0x80, 0x00, 0x00, 0x80.
     *
     * @param leftToLeft The volume of the left channel to the left speaker.
     * @param rightToLeft The volume of the right channel to the left speaker.
     * @param leftToRight The volume of the left channel to the right speaker.
     * @param rightToRight The volume of the right channel to the right speaker.
     */
    void setVolume(uint8_t leftToLeft, uint8_t rightToLeft, uint8_t leftToRight, uint8_t rightToRight);

    /**
     * @brief Sends a test command to the CDRom mech
     *
     * @param callback The callback to call when the command operation is complete.
     */
    void test(CDRomCommandBuffer commandBuffer, eastl::function<void(bool)> &&callback);
    TaskQueue::Task scheduleTest(CDRomCommandBuffer commandBuffer);
    void testBlocking(GPU &, CDRomCommandBuffer commandBuffer);

    /**
     * @brief The action base class for the internal state machine.
     *
     * @details This class is meant to be extended by the various actions
     * that the CDRom device can perform. It provides a framework for
     * the state machine that is used to perform various operations.
     * While it is public, it is not meant to be used directly by the
     * application, and should only be used by the CDRomDevice class.
     *
     */
    template <Concepts::IsCDRomDeviceStateEnum S>
    class Action : public ActionBase {
      protected:
        Action(const char *const name) : ActionBase(name) {}
        void registerMe(CDRomDevice *device) {
            device->switchAction(this);
            m_device = device;
        }

        void setState(S state) { m_device->m_state = static_cast<uint8_t>(state); }
        S getState() const { return static_cast<S>(m_device->m_state); }
    };

    /**
     * @brief Checks if the CDROM device is in idle state.
     *
     */
    [[nodiscard]] bool isIdle() const { return m_state == 0; }

  private:
    void switchAction(ActionBase *action);
    void irq();
    void actionComplete();

    friend class ActionBase;

    eastl::function<void(bool)> m_callback;
    eastl::function<void(PlaybackLocation *)> m_locationCallback;
    PlaybackLocation m_locationStorage;
    PlaybackLocation *m_locationPtr = nullptr;
    uint32_t m_event = 0;
    ActionBase *m_action = nullptr;
    uint8_t m_state = 0;
    bool m_success = false;
    bool m_blocking = false;
    bool m_pendingGetLocation = false;

    struct BlockingAction {
        BlockingAction(CDRomDevice *, GPU &);
        ~BlockingAction();

      private:
        CDRomDevice *m_device;
        GPU &m_gpu;
    };

    struct MaskedIRQ {
        MaskedIRQ();
        ~MaskedIRQ();
    };
};

}  // namespace psyqo
