#include "camera_session.h"

#include <aidl/android/hardware/camera/common/Status.h>
#include <aidl/android/hardware/camera/device/BufferStatus.h>
#include <aidl/android/hardware/camera/device/CaptureResult.h>
#include <aidl/android/hardware/camera/device/ErrorCode.h>
#include <aidl/android/hardware/camera/device/ErrorMsg.h>
#include <aidl/android/hardware/camera/device/NotifyMsg.h>
#include <aidl/android/hardware/camera/device/ShutterMsg.h>
#include <aidl/android/hardware/camera/device/StreamBuffer.h>
#include <aidl/android/hardware/common/fmq/GrantorDescriptor.h>
#include <android/log.h>
#include <android/sharedmem.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <new>
#include <thread>
#include <utility>
#include <vector>

#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "camera_source.h"
#include "camera_buffer.h"
#include "camera_device.h"
#include "camera_renderer.h"
#include "camera_types.h"

namespace camera_provider {
namespace {

namespace camera = aidl::android::hardware::camera;
using camera::common::Status;
using camera::device::BufferStatus;
using camera::device::CaptureResult;
using camera::device::ErrorCode;
using camera::device::ErrorMsg;
using camera::device::NotifyMsg;
using camera::device::ShutterMsg;
using camera::device::StreamBuffer;
using ndk::ScopedAStatus;

constexpr size_t kMaximumQueuedRequests = 16;
constexpr auto kAcquireFenceTimeout = std::chrono::milliseconds(500);
constexpr auto kRequestProcessingTimeout = std::chrono::milliseconds(2000);

ScopedAStatus halError(Status status, const char* message) {
    __android_log_print(ANDROID_LOG_WARN, "camera-provider",
            "session error %d: %s", static_cast<int32_t>(status), message);
    return ScopedAStatus::fromServiceSpecificErrorWithMessage(
            static_cast<int32_t>(status), message);
}

ScopedAStatus halError(Status status, const std::string& message) {
    return halError(status, message.c_str());
}

int64_t bootTimeNanoseconds() {
    timespec now{};
    if (clock_gettime(CLOCK_BOOTTIME, &now) != 0) {
        clock_gettime(CLOCK_MONOTONIC, &now);
    }
    return static_cast<int64_t>(now.tv_sec) * 1'000'000'000LL + now.tv_nsec;
}

bool handleIsEmpty(const aidl::android::hardware::common::NativeHandle& handle) {
    return handle.fds.empty() && handle.ints.empty();
}

NotifyMsg makeErrorNotification(int32_t frameNumber, int32_t streamId, ErrorCode code) {
    ErrorMsg error;
    error.frameNumber = frameNumber;
    error.errorStreamId = streamId;
    error.errorCode = code;
    return NotifyMsg::make<NotifyMsg::Tag::error>(std::move(error));
}

NotifyMsg makeShutterNotification(int32_t frameNumber, const FrameTiming& timing) {
    ShutterMsg shutter;
    shutter.frameNumber = frameNumber;
    shutter.timestamp = timing.timestampNs;
    shutter.readoutTimestamp = timing.timestampNs + timing.exposureTimeNs;
    return NotifyMsg::make<NotifyMsg::Tag::shutter>(std::move(shutter));
}

void initializeResult(CaptureResult* result, int32_t frameNumber) {
    result->frameNumber = frameNumber;
    result->fmqResultSize = 0;
    result->inputBuffer.streamId = -1;
    result->inputBuffer.bufferId = 0;
    result->partialResult = 0;
    result->physicalCameraMetadata.clear();
}

using MetadataQueueDescriptor =
        aidl::android::hardware::common::fmq::MQDescriptor<
                int8_t,
                aidl::android::hardware::common::fmq::SynchronizedReadWrite>;
using GrantorDescriptor =
        aidl::android::hardware::common::fmq::GrantorDescriptor;

constexpr size_t kMetadataQueueCapacity = 1U << 18;
constexpr int32_t kSynchronizedReadWriteFlag = 1;

class MetadataQueue {
public:
    MetadataQueue() = default;
    MetadataQueue(const MetadataQueue&) = delete;
    MetadataQueue& operator=(const MetadataQueue&) = delete;
    ~MetadataQueue() { reset(); }

    bool initialize(const char* name, std::string* error) {
        reset();
        constexpr size_t kPointerBytes = sizeof(uint64_t);
        constexpr size_t kDataOffset = kPointerBytes * 2U;
        constexpr size_t kMemoryBytes =
                kDataOffset + kMetadataQueueCapacity;
        static_assert(std::atomic<uint64_t>::is_always_lock_free);

        const int fd = ASharedMemory_create(name, kMemoryBytes);
        if (fd < 0) {
            if (error != nullptr) {
                *error = std::string("metadata queue allocation failed: ") +
                        std::strerror(errno);
            }
            return false;
        }
        void* const mapping = mmap(nullptr, kMemoryBytes,
                                   PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (mapping == MAP_FAILED) {
            const int savedErrno = errno;
            close(fd);
            if (error != nullptr) {
                *error = std::string("metadata queue mapping failed: ") +
                        std::strerror(savedErrno);
            }
            return false;
        }

        fd_ = fd;
        mapping_ = mapping;
        mappingBytes_ = kMemoryBytes;
        uint8_t* const bytes = static_cast<uint8_t*>(mapping_);
        readPointer_ = new (bytes) std::atomic<uint64_t>(0);
        writePointer_ = new (bytes + kPointerBytes) std::atomic<uint64_t>(0);
        data_ = bytes + kDataOffset;
        return true;
    }

    bool dupeDescriptor(MetadataQueueDescriptor* out,
                        std::string* error) const {
        if (!ready() || out == nullptr) {
            if (error != nullptr) {
                *error = "metadata queue is unavailable";
            }
            return false;
        }
        const int descriptorFd = fcntl(fd_, F_DUPFD_CLOEXEC, 0);
        if (descriptorFd < 0) {
            if (error != nullptr) {
                *error = std::string("metadata queue descriptor duplication failed: ") +
                        std::strerror(errno);
            }
            return false;
        }

        MetadataQueueDescriptor descriptor;
        descriptor.grantors.reserve(3);
        const auto addGrantor = [&descriptor](int32_t offset,
                                               int64_t extent) {
            GrantorDescriptor grantor;
            grantor.fdIndex = 0;
            grantor.offset = offset;
            grantor.extent = extent;
            descriptor.grantors.push_back(grantor);
        };
        addGrantor(0, sizeof(uint64_t));
        addGrantor(sizeof(uint64_t), sizeof(uint64_t));
        addGrantor(sizeof(uint64_t) * 2,
                   static_cast<int64_t>(kMetadataQueueCapacity));
        descriptor.handle.fds.emplace_back(descriptorFd);
        descriptor.quantum = sizeof(int8_t);
        descriptor.flags = kSynchronizedReadWriteFlag;
        *out = std::move(descriptor);
        return true;
    }

    bool read(uint8_t* destination, size_t size) {
        if (size == 0) {
            return true;
        }
        if (!ready() || destination == nullptr ||
            size > kMetadataQueueCapacity) {
            return false;
        }

        const uint64_t write =
                writePointer_->load(std::memory_order_acquire);
        const uint64_t read =
                readPointer_->load(std::memory_order_relaxed);
        const uint64_t available = write - read;
        if (available > kMetadataQueueCapacity) {
            readPointer_->store(write, std::memory_order_release);
            return false;
        }
        if (available < size) {
            return false;
        }

        const size_t offset =
                static_cast<size_t>(read % kMetadataQueueCapacity);
        const size_t first = std::min(size,
                                     kMetadataQueueCapacity - offset);
        std::memcpy(destination, data_ + offset, first);
        if (first != size) {
            std::memcpy(destination + first, data_, size - first);
        }
        readPointer_->store(read + size, std::memory_order_release);
        return true;
    }

    bool write(const uint8_t* source, size_t size) {
        if (size == 0) {
            return true;
        }
        if (!ready() || source == nullptr || size > kMetadataQueueCapacity) {
            return false;
        }

        const uint64_t read =
                readPointer_->load(std::memory_order_acquire);
        const uint64_t write =
                writePointer_->load(std::memory_order_relaxed);
        const uint64_t used = write - read;
        if (used > kMetadataQueueCapacity ||
            kMetadataQueueCapacity - used < size) {
            return false;
        }

        const size_t offset =
                static_cast<size_t>(write % kMetadataQueueCapacity);
        const size_t first = std::min(size,
                                     kMetadataQueueCapacity - offset);
        std::memcpy(data_ + offset, source, first);
        if (first != size) {
            std::memcpy(data_, source + first, size - first);
        }
        writePointer_->store(write + size, std::memory_order_release);
        return true;
    }

private:
    bool ready() const {
        return fd_ >= 0 && mapping_ != MAP_FAILED &&
                readPointer_ != nullptr && writePointer_ != nullptr &&
                data_ != nullptr;
    }

    void reset() {
        readPointer_ = nullptr;
        writePointer_ = nullptr;
        data_ = nullptr;
        if (mapping_ != MAP_FAILED) {
            munmap(mapping_, mappingBytes_);
            mapping_ = MAP_FAILED;
            mappingBytes_ = 0;
        }
        if (fd_ >= 0) {
            close(fd_);
            fd_ = -1;
        }
    }

    int fd_ = -1;
    void* mapping_ = MAP_FAILED;
    size_t mappingBytes_ = 0;
    std::atomic<uint64_t>* readPointer_ = nullptr;
    std::atomic<uint64_t>* writePointer_ = nullptr;
    uint8_t* data_ = nullptr;
};

}  // namespace

struct CameraSession::Impl {
    enum class State {
        Open,
        Configured,
        Active,
        Flushing,
        Closed,
    };

    struct PendingBuffer {
        StreamDescriptor stream;
        BufferView view;
        bool cancelled = false;
        bool succeeded = false;
    };

    struct PendingRequest {
        PendingRequest() = default;
        PendingRequest(PendingRequest&&) noexcept = default;
        PendingRequest& operator=(PendingRequest&&) noexcept = default;
        PendingRequest(const PendingRequest&) = delete;
        PendingRequest& operator=(const PendingRequest&) = delete;

        int32_t frameNumber = 0;
        RequestSettings settings;
        std::vector<PendingBuffer> buffers;
        uint64_t cancellationGeneration = 0;
        bool cancelAll = false;
    };

    Impl(const CameraProfile& profileValue,
            std::shared_ptr<camera::device::ICameraDeviceCallback> callbackValue,
            std::function<void()> onClosedValue)
        : profile(profileValue),
          callback(std::move(callbackValue)),
          onClosed(std::move(onClosedValue)),
          renderer(profileValue.sensorOrientation) {
        std::string error;
        if (!source.openSnapshot(&error)) {
            __android_log_print(ANDROID_LOG_ERROR, "camera-provider",
                                "source snapshot rejected: %s", error.c_str());
            return;
        }
        if (!requestMetadataQueue.initialize(
                    "camera-request-metadata", &error) ||
            !resultMetadataQueue.initialize(
                    "camera-result-metadata", &error)) {
            __android_log_print(ANDROID_LOG_ERROR, "camera-provider",
                                "metadata queue rejected: %s", error.c_str());
            source.release();
            return;
        }
        sourceReady = true;
        queue.reserve(kMaximumQueuedRequests);
        worker = std::thread([this] { workerLoop(); });
    }

    ~Impl() { shutdown(); }

    const StreamDescriptor* findStream(int32_t streamId) const {
        for (const auto& stream : configuredStreams) {
            if (stream.id == streamId) return &stream;
        }
        return nullptr;
    }

    void notify(const std::vector<NotifyMsg>& messages) {
        if (messages.empty()) {
            return;
        }
        if (callback == nullptr) {
            __android_log_print(
                    ANDROID_LOG_ERROR, "camera-provider",
                    "dropping %zu camera notifications: callback is unavailable",
                    messages.size());
            return;
        }
        const ScopedAStatus status = callback->notify(messages);
        if (!status.isOk()) {
            const std::string description = status.getDescription();
            __android_log_print(
                    ANDROID_LOG_ERROR, "camera-provider",
                    "camera notify callback failed: %s",
                    description.c_str());
        }
    }

    void returnResult(CaptureResult&& result) {
        const int32_t frameNumber = result.frameNumber;
        if (callback == nullptr) {
            __android_log_print(
                    ANDROID_LOG_ERROR, "camera-provider",
                    "dropping capture result for frame %d: callback is unavailable",
                    frameNumber);
            return;
        }
        if (!result.result.metadata.empty() &&
            resultMetadataQueue.write(result.result.metadata.data(),
                                      result.result.metadata.size())) {
            result.fmqResultSize =
                    static_cast<int64_t>(result.result.metadata.size());
            result.result.metadata.clear();
        }
        std::vector<CaptureResult> results;
        results.reserve(1);
        results.push_back(std::move(result));
        const ScopedAStatus status = callback->processCaptureResult(results);
        if (!status.isOk()) {
            const std::string description = status.getDescription();
            __android_log_print(
                    ANDROID_LOG_ERROR, "camera-provider",
                    "capture result callback failed for frame %d: %s",
                    frameNumber, description.c_str());
        }
    }

    void returnRequestError(PendingRequest& request) {
        std::vector<NotifyMsg> messages;
        messages.reserve(1);
        messages.push_back(makeErrorNotification(
                request.frameNumber, -1, ErrorCode::ERROR_REQUEST));
        notify(messages);

        CaptureResult result;
        initializeResult(&result, request.frameNumber);
        result.outputBuffers.reserve(request.buffers.size());
        for (auto& buffer : request.buffers) {
            result.outputBuffers.push_back(makeResultBuffer(buffer.view, BufferStatus::ERROR,
                    !buffer.view.acquireFenceWaited()));
        }
        returnResult(std::move(result));
    }

    bool waitForFrame(PendingRequest& request) {
        std::unique_lock<std::mutex> lock(mutex);
        auto now = std::chrono::steady_clock::now();
        if (!haveFrameDeadline || nextFrameDeadline +
                std::chrono::nanoseconds(kNominalFrameDurationNs) < now) {
            nextFrameDeadline = now;
            haveFrameDeadline = true;
        }
        const auto deadline = nextFrameDeadline;
        nextFrameDeadline =
                deadline + std::chrono::nanoseconds(kNominalFrameDurationNs);
        condition.wait_until(lock, deadline, [&] {
            return request.cancelAll ||
                    cancelInFlight.load(std::memory_order_acquire) ||
                    request.cancellationGeneration != cancellationGeneration;
        });
        return !request.cancelAll &&
                !cancelInFlight.load(std::memory_order_acquire) &&
                request.cancellationGeneration == cancellationGeneration;
    }

    void processRequest(PendingRequest& request) {
        const bool allBuffersCancelled = std::all_of(
                request.buffers.begin(), request.buffers.end(),
                [](const PendingBuffer& buffer) { return buffer.cancelled; });
        if (request.cancelAll || allBuffersCancelled || !waitForFrame(request)) {
            returnRequestError(request);
            return;
        }
        const auto requestDeadline =
                std::chrono::steady_clock::now() + kRequestProcessingTimeout;

        FrameTiming timing;
        timing.timestampNs = bootTimeNanoseconds();
        if (timing.timestampNs <= lastTimestampNs) {
            timing.timestampNs = lastTimestampNs + 1;
        }
        lastTimestampNs = timing.timestampNs;

        const bool videoRequest = request.settings.captureIntent == 3 ||
                request.settings.captureIntent == 4 ||
                std::any_of(request.buffers.begin(), request.buffers.end(),
                        [](const PendingBuffer& buffer) {
                            return !buffer.cancelled &&
                                    buffer.stream.videoEncoder;
                        });
        SourceFrame sourceFrame;
        std::string error;
        if (!source.frame(videoRequest, timing.timestampNs, &cancelInFlight,
                          requestDeadline, &sourceFrame, &error) ||
            cancelInFlight.load(std::memory_order_acquire)) {
            returnRequestError(request);
            return;
        }

        size_t successCount = 0;
        for (auto& buffer : request.buffers) {
            if (buffer.cancelled) {
                continue;
            }
            if (cancelInFlight.load(std::memory_order_acquire)) {
                returnRequestError(request);
                return;
            }
            error.clear();
            const auto fenceDeadline = std::min(
                    requestDeadline,
                    std::chrono::steady_clock::now() + kAcquireFenceTimeout);
            if (!waitAcquireFence(&buffer.view, fenceDeadline, &cancelInFlight,
                                  &error)) {
                if (cancelInFlight.load(std::memory_order_acquire)) {
                    returnRequestError(request);
                    return;
                }
                continue;
            }
            if (cancelInFlight.load(std::memory_order_acquire)) {
                returnRequestError(request);
                return;
            }
            error.clear();
            if (!renderer.writeFrame(
                        request.settings, timing, request.frameNumber,
                        buffer.stream, buffer.view.buffer(), sourceFrame,
                        source.mode(), profile.flashAvailable, &error)) {
                continue;
            }
            if (cancelInFlight.load(std::memory_order_acquire)) {
                returnRequestError(request);
                return;
            }
            buffer.succeeded = true;
            ++successCount;
        }

        if (successCount == 0 ||
            cancelInFlight.load(std::memory_order_acquire)) {
            returnRequestError(request);
            return;
        }

        CameraMetadata metadata;
        error.clear();
        const bool metadataOk =
                buildResultMetadata(
                        profile, request.settings, timing, &metadata, &error);

        std::vector<NotifyMsg> messages;
        messages.reserve(1 + request.buffers.size() + (metadataOk ? 0 : 1));
        messages.push_back(makeShutterNotification(request.frameNumber, timing));
        for (const auto& buffer : request.buffers) {
            if (!buffer.succeeded) {
                messages.push_back(makeErrorNotification(
                        request.frameNumber, buffer.stream.id,
                        ErrorCode::ERROR_BUFFER));
            }
        }
        if (!metadataOk) {
            messages.push_back(makeErrorNotification(
                    request.frameNumber, -1, ErrorCode::ERROR_RESULT));
        }
        notify(messages);

        CaptureResult result;
        initializeResult(&result, request.frameNumber);
        if (metadataOk) {
            result.result = std::move(metadata);
            result.partialResult = 1;
        }
        result.outputBuffers.reserve(request.buffers.size());
        for (auto& buffer : request.buffers) {
            const BufferStatus status =
                    buffer.succeeded ? BufferStatus::OK : BufferStatus::ERROR;
            result.outputBuffers.push_back(makeResultBuffer(
                    buffer.view, status, !buffer.view.acquireFenceWaited()));
        }
        returnResult(std::move(result));
    }

    void workerLoop() {
        for (;;) {
            PendingRequest request;
            {
                std::unique_lock<std::mutex> lock(mutex);
                condition.wait(lock, [&] { return stopWorker || !queue.empty(); });
                if (queue.empty()) {
                    if (stopWorker) break;
                    continue;
                }
                request = std::move(queue.front());
                queue.erase(queue.begin());
                inFlight = true;
                cancelInFlight.store(
                        request.cancelAll ||
                                request.cancellationGeneration !=
                                        cancellationGeneration,
                        std::memory_order_release);
                condition.notify_all();
            }

            processRequest(request);

            {
                std::lock_guard<std::mutex> lock(mutex);
                inFlight = false;
                cancelInFlight.store(false, std::memory_order_release);
                if (queue.empty() && state == State::Active) {
                    state = State::Configured;
                }
                condition.notify_all();
            }
        }
    }

    void shutdown() {
        std::lock_guard<std::mutex> shutdownLock(shutdownMutex);
        std::function<void()> release;
        {
            std::lock_guard<std::mutex> submissionLock(submissionMutex);
            acceptingSubmissions = false;
            std::lock_guard<std::mutex> lock(mutex);
            if (state != State::Closed) {
                state = State::Closed;
                ++cancellationGeneration;
                cancelInFlight.store(true, std::memory_order_release);
                for (auto& request : queue) {
                    request.cancelAll = true;
                }
            }
            stopWorker = true;
            condition.notify_all();
        }
        if (worker.joinable()) worker.join();
        source.release();
        renderer.releaseScratch();
        {
            std::unique_lock<std::mutex> lock(mutex);
            condition.wait(lock, [&] {
                return activeSubmissions.load(std::memory_order_acquire) == 0;
            });
            bufferCache.clear();
            configuredStreams.clear();
            lastSettings.reset();
            callback.reset();
            if (!closeReported) {
                closeReported = true;
                release = std::move(onClosed);
            }
        }
        if (release) release();
    }

    const CameraProfile& profile;
    std::shared_ptr<camera::device::ICameraDeviceCallback> callback;
    std::function<void()> onClosed;
    std::mutex mutex;
    std::mutex shutdownMutex;
    std::condition_variable condition;
    std::mutex submissionMutex;
    std::atomic<size_t> activeSubmissions{0};
    std::atomic<bool> cancelInFlight{false};
    State state = State::Open;
    bool stopWorker = false;
    bool inFlight = false;
    bool closeReported = false;
    bool sourceReady = false;
    bool acceptingSubmissions = true;
    std::thread worker;
    std::vector<PendingRequest> queue;
    CameraBufferCache bufferCache;
    CameraSource source;
    CameraRenderer renderer;
    MetadataQueue requestMetadataQueue;
    MetadataQueue resultMetadataQueue;
    std::vector<StreamDescriptor> configuredStreams;
    std::optional<RequestSettings> lastSettings;
    int32_t streamConfigCounter = -1;
    int32_t lastAcceptedFrameNumber = -1;
    int32_t lastRepeatingFrameNumber = -1;
    std::vector<int32_t> lastRepeatingStreams;
    uint64_t cancellationGeneration = 0;
    bool haveFrameDeadline = false;
    std::chrono::steady_clock::time_point nextFrameDeadline;
    int64_t lastTimestampNs = 0;
};

CameraSession::CameraSession(
        const CameraProfile& profile,
        std::shared_ptr<camera::device::ICameraDeviceCallback> callback,
        std::function<void()> onClosed) noexcept {
    try {
        impl_ = std::make_unique<Impl>(
                profile, std::move(callback), std::move(onClosed));
    } catch (...) {
        impl_.reset();
    }
}

CameraSession::~CameraSession() = default;
bool CameraSession::ready() const {
    return impl_ != nullptr && impl_->sourceReady;
}


ScopedAStatus CameraSession::close() {
    impl_->shutdown();
    return ScopedAStatus::ok();
}

ScopedAStatus CameraSession::configureStreams(
        const camera::device::StreamConfiguration& requestedConfiguration,
        std::vector<camera::device::HalStream>* out) {
    std::vector<camera::device::HalStream> halStreams;
    std::vector<StreamDescriptor> streamDescriptors;
    std::string error;
    if (!validateStreamConfiguration(
            impl_->profile, requestedConfiguration, true, &halStreams,
            &streamDescriptors, &error)) {
        __android_log_print(ANDROID_LOG_WARN, "camera-provider",
                "rejected stream configuration: %s; %s", error.c_str(),
                requestedConfiguration.toString().c_str());
        out->clear();
        return halError(Status::ILLEGAL_ARGUMENT, error);
    }

    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->state == Impl::State::Closed) {
        out->clear();
        return halError(Status::INTERNAL_ERROR, "camera session is closed");
    }
    if (impl_->state == Impl::State::Flushing || impl_->inFlight || !impl_->queue.empty()) {
        out->clear();
        return halError(Status::INTERNAL_ERROR, "capture pipeline is not idle");
    }

    for (const auto& oldStream : impl_->configuredStreams) {
        bool retained = false;
        for (const auto& newStream : streamDescriptors) {
            if (oldStream.id == newStream.id && oldStream.width == newStream.width &&
                    oldStream.height == newStream.height &&
                    oldStream.overrideFormat == newStream.overrideFormat) {
                retained = true;
                break;
            }
        }
        if (!retained) impl_->bufferCache.remove(oldStream.id);
    }

    impl_->configuredStreams = std::move(streamDescriptors);
    impl_->lastSettings.reset();
    impl_->streamConfigCounter = requestedConfiguration.streamConfigCounter;
    impl_->state = Impl::State::Configured;
    impl_->haveFrameDeadline = false;
    *out = std::move(halStreams);
    return ScopedAStatus::ok();
}

ScopedAStatus CameraSession::constructDefaultRequestSettings(
        RequestTemplate type, CameraMetadata* out) {
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (impl_->state == Impl::State::Closed) {
            out->metadata.clear();
            return halError(Status::INTERNAL_ERROR, "camera session is closed");
        }
    }
    std::string error;
    if (!buildDefaultRequest(impl_->profile, type, out, &error)) {
        out->metadata.clear();
        return halError(Status::ILLEGAL_ARGUMENT, error);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus CameraSession::flush() {
    std::unique_lock<std::mutex> submissionLock(impl_->submissionMutex);
    std::unique_lock<std::mutex> lock(impl_->mutex);
    if (impl_->state == Impl::State::Closed) {
        return halError(Status::INTERNAL_ERROR, "camera session is closed");
    }
    const bool wasConfigured = !impl_->configuredStreams.empty();
    impl_->state = Impl::State::Flushing;
    ++impl_->cancellationGeneration;
    impl_->cancelInFlight.store(true, std::memory_order_release);
    for (auto& request : impl_->queue) {
        request.cancelAll = true;
    }
    impl_->condition.notify_all();
    submissionLock.unlock();

    for (;;) {
        impl_->condition.wait(lock, [&] {
            return impl_->state == Impl::State::Closed ||
                    (!impl_->inFlight && impl_->queue.empty() &&
                            impl_->activeSubmissions.load(std::memory_order_acquire) == 0);
        });
        if (impl_->state == Impl::State::Closed) {
            return halError(Status::INTERNAL_ERROR, "camera session is closed");
        }

        submissionLock.lock();
        if (impl_->activeSubmissions.load(std::memory_order_acquire) != 0 ||
                impl_->inFlight || !impl_->queue.empty()) {
            submissionLock.unlock();
            continue;
        }
        impl_->state = wasConfigured ? Impl::State::Configured : Impl::State::Open;
        impl_->haveFrameDeadline = false;
        impl_->cancelInFlight.store(false, std::memory_order_release);
        submissionLock.unlock();
        return ScopedAStatus::ok();
    }
}

ScopedAStatus CameraSession::getCaptureRequestMetadataQueue(
        aidl::android::hardware::common::fmq::MQDescriptor<int8_t,
                aidl::android::hardware::common::fmq::SynchronizedReadWrite>* out) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->state == Impl::State::Closed) {
        return halError(Status::INTERNAL_ERROR, "camera session is closed");
    }
    std::string error;
    if (!impl_->requestMetadataQueue.dupeDescriptor(out, &error)) {
        *out = {};
        return halError(Status::INTERNAL_ERROR, error);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus CameraSession::getCaptureResultMetadataQueue(
        aidl::android::hardware::common::fmq::MQDescriptor<int8_t,
                aidl::android::hardware::common::fmq::SynchronizedReadWrite>* out) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->state == Impl::State::Closed) {
        return halError(Status::INTERNAL_ERROR, "camera session is closed");
    }
    std::string error;
    if (!impl_->resultMetadataQueue.dupeDescriptor(out, &error)) {
        *out = {};
        return halError(Status::INTERNAL_ERROR, error);
    }
    return ScopedAStatus::ok();
}

ScopedAStatus CameraSession::isReconfigurationRequired(
        const CameraMetadata&, const CameraMetadata&, bool* out) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->state == Impl::State::Closed) {
        return halError(Status::INTERNAL_ERROR, "camera session is closed");
    }
    *out = false;
    return ScopedAStatus::ok();
}

ScopedAStatus CameraSession::processCaptureRequest(
        const std::vector<camera::device::CaptureRequest>& requests,
        const std::vector<camera::device::BufferCache>& cachesToRemove,
        int32_t* out) {
    struct SubmissionGuard {
        Impl* impl;
        ~SubmissionGuard() {
            impl->activeSubmissions.fetch_sub(1, std::memory_order_release);
            impl->condition.notify_all();
        }
    };
    *out = 0;
    {
        std::lock_guard<std::mutex> submissionLock(impl_->submissionMutex);
        if (!impl_->acceptingSubmissions) {
            return halError(Status::INTERNAL_ERROR,
                            "camera session is closed");
        }
        impl_->activeSubmissions.fetch_add(1, std::memory_order_acq_rel);
    }
    SubmissionGuard submission{impl_.get()};

    std::unique_lock<std::mutex> lock(impl_->mutex);
    for (const auto& cache : cachesToRemove) {
        impl_->bufferCache.remove(cache.streamId, cache.bufferId);
    }
    if (requests.size() > kMaximumQueuedRequests) {
        return halError(Status::ILLEGAL_ARGUMENT,
                        "capture request batch exceeds queue capacity");
    }
    if (impl_->state == Impl::State::Closed) {
        return halError(Status::INTERNAL_ERROR, "camera session is closed");
    }
    if (impl_->state == Impl::State::Open) {
        return halError(Status::ILLEGAL_ARGUMENT, "streams are not configured");
    }

    impl_->condition.wait(lock, [&] {
        return impl_->state == Impl::State::Closed ||
                impl_->queue.size() <=
                        kMaximumQueuedRequests - requests.size();
    });
    if (impl_->state == Impl::State::Closed) {
        return halError(Status::INTERNAL_ERROR, "camera session is closed");
    }


    auto cacheTransaction = impl_->bufferCache.beginTransaction();
    std::vector<Impl::PendingRequest> pendingRequests;
    pendingRequests.reserve(requests.size());
    std::optional<RequestSettings> nextSettings = impl_->lastSettings;
    int32_t nextFrameNumber = impl_->lastAcceptedFrameNumber;
    const uint64_t requestGeneration = impl_->cancellationGeneration;
    const bool cancelBatch = impl_->state == Impl::State::Flushing;

    for (const auto& parcel : requests) {
        if (parcel.frameNumber <= nextFrameNumber) {
            return halError(Status::ILLEGAL_ARGUMENT,
                            "frame numbers must increase");
        }
        if (parcel.fmqSettingsSize < 0 ||
            parcel.fmqSettingsSize >
                    static_cast<int64_t>(kMetadataQueueCapacity)) {
            return halError(Status::ILLEGAL_ARGUMENT,
                            "request metadata FMQ size is invalid");
        }
        if (!parcel.physicalCameraSettings.empty()) {
            return halError(Status::ILLEGAL_ARGUMENT,
                            "physical settings are not supported");
        }
        if (!handleIsEmpty(parcel.inputBuffer.buffer)) {
            return halError(Status::ILLEGAL_ARGUMENT,
                            "input buffers are not supported");
        }
        if (parcel.outputBuffers.empty()) {
            return halError(Status::ILLEGAL_ARGUMENT,
                            "capture request has no outputs");
        }

        Impl::PendingRequest request;
        request.frameNumber = parcel.frameNumber;
        request.cancellationGeneration = requestGeneration;
        request.cancelAll = cancelBatch;
        std::string error;
        CameraMetadata fmqSettings;
        const CameraMetadata* settings = &parcel.settings;
        if (parcel.fmqSettingsSize > 0) {
            fmqSettings.metadata.resize(
                    static_cast<size_t>(parcel.fmqSettingsSize));
            if (!impl_->requestMetadataQueue.read(
                        fmqSettings.metadata.data(),
                        fmqSettings.metadata.size())) {
                return halError(
                        Status::ILLEGAL_ARGUMENT,
                        "request metadata FMQ did not contain the declared bytes");
            }
            settings = &fmqSettings;
        }
        if (!parseRequestSettings(
                    impl_->profile, *settings,
                    nextSettings ? &*nextSettings : nullptr,
                    &request.settings, &error)) {
            return halError(Status::ILLEGAL_ARGUMENT, error);
        }
        request.buffers.reserve(parcel.outputBuffers.size());
        for (size_t index = 0; index < parcel.outputBuffers.size(); ++index) {
            const auto& output = parcel.outputBuffers[index];
            const StreamDescriptor* stream = impl_->findStream(output.streamId);
            if (stream == nullptr || output.bufferId <= 0 ||
                output.status != BufferStatus::OK ||
                !handleIsEmpty(output.releaseFence)) {
                return halError(Status::ILLEGAL_ARGUMENT,
                                "output buffer is malformed");
            }
            for (size_t earlier = 0; earlier < index; ++earlier) {
                if (parcel.outputBuffers[earlier].streamId == output.streamId) {
                    return halError(Status::ILLEGAL_ARGUMENT,
                            "capture targets a stream more than once");
                }
            }

            BufferView view;
            error.clear();
            if (!cacheTransaction.prepare(
                        output, *stream, &view, &error)) {
                return halError(Status::ILLEGAL_ARGUMENT, error);
            }
            Impl::PendingBuffer pendingBuffer;
            pendingBuffer.stream = *stream;
            pendingBuffer.view = std::move(view);
            request.buffers.push_back(std::move(pendingBuffer));
        }

        nextSettings = request.settings;
        nextFrameNumber = parcel.frameNumber;
        pendingRequests.push_back(std::move(request));
    }

    for (auto& request : pendingRequests) {
        impl_->queue.push_back(std::move(request));
    }
    cacheTransaction.commit();
    impl_->lastSettings = nextSettings;
    impl_->lastAcceptedFrameNumber = nextFrameNumber;
    if (!cancelBatch && !requests.empty()) {
        impl_->state = Impl::State::Active;
    }
    *out = static_cast<int32_t>(requests.size());
    impl_->condition.notify_all();
    return ScopedAStatus::ok();
}

ScopedAStatus CameraSession::signalStreamFlush(
        const std::vector<int32_t>& streamIds, int32_t streamConfigCounter) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->state == Impl::State::Closed) {
        return halError(Status::INTERNAL_ERROR, "camera session is closed");
    }
    if (streamConfigCounter < impl_->streamConfigCounter) {
        return ScopedAStatus::ok();
    }
    for (auto& request : impl_->queue) {
        for (auto& buffer : request.buffers) {
            for (const int32_t streamId : streamIds) {
                if (buffer.stream.id == streamId) {
                    buffer.cancelled = true;
                    break;
                }
            }
        }
        request.cancelAll = std::all_of(
                request.buffers.begin(), request.buffers.end(),
                [](const Impl::PendingBuffer& buffer) {
                    return buffer.cancelled;
                });
    }
    impl_->condition.notify_all();
    return ScopedAStatus::ok();
}

ScopedAStatus CameraSession::switchToOffline(const std::vector<int32_t>&,
        camera::device::CameraOfflineSessionInfo* offlineSessionInfo,
        std::shared_ptr<camera::device::ICameraOfflineSession>* out) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->state == Impl::State::Closed) {
        offlineSessionInfo->offlineStreams.clear();
        offlineSessionInfo->offlineRequests.clear();
        out->reset();
        return halError(Status::INTERNAL_ERROR, "camera session is closed");
    }
    *offlineSessionInfo = {};
    out->reset();
    return halError(Status::OPERATION_NOT_SUPPORTED, "offline processing is not supported");
}

ScopedAStatus CameraSession::repeatingRequestEnd(
        int32_t frameNumber, const std::vector<int32_t>& streamIds) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->state == Impl::State::Closed) {
        return halError(Status::INTERNAL_ERROR, "camera session is closed");
    }
    impl_->lastRepeatingFrameNumber = frameNumber;
    impl_->lastRepeatingStreams = streamIds;
    return ScopedAStatus::ok();
}

}  // namespace camera_provider
