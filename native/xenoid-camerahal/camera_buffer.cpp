#include "camera_buffer.h"

#include <android/binder_auto_utils.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <new>
#include <poll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace camera_provider {
namespace {

using aidl::android::hardware::camera::device::BufferStatus;
using aidl::android::hardware::camera::device::StreamBuffer;
using aidl::android::hardware::common::NativeHandle;

constexpr int32_t kHandleMagic = 0x03141592;
constexpr size_t kLegacyHandleIntCount = 8;
constexpr size_t kCameraHandleIntCount = 13;

constexpr size_t kMagicIndex = 0;
constexpr size_t kFlagsIndex = 1;
constexpr size_t kSizeIndex = 2;
constexpr size_t kOffsetIndex = 3;
constexpr size_t kPidIndex = 6;
constexpr size_t kReservedIndex = 7;
constexpr size_t kFormatIndex = 8;
constexpr size_t kWidthIndex = 9;
constexpr size_t kHeightIndex = 10;
constexpr size_t kLumaStrideIndex = 11;
constexpr size_t kChromaStrideIndex = 12;

class OwnedFd final {
  public:
    explicit OwnedFd(int fd = -1) : fd_(fd) {}
    ~OwnedFd() {
        if (fd_ >= 0) {
            close(fd_);
        }
    }
    OwnedFd(const OwnedFd&) = delete;
    OwnedFd& operator=(const OwnedFd&) = delete;
    OwnedFd(OwnedFd&& other) noexcept : fd_(other.release()) {}
    OwnedFd& operator=(OwnedFd&& other) noexcept {
        if (this != &other) {
            if (fd_ >= 0) {
                close(fd_);
            }
            fd_ = other.release();
        }
        return *this;
    }

    int get() const { return fd_; }
    int release() {
        const int fd = fd_;
        fd_ = -1;
        return fd;
    }

  private:
    int fd_;
};

void setError(std::string* error, const std::string& message) {
    if (error != nullptr) {
        *error = message;
    }
}

int duplicateFd(int fd) {
    int duplicate;
    do {
        duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    } while (duplicate < 0 && errno == EINTR);
    return duplicate;
}

bool isEmptyHandle(const NativeHandle& handle) {
    return handle.fds.empty() && handle.ints.empty();
}

bool validateFence(const NativeHandle& fence, const char* name, std::string* error) {
    if (isEmptyHandle(fence)) {
        return true;
    }
    if (fence.fds.size() != 1 || !fence.ints.empty() || fence.fds[0].get() < 0) {
        setError(error, std::string(name) + " must be empty or contain exactly one fd");
        return false;
    }
    return true;
}

bool multiply(uint64_t left, uint64_t right, uint64_t* result) {
    if (left != 0 && right > std::numeric_limits<uint64_t>::max() / left) {
        return false;
    }
    *result = left * right;
    return true;
}

bool add(uint64_t left, uint64_t right, uint64_t* result) {
    if (right > std::numeric_limits<uint64_t>::max() - left) {
        return false;
    }
    *result = left + right;
    return true;
}

bool minimumBufferSize(const StreamDescriptor& stream, int32_t* lumaStride,
                       int32_t* chromaStride, uint64_t* minimumSize,
                       std::string* error) {
    if (stream.width <= 0 || stream.height <= 0) {
        setError(error, "stream dimensions must be positive");
        return false;
    }

    const uint64_t width = static_cast<uint32_t>(stream.width);
    const uint64_t height = static_cast<uint32_t>(stream.height);
    uint64_t first = 0;
    uint64_t second = 0;

    if (stream.overrideFormat == kRgba8888Format) {
        const uint64_t stride = (width + 1U) & ~UINT64_C(1);
        const uint64_t alignedHeight = (height + 1U) & ~UINT64_C(1);
        if (stride > INT32_MAX || !multiply(stride, alignedHeight, &first) ||
            !multiply(first, 4U, &second) || !add(second, 4U, minimumSize)) {
            setError(error, "RGBA buffer dimensions overflow");
            return false;
        }
        *lumaStride = static_cast<int32_t>(stride);
        *chromaStride = 0;
        return true;
    }

    if (stream.overrideFormat == kYuv420Format) {
        const uint64_t stride = (width + 15U) & ~UINT64_C(15);
        const uint64_t alignedHeight = (height + 1U) & ~UINT64_C(1);
        if (stride > INT32_MAX || !multiply(stride, alignedHeight, &first) ||
            !multiply(stride, alignedHeight / 2U, &second) ||
            !add(first, second, minimumSize)) {
            setError(error, "YUV buffer dimensions overflow");
            return false;
        }
        *lumaStride = static_cast<int32_t>(stride);
        *chromaStride = static_cast<int32_t>(stride);
        return true;
    }

    if (stream.overrideFormat == kBlobFormat) {
        if (!multiply(width, height, &first) ||
            !add(first, kJpegBlobFooterBytes, minimumSize)) {
            setError(error, "BLOB buffer dimensions overflow");
            return false;
        }
        *lumaStride = stream.width;
        *chromaStride = 0;
        return true;
    }

    setError(error, "stream override format is unsupported");
    return false;
}

}  // namespace

CachedBuffer::CachedBuffer(int fd, uint8_t* mapping, size_t capacity,
                           size_t blobCapacity, int32_t format, int32_t width,
                           int32_t height, int32_t lumaStride,
                           int32_t chromaStride)
    : fd_(fd),
      mapping_(mapping),
      capacity_(capacity),
      blobCapacity_(blobCapacity),
      format_(format),
      width_(width),
      height_(height),
      lumaStride_(lumaStride),
      chromaStride_(chromaStride) {}

CachedBuffer::~CachedBuffer() {
    if (mapping_ != nullptr) {
        munmap(mapping_, capacity_);
    }
    if (fd_ >= 0) {
        close(fd_);
    }
}

BufferView::BufferView(int32_t streamId, int64_t bufferId,
                       std::shared_ptr<CachedBuffer> buffer, int acquireFenceFd)
    : streamId_(streamId),
      bufferId_(bufferId),
      buffer_(std::move(buffer)),
      acquireFenceFd_(acquireFenceFd) {}

BufferView::~BufferView() {
    reset();
}

BufferView::BufferView(BufferView&& other) noexcept
    : streamId_(other.streamId_),
      bufferId_(other.bufferId_),
      buffer_(std::move(other.buffer_)),
      acquireFenceFd_(other.acquireFenceFd_),
      acquireFenceWaited_(other.acquireFenceWaited_) {
    other.streamId_ = -1;
    other.bufferId_ = 0;
    other.acquireFenceFd_ = -1;
    other.acquireFenceWaited_ = false;
}

BufferView& BufferView::operator=(BufferView&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    reset();
    streamId_ = other.streamId_;
    bufferId_ = other.bufferId_;
    buffer_ = std::move(other.buffer_);
    acquireFenceFd_ = other.acquireFenceFd_;
    acquireFenceWaited_ = other.acquireFenceWaited_;
    other.streamId_ = -1;
    other.bufferId_ = 0;
    other.acquireFenceFd_ = -1;
    other.acquireFenceWaited_ = false;
    return *this;
}

int BufferView::releaseAcquireFence() {
    const int fd = acquireFenceFd_;
    acquireFenceFd_ = -1;
    return fd;
}

void BufferView::reset() {
    if (acquireFenceFd_ >= 0) {
        close(acquireFenceFd_);
    }
    streamId_ = -1;
    bufferId_ = 0;
    buffer_.reset();
    acquireFenceFd_ = -1;
    acquireFenceWaited_ = false;
}

CameraBufferCache::Transaction::Transaction(CameraBufferCache* owner)
    : owner_(owner) {
    std::lock_guard<std::mutex> lock(owner_->mutex_);
    buffers_ = owner_->buffers_;
}

bool CameraBufferCache::Transaction::prepare(
        const StreamBuffer& parcel, const StreamDescriptor& stream,
        BufferView* out, std::string* error) {
    return CameraBufferCache::prepareInMap(
            &buffers_, parcel, stream, out, error);
}

void CameraBufferCache::Transaction::remove(
        int32_t streamId, int64_t bufferId) {
    buffers_.erase(CacheKey(streamId, bufferId));
}

void CameraBufferCache::Transaction::remove(int32_t streamId) {
    auto current = buffers_.lower_bound(
            CacheKey(streamId, std::numeric_limits<int64_t>::min()));
    while (current != buffers_.end() && current->first.first == streamId) {
        current = buffers_.erase(current);
    }
}

void CameraBufferCache::Transaction::commit() {
    if (owner_ == nullptr || committed_) {
        return;
    }
    std::lock_guard<std::mutex> lock(owner_->mutex_);
    owner_->buffers_ = std::move(buffers_);
    committed_ = true;
}

CameraBufferCache::Transaction CameraBufferCache::beginTransaction() {
    return Transaction(this);
}

bool CameraBufferCache::prepare(const StreamBuffer& parcel,
                                const StreamDescriptor& stream, BufferView* out,
                                std::string* error) {
    Transaction transaction = beginTransaction();
    if (!transaction.prepare(parcel, stream, out, error)) {
        return false;
    }
    transaction.commit();
    return true;
}

bool CameraBufferCache::prepareInMap(
        BufferMap* buffers, const StreamBuffer& parcel,
        const StreamDescriptor& stream, BufferView* out, std::string* error) {
    if (buffers == nullptr || out == nullptr) {
        setError(error, "output buffer transaction is invalid");
        return false;
    }
    *out = BufferView();

    if (parcel.streamId != stream.id || parcel.streamId < 0 ||
        parcel.bufferId <= 0) {
        setError(error, "buffer identity does not match the stream");
        return false;
    }
    if (parcel.status != BufferStatus::OK) {
        setError(error, "request buffer status is not OK");
        return false;
    }
    if (!isEmptyHandle(parcel.releaseFence)) {
        setError(error, "request release fence must be empty");
        return false;
    }
    if (!validateFence(parcel.acquireFence, "acquire fence", error)) {
        return false;
    }

    OwnedFd acquireFence;
    if (!isEmptyHandle(parcel.acquireFence)) {
        acquireFence = OwnedFd(duplicateFd(parcel.acquireFence.fds[0].get()));
        if (acquireFence.get() < 0) {
            setError(error, std::string("could not duplicate acquire fence: ") +
                                    std::strerror(errno));
            return false;
        }
    }

    const bool hasHandle = !isEmptyHandle(parcel.buffer);
    std::shared_ptr<CachedBuffer> cached;
    const CacheKey key(parcel.streamId, parcel.bufferId);

    if (!hasHandle) {
        const auto found = buffers->find(key);
        if (found == buffers->end()) {
            setError(error, "handle-less buffer is not present in the cache");
            return false;
        }
        cached = found->second;
    } else {
        if (parcel.buffer.fds.size() != 1 ||
            (parcel.buffer.ints.size() != kLegacyHandleIntCount &&
             parcel.buffer.ints.size() != kCameraHandleIntCount) ||
            parcel.buffer.fds[0].get() < 0) {
            setError(error, "buffer handle has an invalid transport shape");
            return false;
        }

        const std::vector<int32_t>& ints = parcel.buffer.ints;
        if (ints[kMagicIndex] != kHandleMagic || ints[kFlagsIndex] != 0 ||
            ints[kSizeIndex] <= 0 || ints[kOffsetIndex] != 0 ||
            ints[kPidIndex] <= 0 || ints[kReservedIndex] != 0) {
            setError(error, "buffer handle has an invalid legacy prefix");
            return false;
        }

        int32_t expectedLumaStride = 0;
        int32_t expectedChromaStride = 0;
        uint64_t requiredSize = 0;
        if (!minimumBufferSize(stream, &expectedLumaStride, &expectedChromaStride,
                               &requiredSize, error)) {
            return false;
        }

        uint64_t blobCapacity = 0;
        if (stream.overrideFormat == kRgba8888Format) {
            if (ints.size() != kLegacyHandleIntCount) {
                setError(error, "RGBA buffer must use the legacy handle layout");
                return false;
            }
        } else {
            if (ints.size() != kCameraHandleIntCount) {
                setError(error, "camera buffer must use the extended handle layout");
                return false;
            }
            bool geometryMatches = ints[kFormatIndex] == stream.overrideFormat;
            if (stream.overrideFormat == kBlobFormat) {
                uint64_t declaredPayload = 0;
                uint64_t declaredMinimum = 0;
                geometryMatches = geometryMatches && ints[kWidthIndex] > 0 &&
                        ints[kHeightIndex] == 1 &&
                        ints[kLumaStrideIndex] == ints[kWidthIndex] &&
                        ints[kChromaStrideIndex] == 0 &&
                        multiply(static_cast<uint32_t>(ints[kWidthIndex]),
                                 static_cast<uint32_t>(ints[kHeightIndex]),
                                 &declaredPayload) &&
                        add(declaredPayload, kJpegBlobFooterBytes,
                            &declaredMinimum) &&
                        declaredMinimum <=
                                static_cast<uint32_t>(ints[kSizeIndex]);
                blobCapacity = declaredPayload;
            } else {
                geometryMatches = geometryMatches &&
                        ints[kWidthIndex] == stream.width &&
                        ints[kHeightIndex] == stream.height &&
                        ints[kLumaStrideIndex] == expectedLumaStride &&
                        ints[kChromaStrideIndex] == expectedChromaStride;
            }
            if (!geometryMatches) {
                setError(error,
                         "extended buffer geometry mismatch: got format=" +
                                 std::to_string(ints[kFormatIndex]) + " width=" +
                                 std::to_string(ints[kWidthIndex]) + " height=" +
                                 std::to_string(ints[kHeightIndex]) + " luma=" +
                                 std::to_string(ints[kLumaStrideIndex]) + " chroma=" +
                                 std::to_string(ints[kChromaStrideIndex]) +
                                 "; expected format=" +
                                 std::to_string(stream.overrideFormat) + " width=" +
                                 std::to_string(stream.width) + " height=" +
                                 std::to_string(stream.height) + " luma=" +
                                 std::to_string(expectedLumaStride) + " chroma=" +
                                 std::to_string(expectedChromaStride));
                return false;
            }
        }

        const uint64_t capacity = static_cast<uint32_t>(ints[kSizeIndex]);
        if (stream.overrideFormat != kBlobFormat) {
            blobCapacity = capacity;
        }
        if (requiredSize > capacity || requiredSize > blobCapacity ||
            capacity > kMaximumCameraBufferBytes) {
            setError(error, "buffer capacity is invalid");
            return false;
        }

        OwnedFd bufferFd(duplicateFd(parcel.buffer.fds[0].get()));
        if (bufferFd.get() < 0) {
            setError(error, std::string("could not duplicate buffer fd: ") +
                                    std::strerror(errno));
            return false;
        }

        struct stat fdStatus {};
        int statResult;
        do {
            statResult = fstat(bufferFd.get(), &fdStatus);
        } while (statResult < 0 && errno == EINTR);
        if (statResult < 0 || fdStatus.st_size < 0 ||
            static_cast<uint64_t>(fdStatus.st_size) < capacity) {
            setError(error, "buffer fd is smaller than the declared capacity");
            return false;
        }

        void* mapping = mmap(nullptr, static_cast<size_t>(capacity),
                             PROT_READ | PROT_WRITE, MAP_SHARED, bufferFd.get(), 0);
        if (mapping == MAP_FAILED) {
            setError(error,
                     std::string("could not map buffer fd: ") + std::strerror(errno));
            return false;
        }

        cached = std::shared_ptr<CachedBuffer>(new (std::nothrow) CachedBuffer(
                bufferFd.release(), static_cast<uint8_t*>(mapping),
                static_cast<size_t>(capacity), static_cast<size_t>(blobCapacity),
                stream.overrideFormat, stream.width, stream.height,
                expectedLumaStride, expectedChromaStride));
        if (cached == nullptr) {
            munmap(mapping, static_cast<size_t>(capacity));
            setError(error, "could not allocate cached buffer state");
            return false;
        }

        buffers->insert_or_assign(key, cached);
    }

    *out = BufferView(parcel.streamId, parcel.bufferId, std::move(cached),
                      acquireFence.release());
    return true;
}

void CameraBufferCache::remove(int32_t streamId, int64_t bufferId) {
    std::lock_guard<std::mutex> lock(mutex_);
    buffers_.erase(CacheKey(streamId, bufferId));
}

void CameraBufferCache::remove(int32_t streamId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto current = buffers_.lower_bound(
            CacheKey(streamId, std::numeric_limits<int64_t>::min()));
    while (current != buffers_.end() && current->first.first == streamId) {
        current = buffers_.erase(current);
    }
}

void CameraBufferCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    buffers_.clear();
}

bool waitAcquireFence(
        BufferView* view, const std::chrono::steady_clock::time_point& deadline,
        const std::atomic<bool>* cancelled, std::string* error) {
    if (view == nullptr || !view->valid()) {
        setError(error, "buffer view is invalid");
        return false;
    }
    if (cancelled != nullptr && cancelled->load(std::memory_order_acquire)) {
        setError(error, "acquire fence wait cancelled");
        return false;
    }
    if (view->acquireFenceWaited_) {
        return true;
    }
    if (view->acquireFenceFd_ < 0) {
        view->acquireFenceWaited_ = true;
        return true;
    }

    struct pollfd descriptor {
        view->acquireFenceFd_, POLLIN, 0
    };
    constexpr int kCancellationPollMs = 5;

    for (;;) {
        if (cancelled != nullptr &&
            cancelled->load(std::memory_order_acquire)) {
            setError(error, "acquire fence wait cancelled");
            return false;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            setError(error, "acquire fence wait timed out");
            return false;
        }
        const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                        deadline - now);
        int remainingMs = static_cast<int>(remaining.count());
        if (remainingMs <= 0) {
            remainingMs = 1;
        }
        remainingMs = std::min(remainingMs, kCancellationPollMs);

        descriptor.revents = 0;
        const int result = poll(&descriptor, 1, remainingMs);
        if (result > 0) {
            if ((descriptor.revents & POLLIN) != 0) {
                view->acquireFenceWaited_ = true;
                return true;
            }
            setError(error, "acquire fence reported an invalid poll state");
            return false;
        }
        if (result == 0 || errno == EINTR) {
            continue;
        }
        setError(error,
                 std::string("acquire fence wait failed: ") +
                         std::strerror(errno));
        return false;
    }
}

StreamBuffer makeResultBuffer(BufferView& view, BufferStatus status,
                              bool returnUnwaitedAcquireFence) {
    StreamBuffer result;
    result.streamId = view.streamId_;
    result.bufferId = view.bufferId_;
    result.status = status;

    if (status == BufferStatus::ERROR && returnUnwaitedAcquireFence &&
        !view.acquireFenceWaited_ && view.acquireFenceFd_ >= 0) {
        ndk::ScopedFileDescriptor releaseFence(view.releaseAcquireFence());
        result.releaseFence.fds.push_back(std::move(releaseFence));
    }
    return result;
}

}  // namespace camera_provider
