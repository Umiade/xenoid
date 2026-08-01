#pragma once

#include <aidl/android/hardware/camera/device/BufferStatus.h>
#include <aidl/android/hardware/camera/device/StreamBuffer.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

#include "camera_types.h"

namespace camera_provider {

class CachedBuffer final {
  public:
    ~CachedBuffer();

    CachedBuffer(const CachedBuffer&) = delete;
    CachedBuffer& operator=(const CachedBuffer&) = delete;

    uint8_t* data() const { return mapping_; }
    size_t capacity() const { return capacity_; }
    size_t blobCapacity() const { return blobCapacity_; }
    int32_t format() const { return format_; }
    int32_t width() const { return width_; }
    int32_t height() const { return height_; }
    int32_t lumaStride() const { return lumaStride_; }
    int32_t chromaStride() const { return chromaStride_; }

  private:
    friend class CameraBufferCache;

    CachedBuffer(int fd, uint8_t* mapping, size_t capacity, size_t blobCapacity,
                 int32_t format, int32_t width, int32_t height,
                 int32_t lumaStride, int32_t chromaStride);

    int fd_ = -1;
    uint8_t* mapping_ = nullptr;
    size_t capacity_ = 0;
    size_t blobCapacity_ = 0;
    int32_t format_ = 0;
    int32_t width_ = 0;
    int32_t height_ = 0;
    int32_t lumaStride_ = 0;
    int32_t chromaStride_ = 0;
};

class BufferView final {
  public:
    BufferView() = default;
    ~BufferView();

    BufferView(BufferView&& other) noexcept;
    BufferView& operator=(BufferView&& other) noexcept;
    BufferView(const BufferView&) = delete;
    BufferView& operator=(const BufferView&) = delete;

    bool valid() const { return buffer_ != nullptr; }
    int32_t streamId() const { return streamId_; }
    int64_t bufferId() const { return bufferId_; }
    CachedBuffer& buffer() const { return *buffer_; }
    bool hasAcquireFence() const { return acquireFenceFd_ >= 0; }
    bool acquireFenceWaited() const { return acquireFenceWaited_; }

  private:
    friend class CameraBufferCache;
    friend bool waitAcquireFence(
            BufferView*, const std::chrono::steady_clock::time_point&,
            const std::atomic<bool>*, std::string*);
    friend aidl::android::hardware::camera::device::StreamBuffer makeResultBuffer(
            BufferView&,
            aidl::android::hardware::camera::device::BufferStatus, bool);

    BufferView(int32_t streamId, int64_t bufferId,
               std::shared_ptr<CachedBuffer> buffer, int acquireFenceFd);
    void reset();
    int releaseAcquireFence();

    int32_t streamId_ = -1;
    int64_t bufferId_ = 0;
    std::shared_ptr<CachedBuffer> buffer_;
    int acquireFenceFd_ = -1;
    bool acquireFenceWaited_ = false;
};

class CameraBufferCache final {
    using CacheKey = std::pair<int32_t, int64_t>;
    using BufferMap = std::map<CacheKey, std::shared_ptr<CachedBuffer>>;

  public:
    class Transaction final {
      public:
        Transaction(Transaction&&) noexcept = default;
        Transaction& operator=(Transaction&&) noexcept = default;
        Transaction(const Transaction&) = delete;
        Transaction& operator=(const Transaction&) = delete;

        bool prepare(
                const aidl::android::hardware::camera::device::StreamBuffer& parcel,
                const StreamDescriptor& stream, BufferView* out,
                std::string* error);
        void remove(int32_t streamId, int64_t bufferId);
        void remove(int32_t streamId);
        void commit();

      private:
        friend class CameraBufferCache;
        explicit Transaction(CameraBufferCache* owner);

        CameraBufferCache* owner_ = nullptr;
        BufferMap buffers_;
        bool committed_ = false;
    };

    Transaction beginTransaction();
    bool prepare(
            const aidl::android::hardware::camera::device::StreamBuffer& parcel,
            const StreamDescriptor& stream, BufferView* out, std::string* error);
    void remove(int32_t streamId, int64_t bufferId);
    void remove(int32_t streamId);
    void clear();

  private:
    static bool prepareInMap(
            BufferMap* buffers,
            const aidl::android::hardware::camera::device::StreamBuffer& parcel,
            const StreamDescriptor& stream, BufferView* out,
            std::string* error);

    std::mutex mutex_;
    BufferMap buffers_;
};

bool waitAcquireFence(
        BufferView* view, const std::chrono::steady_clock::time_point& deadline,
        const std::atomic<bool>* cancelled, std::string* error);

aidl::android::hardware::camera::device::StreamBuffer makeResultBuffer(
        BufferView& view,
        aidl::android::hardware::camera::device::BufferStatus status,
        bool returnUnwaitedAcquireFence);

}  // namespace camera_provider
