#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace camera_provider {

enum class SourceMode {
    Naturalized,
    Faithful,
};

// A borrowed, display-upright RGBA frame. The storage remains valid until the
// next frame() call or CameraSource destruction.
struct SourceFrame {
    const uint8_t* rgba = nullptr;
    size_t rgbaBytes = 0;
    int32_t width = 0;
    int32_t height = 0;
    int32_t rowStride = 0;
    int32_t rotationDegrees = 0;

    bool available() const {
        return rgba != nullptr && width > 0 && height > 0 && rowStride > 0 &&
                static_cast<size_t>(rowStride) >=
                        static_cast<size_t>(width) * 4U &&
                rgbaBytes >= static_cast<size_t>(rowStride) *
                        static_cast<size_t>(height);
    }
};

class CameraSource final {
  public:
    CameraSource();
    ~CameraSource();

    CameraSource(const CameraSource&) = delete;
    CameraSource& operator=(const CameraSource&) = delete;

    // Captures one immutable generation from /data/misc/camera/source. A
    // missing current.conf is a valid source-free snapshot.
    bool openSnapshot(std::string* error);

    // Selects video for record requests, photo otherwise, with the configured
    // cross-kind fallback. monotonicTimestampNs drives the looping video clock.
    bool frame(bool videoRequest, int64_t monotonicTimestampNs,
               const std::atomic<bool>* cancelled,
               const std::chrono::steady_clock::time_point& deadline,
               SourceFrame* out, std::string* error);
    // Releases decoder state, source descriptors, and decoded frame storage.
    // No frame calls may be in progress.
    void release();

    SourceMode mode() const;
    uint64_t generation() const;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace camera_provider
