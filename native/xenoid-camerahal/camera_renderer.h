#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "camera_types.h"
#include "camera_source.h"

namespace camera_provider {

class CachedBuffer;

class CameraRenderer final {
  public:
    explicit CameraRenderer(int32_t sensorOrientation);

    bool writeFrame(const RequestSettings& settings, const FrameTiming& timing,
                    int64_t frameNumber, const StreamDescriptor& stream,
                    CachedBuffer& buffer, const SourceFrame& source,
                    SourceMode mode, bool flashAvailable,
                    std::string* error);
    // Releases frame-sized working storage after the session worker stops.
    void releaseScratch();

  private:
    struct SceneState {
        uint64_t key;
        uint64_t phase;
        uint32_t centerX;
        uint32_t centerY;
        int32_t baseLift;
    };

    struct NaturalState {
        uint64_t noiseEpoch;
        uint16_t noiseBlend;
        int32_t motionX;
        int32_t motionY;
        int32_t exposureGain;
        int32_t redGain;
        int32_t blueGain;
    };

    struct Rgb {
        uint8_t red;
        uint8_t green;
        uint8_t blue;
    };

    struct JpegWriteContext {
        uint8_t* destination;
        size_t capacity;
        size_t size;
    };

    struct ScratchIdentity {
        const uint8_t* source = nullptr;
        size_t sourceBytes = 0;
        int32_t sourceWidth = 0;
        int32_t sourceHeight = 0;
        int32_t sourceStride = 0;
        int32_t sourceRotation = 0;
        int32_t outputRotation = 0;
        int32_t width = 0;
        int32_t height = 0;
        int64_t frameNumber = 0;
        int64_t timestampNs = 0;
        uint64_t fallbackKey = 0;
        uint64_t fallbackPhase = 0;
        SourceMode mode = SourceMode::Naturalized;
        bool sourceAvailable = false;
    };

    static bool appendJpeg(void* context, const void* data, size_t size);
    static bool isRightAngle(int32_t degrees);
    static int32_t normalizeRotation(int32_t degrees);
    static bool sameIdentity(const ScratchIdentity& left,
                             const ScratchIdentity& right);
    static SceneState makeSceneState(const RequestSettings& settings,
                                     const FrameTiming& timing,
                                     int64_t frameNumber);
    NaturalState makeNaturalState(const FrameTiming& timing,
                                  int64_t frameNumber) const;
    static Rgb scenePixel(const SceneState& state, uint32_t normalizedX,
                          uint32_t normalizedY);
    static Rgb sampleSource(const SourceFrame& source, int64_t sourceX,
                            int64_t sourceY);
    static Rgb naturalizePixel(const Rgb& pixel, const NaturalState& state,
                               uint64_t seed, uint32_t normalizedX,
                               uint32_t normalizedY);

    bool resizeScratch(int32_t width, int32_t height, std::string* error);
    bool renderScratch(const RequestSettings& settings,
                       const FrameTiming& timing,
                       int64_t frameNumber, const SourceFrame& source,
                       SourceMode mode, bool flashAvailable,
                       int32_t outputRotation, int32_t width,
                       int32_t height, std::string* error);
    bool renderFallbackScratch(const SceneState& state,
                               int32_t outputRotation,
                               int32_t width, int32_t height,
                               std::string* error);
    bool renderSourceScratch(const SourceFrame& source,
                             const NaturalState* naturalState,
                             int32_t outputRotation, int32_t width,
                             int32_t height, std::string* error);
    bool writeRgba(int32_t width, int32_t height, CachedBuffer& buffer,
                   std::string* error) const;
    bool writeYuv(int32_t width, int32_t height, CachedBuffer& buffer,
                  std::string* error) const;
    bool writeJpeg(const RequestSettings& settings, const FrameTiming& timing,
                   int32_t width, int32_t height, CachedBuffer& buffer,
                   std::string* error);

    std::vector<uint32_t> normalizedXScratch_;
    std::vector<int64_t> coordinateXScratch_;
    std::vector<int64_t> coordinateYScratch_;
    std::vector<uint8_t> rgbaScratch_;
    uint64_t seed_ = 0;
    int32_t sensorOrientation_ = 0;
    bool sensorOrientationValid_ = false;
    ScratchIdentity renderedIdentity_;
    bool scratchValid_ = false;
};

inline void CameraRenderer::releaseScratch() {
    std::vector<uint32_t>().swap(normalizedXScratch_);
    std::vector<int64_t>().swap(coordinateXScratch_);
    std::vector<int64_t>().swap(coordinateYScratch_);
    std::vector<uint8_t>().swap(rgbaScratch_);
    renderedIdentity_ = ScratchIdentity{};
    scratchValid_ = false;
}

}  // namespace camera_provider
