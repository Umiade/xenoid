#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace camera_provider {

inline constexpr int32_t kBlobFormat = 33;
inline constexpr int32_t kImplementationDefinedFormat = 34;
inline constexpr int32_t kYuv420Format = 35;
inline constexpr int32_t kRgba8888Format = 1;
inline constexpr int64_t kNominalFrameDurationNs = 33'333'333LL;

struct StreamDescriptor {
    int32_t id = -1;
    int32_t width = 0;
    int32_t height = 0;
    int32_t requestedFormat = 0;
    int32_t overrideFormat = 0;
    int64_t usage = 0;
    bool videoEncoder = false;
};

struct RequestSettings {
    int32_t requestId = 0;
    uint8_t captureIntent = 1;
    uint8_t controlMode = 1;
    uint8_t aeMode = 1;
    uint8_t aeAntibandingMode = 3;
    uint8_t aeLock = 0;
    uint8_t aePrecaptureTrigger = 0;
    uint8_t afMode = 1;
    uint8_t afTrigger = 0;
    uint8_t awbMode = 1;
    uint8_t awbLock = 0;
    uint8_t effectMode = 0;
    uint8_t sceneMode = 0;
    uint8_t videoStabilizationMode = 0;
    uint8_t flashMode = 0;
    uint8_t aberrationMode = 0;
    uint8_t noiseReductionMode = 0;
    uint8_t lensOpticalStabilizationMode = 0;
    uint8_t faceDetectMode = 0;
    uint8_t hotPixelMapMode = 0;
    uint8_t testPatternMode = 0;
    int32_t aeExposureCompensation = 0;
    std::array<int32_t, 2> aeTargetFpsRange = {30, 30};
    std::array<int32_t, 4> cropRegion = {0, 0, 1920, 1080};
    int32_t jpegOrientation = 0;
    uint8_t jpegQuality = 95;
};

struct FrameTiming {
    int64_t timestampNs = 0;
    int64_t frameDurationNs = kNominalFrameDurationNs;
    int64_t exposureTimeNs = 10'000'000LL;
    int32_t sensitivity = 100;
    uint8_t pipelineDepth = 4;
};

}  // namespace camera_provider
