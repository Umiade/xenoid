#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace camera_provider {

inline constexpr int32_t kBlobFormat = 33;
inline constexpr int32_t kImplementationDefinedFormat = 34;
inline constexpr int32_t kYuv420Format = 35;
inline constexpr int32_t kRgba8888Format = 1;
inline constexpr int64_t kNominalFrameDurationNs = 33'333'333LL;
inline constexpr uint64_t kMaximumCameraBufferBytes = 64U * 1024U * 1024U;
inline constexpr uint64_t kJpegBlobFooterBytes = 8U;
inline constexpr uint8_t kOutputBlob = 1U << 0U;
inline constexpr uint8_t kOutputNonStalling = 1U << 1U;
inline constexpr uint8_t kOutputAll = kOutputBlob | kOutputNonStalling;

struct CameraOutputSize {
    int32_t width;
    int32_t height;
    int64_t blobStallDurationNs;
    uint8_t formatMask;
};

struct CameraProfile {
    std::string_view id;
    bool frontFacing;
    int32_t sensorOrientation;
    int32_t pixelWidth;
    int32_t pixelHeight;
    float physicalWidthMm;
    float physicalHeightMm;
    float focalLengthMm;
    float aperture;
    bool flashAvailable;
    bool oisAvailable;
    const CameraOutputSize* outputSizes;
    size_t outputSizeCount;
    int32_t jpegMaxSize;
};

inline constexpr std::array<CameraOutputSize, 6> kRearOutputSizes = {{
        {4080, 3072, 220'000'000LL, kOutputBlob},
        {3840, 2160, 180'000'000LL, kOutputBlob},
        {1920, 1080, 100'000'000LL, kOutputAll},
        {1280, 720, 70'000'000LL, kOutputAll},
        {640, 480, 30'000'000LL, kOutputAll},
        {320, 240, 15'000'000LL, kOutputAll},
}};

inline constexpr std::array<CameraOutputSize, 5> kFrontOutputSizes = {{
        {3840, 2880, 200'000'000LL, kOutputBlob},
        {1920, 1080, 100'000'000LL, kOutputAll},
        {1280, 720, 70'000'000LL, kOutputAll},
        {640, 480, 30'000'000LL, kOutputAll},
        {320, 240, 15'000'000LL, kOutputAll},
}};

inline constexpr std::array<CameraProfile, 2> kCameraProfiles = {{
        {"0", false, 90, 4080, 3072, 9.792f, 7.3728f, 6.81f, 1.85f,
         true, false, kRearOutputSizes.data(), kRearOutputSizes.size(),
         13 * 1024 * 1024},
        {"1", true, 270, 3840, 2880, 4.6848f, 3.5136f, 2.74f, 2.2f,
         false, false, kFrontOutputSizes.data(), kFrontOutputSizes.size(),
         12 * 1024 * 1024},
}};

constexpr bool cameraProfileIsSafe(const CameraProfile& profile) {
    if (profile.id.empty() || profile.sensorOrientation < 0 ||
        profile.sensorOrientation >= 360 ||
        profile.sensorOrientation % 90 != 0 || profile.pixelWidth <= 0 ||
        profile.pixelHeight <= 0 || profile.physicalWidthMm <= 0.0f ||
        profile.physicalHeightMm <= 0.0f || profile.focalLengthMm <= 0.0f ||
        profile.aperture <= 0.0f || profile.oisAvailable ||
        profile.outputSizes == nullptr || profile.outputSizeCount == 0 ||
        profile.jpegMaxSize <= 0 ||
        static_cast<uint64_t>(profile.jpegMaxSize) >
                kMaximumCameraBufferBytes) {
        return false;
    }
    int64_t previousArea = INT64_MAX;
    for (size_t index = 0; index < profile.outputSizeCount; ++index) {
        const CameraOutputSize& size = profile.outputSizes[index];
        if (size.width <= 0 || size.height <= 0 ||
            size.width > profile.pixelWidth || size.height > profile.pixelHeight ||
            size.blobStallDurationNs < 0 || size.formatMask == 0 ||
            (size.formatMask & ~kOutputAll) != 0 ||
            (size.formatMask & kOutputBlob) == 0) {
            return false;
        }
        const int64_t area =
                static_cast<int64_t>(size.width) * size.height;
        if (area >= previousArea ||
            ((size.formatMask & kOutputNonStalling) != 0 &&
             static_cast<uint64_t>(area) * 4U + 4U >
                     kMaximumCameraBufferBytes) ||
            static_cast<uint64_t>(area) + kJpegBlobFooterBytes >
                    static_cast<uint64_t>(profile.jpegMaxSize)) {
            return false;
        }
        previousArea = area;
    }
    return true;
}

static_assert(cameraProfileIsSafe(kCameraProfiles[0]));
static_assert(cameraProfileIsSafe(kCameraProfiles[1]));
static_assert(kCameraProfiles[0].id != kCameraProfiles[1].id);

inline const CameraProfile* findCameraProfile(std::string_view id) {
    for (const CameraProfile& profile : kCameraProfiles) {
        if (profile.id == id) return &profile;
    }
    return nullptr;
}
inline constexpr uint8_t outputFormatMask(int32_t format) {
    return format == kBlobFormat ? kOutputBlob
            : (format == kImplementationDefinedFormat ||
               format == kYuv420Format)
            ? kOutputNonStalling
            : 0;
}

inline const CameraOutputSize* findCameraOutputSize(
        const CameraProfile& profile, int32_t format, int32_t width,
        int32_t height) {
    const uint8_t requiredMask = outputFormatMask(format);
    if (requiredMask == 0) return nullptr;
    for (size_t index = 0; index < profile.outputSizeCount; ++index) {
        const CameraOutputSize& size = profile.outputSizes[index];
        if (size.width == width && size.height == height &&
            (size.formatMask & requiredMask) != 0) {
            return &size;
        }
    }
    return nullptr;
}

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
    uint8_t afMode = 0;
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
    std::array<int32_t, 4> cropRegion = {0, 0, 0, 0};
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
