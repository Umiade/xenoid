#include "camera_metadata.h"

#include <aidl/android/hardware/camera/metadata/CameraMetadataTag.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "camera_metadata_abi.h"

namespace camera_provider {
namespace {

using MetadataTag = ::aidl::android::hardware::camera::metadata::CameraMetadataTag;

constexpr uint32_t tagValue(MetadataTag tag) {
    return static_cast<uint32_t>(static_cast<int32_t>(tag));
}

constexpr int32_t keyValue(MetadataTag tag) {
    return static_cast<int32_t>(tag);
}

template <typename T>
constexpr uint8_t metadataType();

template <>
constexpr uint8_t metadataType<uint8_t>() {
    return CAMERA_METADATA_TYPE_BYTE;
}

template <>
constexpr uint8_t metadataType<int32_t>() {
    return CAMERA_METADATA_TYPE_INT32;
}

template <>
constexpr uint8_t metadataType<float>() {
    return CAMERA_METADATA_TYPE_FLOAT;
}

template <>
constexpr uint8_t metadataType<int64_t>() {
    return CAMERA_METADATA_TYPE_INT64;
}

template <>
constexpr uint8_t metadataType<double>() {
    return CAMERA_METADATA_TYPE_DOUBLE;
}

template <>
constexpr uint8_t metadataType<camera_metadata_rational_t>() {
    return CAMERA_METADATA_TYPE_RATIONAL;
}

bool fail(std::string* error, std::string message) {
    if (error != nullptr) *error = std::move(message);
    return false;
}

class MetadataBuilder {
public:
    MetadataBuilder() : metadata_(allocate_camera_metadata(128, 8192)) {
        if (metadata_ == nullptr) error_ = "unable to allocate camera metadata";
    }

    ~MetadataBuilder() {
        if (metadata_ != nullptr) free_camera_metadata(metadata_);
    }

    MetadataBuilder(const MetadataBuilder&) = delete;
    MetadataBuilder& operator=(const MetadataBuilder&) = delete;

    template <typename T>
    bool add(MetadataTag tag, const T* values, size_t count) {
        static_assert(std::is_same_v<T, uint8_t> || std::is_same_v<T, int32_t> ||
                      std::is_same_v<T, float> || std::is_same_v<T, int64_t> ||
                      std::is_same_v<T, double> ||
                      std::is_same_v<T, camera_metadata_rational_t>);
        if (!error_.empty()) return false;
        if (count != 0 && values == nullptr) {
            error_ = "null camera metadata value";
            return false;
        }
        const uint32_t rawTag = tagValue(tag);
        if (get_camera_metadata_tag_type(rawTag) != metadataType<T>()) {
            error_ = "camera metadata tag type mismatch for " + std::to_string(rawTag);
            return false;
        }
        if (add_camera_metadata_entry(metadata_, rawTag, values, count) != 0) {
            error_ = "unable to add camera metadata tag " + std::to_string(rawTag);
            return false;
        }
        return true;
    }

    template <typename T, size_t N>
    bool add(MetadataTag tag, const std::array<T, N>& values) {
        return add(tag, values.data(), values.size());
    }

    template <typename T>
    bool addOne(MetadataTag tag, T value) {
        return add(tag, &value, 1);
    }

    template <typename T>
    bool addEmpty(MetadataTag tag) {
        return add<T>(tag, nullptr, 0);
    }

    bool finish(CameraMetadata* output, std::string* error) {
        if (output == nullptr) return fail(error, "null camera metadata output");
        output->metadata.clear();
        if (!error_.empty()) return fail(error, error_);
        if (sort_camera_metadata(metadata_) != 0) {
            return fail(error, "unable to sort camera metadata");
        }

        camera_metadata_t* compact = clone_camera_metadata(metadata_);
        if (compact == nullptr) return fail(error, "unable to compact camera metadata");
        const size_t size = get_camera_metadata_size(compact);
        const size_t expectedCompactSize = get_camera_metadata_compact_size(compact);
        if (size == 0 || size != expectedCompactSize ||
            validate_camera_metadata_structure(compact, &size) != 0) {
            free_camera_metadata(compact);
            return fail(error, "constructed camera metadata failed validation");
        }
        const auto* begin = reinterpret_cast<const uint8_t*>(compact);
        output->metadata.assign(begin, begin + size);
        free_camera_metadata(compact);
        return true;
    }

private:
    camera_metadata_t* metadata_ = nullptr;
    std::string error_;
};

template <typename T>
void addCharacteristic(MetadataBuilder* builder, std::vector<int32_t>* keys,
                       MetadataTag tag, const T* values, size_t count) {
    if (builder->add(tag, values, count)) keys->push_back(keyValue(tag));
}

template <typename T, size_t N>
void addCharacteristic(MetadataBuilder* builder, std::vector<int32_t>* keys,
                       MetadataTag tag, const std::array<T, N>& values) {
    addCharacteristic(builder, keys, tag, values.data(), values.size());
}

template <typename T>
void addCharacteristicOne(MetadataBuilder* builder, std::vector<int32_t>* keys,
                          MetadataTag tag, T value) {
    addCharacteristic(builder, keys, tag, &value, 1);
}

template <typename T>
void addEmptyCharacteristic(MetadataBuilder* builder, std::vector<int32_t>* keys,
                            MetadataTag tag) {
    const T unused{};
    addCharacteristic<T>(builder, keys, tag, &unused, 0);
}

bool addCharacteristicKeyList(MetadataBuilder* builder, std::vector<int32_t>* keys) {
    keys->push_back(keyValue(MetadataTag::ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS));
    std::sort(keys->begin(), keys->end());
    keys->erase(std::unique(keys->begin(), keys->end()), keys->end());
    return builder->add(MetadataTag::ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS,
                        keys->data(), keys->size());
}

struct CameraOutputSize {
    int32_t width;
    int32_t height;
    int64_t blobStallDurationNs;
};

constexpr std::array<int32_t, 3> kStreamFormats = {
        kBlobFormat,
        kYuv420Format,
        kImplementationDefinedFormat,
};

constexpr std::array<CameraOutputSize, 8> kCameraOutputSizes = {{
        {1920, 1080, 100'000'000LL},
        {1440, 1080, 90'000'000LL},
        {1280, 960, 80'000'000LL},
        {1280, 720, 70'000'000LL},
        {1024, 768, 60'000'000LL},
        {800, 600, 50'000'000LL},
        {640, 480, 30'000'000LL},
        {320, 240, 15'000'000LL},
}};

constexpr size_t kStreamTupleValueCount =
        kStreamFormats.size() * kCameraOutputSizes.size() * 4;

constexpr std::array<int32_t, kStreamTupleValueCount> makeStreamConfigurations() {
    std::array<int32_t, kStreamTupleValueCount> values{};
    size_t index = 0;
    for (const int32_t format : kStreamFormats) {
        for (const CameraOutputSize& size : kCameraOutputSizes) {
            values[index++] = format;
            values[index++] = size.width;
            values[index++] = size.height;
            values[index++] = 0;  // output stream
        }
    }
    return values;
}

constexpr std::array<int64_t, kStreamTupleValueCount> makeMinFrameDurations() {
    std::array<int64_t, kStreamTupleValueCount> values{};
    size_t index = 0;
    for (const int32_t format : kStreamFormats) {
        for (const CameraOutputSize& size : kCameraOutputSizes) {
            values[index++] = format;
            values[index++] = size.width;
            values[index++] = size.height;
            values[index++] = kNominalFrameDurationNs;
        }
    }
    return values;
}

constexpr std::array<int64_t, kStreamTupleValueCount> makeStallDurations() {
    std::array<int64_t, kStreamTupleValueCount> values{};
    size_t index = 0;
    for (const int32_t format : kStreamFormats) {
        for (const CameraOutputSize& size : kCameraOutputSizes) {
            values[index++] = format;
            values[index++] = size.width;
            values[index++] = size.height;
            values[index++] = format == kBlobFormat ? size.blobStallDurationNs : 0;
        }
    }
    return values;
}

constexpr bool outputSizesAreValid() {
    for (size_t index = 0; index < kCameraOutputSizes.size(); ++index) {
        const CameraOutputSize& size = kCameraOutputSizes[index];
        if (size.width <= 0 || size.height <= 0 || size.width > 1920 ||
            size.height > 1080) {
            return false;
        }
        if (index != 0) {
            const CameraOutputSize& previous = kCameraOutputSizes[index - 1];
            const int64_t previousArea =
                    static_cast<int64_t>(previous.width) * previous.height;
            const int64_t area = static_cast<int64_t>(size.width) * size.height;
            if (previousArea < area) return false;
        }
    }
    return true;
}

constexpr auto kStreamConfigurations = makeStreamConfigurations();
constexpr auto kMinFrameDurations = makeMinFrameDurations();
constexpr auto kStallDurations = makeStallDurations();

static_assert(kCameraOutputSizes.size() == 8);
static_assert(outputSizesAreValid());
static_assert(kStreamConfigurations.size() == 3 * 8 * 4);
static_assert(kMinFrameDurations.size() == kStreamConfigurations.size());
static_assert(kStallDurations.size() == kStreamConfigurations.size());

constexpr std::array<int32_t, 26> kAvailableRequestKeys = {
        keyValue(MetadataTag::ANDROID_COLOR_CORRECTION_ABERRATION_MODE),
        keyValue(MetadataTag::ANDROID_CONTROL_AE_ANTIBANDING_MODE),
        keyValue(MetadataTag::ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION),
        keyValue(MetadataTag::ANDROID_CONTROL_AE_LOCK),
        keyValue(MetadataTag::ANDROID_CONTROL_AE_MODE),
        keyValue(MetadataTag::ANDROID_CONTROL_AE_TARGET_FPS_RANGE),
        keyValue(MetadataTag::ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER),
        keyValue(MetadataTag::ANDROID_CONTROL_AF_MODE),
        keyValue(MetadataTag::ANDROID_CONTROL_AF_TRIGGER),
        keyValue(MetadataTag::ANDROID_CONTROL_AWB_LOCK),
        keyValue(MetadataTag::ANDROID_CONTROL_AWB_MODE),
        keyValue(MetadataTag::ANDROID_CONTROL_CAPTURE_INTENT),
        keyValue(MetadataTag::ANDROID_CONTROL_EFFECT_MODE),
        keyValue(MetadataTag::ANDROID_CONTROL_MODE),
        keyValue(MetadataTag::ANDROID_CONTROL_SCENE_MODE),
        keyValue(MetadataTag::ANDROID_CONTROL_VIDEO_STABILIZATION_MODE),
        keyValue(MetadataTag::ANDROID_FLASH_MODE),
        keyValue(MetadataTag::ANDROID_JPEG_ORIENTATION),
        keyValue(MetadataTag::ANDROID_JPEG_QUALITY),
        keyValue(MetadataTag::ANDROID_LENS_OPTICAL_STABILIZATION_MODE),
        keyValue(MetadataTag::ANDROID_NOISE_REDUCTION_MODE),
        keyValue(MetadataTag::ANDROID_REQUEST_ID),
        keyValue(MetadataTag::ANDROID_SCALER_CROP_REGION),
        keyValue(MetadataTag::ANDROID_SENSOR_TEST_PATTERN_MODE),
        keyValue(MetadataTag::ANDROID_STATISTICS_FACE_DETECT_MODE),
        keyValue(MetadataTag::ANDROID_STATISTICS_HOT_PIXEL_MAP_MODE),
};

constexpr std::array<int32_t, 36> kAvailableResultKeys = {
        keyValue(MetadataTag::ANDROID_COLOR_CORRECTION_ABERRATION_MODE),
        keyValue(MetadataTag::ANDROID_CONTROL_AE_ANTIBANDING_MODE),
        keyValue(MetadataTag::ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION),
        keyValue(MetadataTag::ANDROID_CONTROL_AE_LOCK),
        keyValue(MetadataTag::ANDROID_CONTROL_AE_MODE),
        keyValue(MetadataTag::ANDROID_CONTROL_AE_TARGET_FPS_RANGE),
        keyValue(MetadataTag::ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER),
        keyValue(MetadataTag::ANDROID_CONTROL_AF_MODE),
        keyValue(MetadataTag::ANDROID_CONTROL_AF_TRIGGER),
        keyValue(MetadataTag::ANDROID_CONTROL_AWB_LOCK),
        keyValue(MetadataTag::ANDROID_CONTROL_AWB_MODE),
        keyValue(MetadataTag::ANDROID_CONTROL_CAPTURE_INTENT),
        keyValue(MetadataTag::ANDROID_CONTROL_EFFECT_MODE),
        keyValue(MetadataTag::ANDROID_CONTROL_MODE),
        keyValue(MetadataTag::ANDROID_CONTROL_SCENE_MODE),
        keyValue(MetadataTag::ANDROID_CONTROL_VIDEO_STABILIZATION_MODE),
        keyValue(MetadataTag::ANDROID_CONTROL_AE_STATE),
        keyValue(MetadataTag::ANDROID_CONTROL_AF_STATE),
        keyValue(MetadataTag::ANDROID_CONTROL_AWB_STATE),
        keyValue(MetadataTag::ANDROID_FLASH_MODE),
        keyValue(MetadataTag::ANDROID_FLASH_STATE),
        keyValue(MetadataTag::ANDROID_JPEG_ORIENTATION),
        keyValue(MetadataTag::ANDROID_JPEG_QUALITY),
        keyValue(MetadataTag::ANDROID_LENS_OPTICAL_STABILIZATION_MODE),
        keyValue(MetadataTag::ANDROID_LENS_STATE),
        keyValue(MetadataTag::ANDROID_NOISE_REDUCTION_MODE),
        keyValue(MetadataTag::ANDROID_REQUEST_ID),
        keyValue(MetadataTag::ANDROID_REQUEST_PIPELINE_DEPTH),
        keyValue(MetadataTag::ANDROID_SCALER_CROP_REGION),
        keyValue(MetadataTag::ANDROID_SENSOR_EXPOSURE_TIME),
        keyValue(MetadataTag::ANDROID_SENSOR_FRAME_DURATION),
        keyValue(MetadataTag::ANDROID_SENSOR_SENSITIVITY),
        keyValue(MetadataTag::ANDROID_SENSOR_TIMESTAMP),
        keyValue(MetadataTag::ANDROID_SENSOR_TEST_PATTERN_MODE),
        keyValue(MetadataTag::ANDROID_STATISTICS_FACE_DETECT_MODE),
        keyValue(MetadataTag::ANDROID_STATISTICS_HOT_PIXEL_MAP_MODE),
};

template <size_t N>
constexpr bool keysAreStrictlyIncreasing(const std::array<int32_t, N>& keys) {
    for (size_t index = 1; index < keys.size(); ++index) {
        if (keys[index - 1] >= keys[index]) return false;
    }
    return true;
}

template <size_t RequestCount, size_t ResultCount>
constexpr bool requestKeysAreResultKeys(
        const std::array<int32_t, RequestCount>& requestKeys,
        const std::array<int32_t, ResultCount>& resultKeys) {
    for (const int32_t requestKey : requestKeys) {
        bool found = false;
        for (const int32_t resultKey : resultKeys) {
            if (requestKey == resultKey) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

static_assert(keysAreStrictlyIncreasing(kAvailableRequestKeys));
static_assert(keysAreStrictlyIncreasing(kAvailableResultKeys));
static_assert(requestKeysAreResultKeys(kAvailableRequestKeys, kAvailableResultKeys));


bool validateSettings(const RequestSettings& settings, std::string* error) {
    const auto byteInRange = [](uint8_t value, uint8_t maximum) {
        return value <= maximum;
    };
    const auto unsupported = [error](const char* name, uint8_t value) {
        return fail(error, std::string(name) + " value " +
                           std::to_string(static_cast<unsigned int>(value)) +
                           " is unsupported");
    };
    if (!byteInRange(settings.captureIntent, 6)) {
        return fail(error, "capture intent is out of range");
    }
    if (settings.controlMode > 1) return unsupported("control mode", settings.controlMode);
    if (settings.aeMode != 1) return unsupported("AE mode", settings.aeMode);
    if (settings.aeAntibandingMode > 3) {
        return unsupported("AE antibanding mode", settings.aeAntibandingMode);
    }
    if (settings.aeLock > 1) return unsupported("AE lock", settings.aeLock);
    if (settings.aePrecaptureTrigger > 2) {
        return unsupported("AE precapture trigger", settings.aePrecaptureTrigger);
    }
    if (settings.afMode > 1) return unsupported("AF mode", settings.afMode);
    if (settings.afTrigger > 2) return unsupported("AF trigger", settings.afTrigger);
    if (settings.awbMode != 1) return unsupported("AWB mode", settings.awbMode);
    if (settings.awbLock > 1) return unsupported("AWB lock", settings.awbLock);
    if (settings.effectMode != 0) return unsupported("effect mode", settings.effectMode);
    if (settings.sceneMode != 0) return unsupported("scene mode", settings.sceneMode);
    if (settings.videoStabilizationMode != 0) {
        return unsupported("video stabilization mode", settings.videoStabilizationMode);
    }
    if (settings.flashMode != 0) return unsupported("flash mode", settings.flashMode);
    if (settings.aberrationMode != 0) {
        return unsupported("aberration mode", settings.aberrationMode);
    }
    if (settings.noiseReductionMode != 0) {
        return unsupported("noise reduction mode", settings.noiseReductionMode);
    }
    if (settings.lensOpticalStabilizationMode != 0) {
        return unsupported("optical stabilization mode",
                           settings.lensOpticalStabilizationMode);
    }
    if (settings.faceDetectMode != 0) {
        return unsupported("face detect mode", settings.faceDetectMode);
    }
    if (settings.hotPixelMapMode != 0) {
        return unsupported("hot-pixel map mode", settings.hotPixelMapMode);
    }
    if (settings.testPatternMode != 0) {
        return unsupported("test-pattern mode", settings.testPatternMode);
    }
    if (settings.aeExposureCompensation != 0) {
        return fail(error, "exposure compensation is unsupported");
    }
    if (settings.aeTargetFpsRange != std::array<int32_t, 2>{15, 30} &&
        settings.aeTargetFpsRange != std::array<int32_t, 2>{30, 30}) {
        return fail(error, "target frame-rate range is unsupported");
    }

    if (settings.cropRegion != std::array<int32_t, 4>{0, 0, 1920, 1080}) {
        return fail(error, "crop region must match the uncropped active array");
    }
    if (settings.jpegOrientation != 0 && settings.jpegOrientation != 90 &&
        settings.jpegOrientation != 180 && settings.jpegOrientation != 270) {
        return fail(error, "JPEG orientation must be a right angle");
    }
    if (settings.jpegQuality < 1 || settings.jpegQuality > 100) {
        return fail(error, "JPEG quality is out of range");
    }
    return true;
}

void addImplementedControls(MetadataBuilder* builder, const RequestSettings& settings) {
    builder->addOne(MetadataTag::ANDROID_COLOR_CORRECTION_ABERRATION_MODE,
                    settings.aberrationMode);
    builder->addOne(MetadataTag::ANDROID_CONTROL_AE_ANTIBANDING_MODE,
                    settings.aeAntibandingMode);
    builder->addOne(MetadataTag::ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION,
                    settings.aeExposureCompensation);
    builder->addOne(MetadataTag::ANDROID_CONTROL_AE_LOCK, settings.aeLock);
    builder->addOne(MetadataTag::ANDROID_CONTROL_AE_MODE, settings.aeMode);
    builder->add(MetadataTag::ANDROID_CONTROL_AE_TARGET_FPS_RANGE,
                 settings.aeTargetFpsRange);
    builder->addOne(MetadataTag::ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER,
                    settings.aePrecaptureTrigger);
    builder->addOne(MetadataTag::ANDROID_CONTROL_AF_MODE, settings.afMode);
    builder->addOne(MetadataTag::ANDROID_CONTROL_AF_TRIGGER, settings.afTrigger);
    builder->addOne(MetadataTag::ANDROID_CONTROL_AWB_LOCK, settings.awbLock);
    builder->addOne(MetadataTag::ANDROID_CONTROL_AWB_MODE, settings.awbMode);
    builder->addOne(MetadataTag::ANDROID_CONTROL_CAPTURE_INTENT, settings.captureIntent);
    builder->addOne(MetadataTag::ANDROID_CONTROL_EFFECT_MODE, settings.effectMode);
    builder->addOne(MetadataTag::ANDROID_CONTROL_MODE, settings.controlMode);
    builder->addOne(MetadataTag::ANDROID_CONTROL_SCENE_MODE, settings.sceneMode);
    builder->addOne(MetadataTag::ANDROID_CONTROL_VIDEO_STABILIZATION_MODE,
                    settings.videoStabilizationMode);
    builder->addOne(MetadataTag::ANDROID_FLASH_MODE, settings.flashMode);
    builder->addOne(MetadataTag::ANDROID_JPEG_ORIENTATION, settings.jpegOrientation);
    builder->addOne(MetadataTag::ANDROID_JPEG_QUALITY, settings.jpegQuality);
    builder->addOne(MetadataTag::ANDROID_LENS_OPTICAL_STABILIZATION_MODE,
                    settings.lensOpticalStabilizationMode);
    builder->addOne(MetadataTag::ANDROID_NOISE_REDUCTION_MODE,
                    settings.noiseReductionMode);
    builder->addOne(MetadataTag::ANDROID_REQUEST_ID, settings.requestId);
    builder->add(MetadataTag::ANDROID_SCALER_CROP_REGION, settings.cropRegion);
    builder->addOne<int32_t>(MetadataTag::ANDROID_SENSOR_TEST_PATTERN_MODE,
                             settings.testPatternMode);
    builder->addOne(MetadataTag::ANDROID_STATISTICS_FACE_DETECT_MODE,
                    settings.faceDetectMode);
    builder->addOne(MetadataTag::ANDROID_STATISTICS_HOT_PIXEL_MAP_MODE,
                    settings.hotPixelMapMode);
}

class CheckedMetadata {
public:
    CheckedMetadata() = default;
    ~CheckedMetadata() {
        if (metadata_ != nullptr) free_camera_metadata(metadata_);
    }

    bool copyFrom(const CameraMetadata& source, std::string* error) {
        if (source.metadata.empty()) return fail(error, "camera metadata is empty");
        metadata_ = allocate_copy_camera_metadata_checked(
                reinterpret_cast<const camera_metadata_t*>(source.metadata.data()),
                source.metadata.size());
        if (metadata_ == nullptr) {
            return fail(error, "camera metadata structure is malformed");
        }
        return true;
    }

    const camera_metadata_t* get() const { return metadata_; }

private:
    camera_metadata_t* metadata_ = nullptr;
};

enum class ParsedField : size_t {
    AberrationMode,
    AeAntibandingMode,
    AeExposureCompensation,
    AeLock,
    AeMode,
    AeTargetFpsRange,
    AePrecaptureTrigger,
    AfMode,
    AfTrigger,
    AwbLock,
    AwbMode,
    CaptureIntent,
    EffectMode,
    ControlMode,
    SceneMode,
    VideoStabilizationMode,
    FlashMode,
    JpegOrientation,
    JpegQuality,
    LensOpticalStabilizationMode,
    NoiseReductionMode,
    RequestId,
    CropRegion,
    TestPatternMode,
    FaceDetectMode,
    HotPixelMapMode,
    Count,
};

bool claimEntry(std::array<bool, static_cast<size_t>(ParsedField::Count)>* seen,
                ParsedField field, const camera_metadata_ro_entry_t& entry,
                uint8_t expectedType, size_t expectedCount, std::string* error) {
    const size_t index = static_cast<size_t>(field);
    if ((*seen)[index]) return fail(error, "duplicate camera metadata control");
    (*seen)[index] = true;
    if (entry.type != expectedType || entry.count != expectedCount) {
        return fail(error, "camera metadata control has the wrong type or count");
    }
    return true;
}


}  // namespace

bool buildStaticMetadata(bool frontFacing, CameraMetadata* output, std::string* error) {
    if (error != nullptr) error->clear();
    if (output == nullptr) return fail(error, "null static metadata output");
    output->metadata.clear();

    MetadataBuilder builder;
    std::vector<int32_t> characteristicKeys;
    characteristicKeys.reserve(64);

    const std::array<uint8_t, 1> offModes = {0};
    const std::array<uint8_t, 2> controlModes = {0, 1};
    const std::array<uint8_t, 2> afModes = {0, 1};
    const std::array<uint8_t, 4> aeAntibandingModes = {0, 1, 2, 3};
    const std::array<uint8_t, 1> aeModes = {1};
    const std::array<uint8_t, 1> awbModes = {1};
    const std::array<int32_t, 3> maxRegions = {0, 0, 0};
    const std::array<int32_t, 2> aeCompensationRange = {0, 0};
    const camera_metadata_rational_t aeCompensationStep = {0, 1};
    const std::array<int32_t, 2> thumbnailSizes = {0, 0};
    const std::array<int32_t, 4> fpsRanges = {15, 30, 30, 30};
    const std::array<int32_t, 3> maxOutputStreams = {0, 2, 1};
    const std::array<int32_t, 4> activeArray = {0, 0, 1920, 1080};
    const std::array<int32_t, 2> pixelArray = {1920, 1080};
    const std::array<int32_t, 1> testPatterns = {0};
    const std::array<float, 2> physicalSize = {5.76f, 4.29f};
    const std::array<float, 1> focalLengths = {4.38f};
    const std::array<float, 1> maximumDigitalZoom = {1.0f};
    const std::array<int32_t, 2> sensitivityRange = {50, 800};
    const std::array<int64_t, 2> exposureTimeRange = {100'000LL, 66'666'666LL};
    const std::array<uint8_t, 1> capabilities = {0};  // BACKWARD_COMPATIBLE

    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_COLOR_CORRECTION_AVAILABLE_ABERRATION_MODES,
                      offModes);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_CONTROL_AE_AVAILABLE_ANTIBANDING_MODES,
                      aeAntibandingModes);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_CONTROL_AE_AVAILABLE_MODES, aeModes);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES,
                      fpsRanges);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_CONTROL_AE_COMPENSATION_RANGE,
                      aeCompensationRange);
    addCharacteristicOne(&builder, &characteristicKeys,
                         MetadataTag::ANDROID_CONTROL_AE_COMPENSATION_STEP,
                         aeCompensationStep);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_CONTROL_AF_AVAILABLE_MODES, afModes);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_CONTROL_AVAILABLE_EFFECTS, offModes);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_CONTROL_AVAILABLE_SCENE_MODES, offModes);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_CONTROL_AVAILABLE_VIDEO_STABILIZATION_MODES,
                      offModes);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_CONTROL_AWB_AVAILABLE_MODES, awbModes);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_CONTROL_MAX_REGIONS, maxRegions);
    addCharacteristicOne<uint8_t>(&builder, &characteristicKeys,
                                  MetadataTag::ANDROID_CONTROL_AE_LOCK_AVAILABLE, 1);
    addCharacteristicOne<uint8_t>(&builder, &characteristicKeys,
                                  MetadataTag::ANDROID_CONTROL_AWB_LOCK_AVAILABLE, 1);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_CONTROL_AVAILABLE_MODES, controlModes);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_EDGE_AVAILABLE_EDGE_MODES, offModes);
    addCharacteristicOne<uint8_t>(&builder, &characteristicKeys,
                                  MetadataTag::ANDROID_FLASH_INFO_AVAILABLE, 0);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_HOT_PIXEL_AVAILABLE_HOT_PIXEL_MODES,
                      offModes);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_JPEG_AVAILABLE_THUMBNAIL_SIZES,
                      thumbnailSizes);
    addCharacteristicOne<int32_t>(&builder, &characteristicKeys,
                                  MetadataTag::ANDROID_JPEG_MAX_SIZE, 13 * 1024 * 1024);
    addCharacteristicOne<uint8_t>(&builder, &characteristicKeys,
                                  MetadataTag::ANDROID_LENS_FACING,
                                  frontFacing ? 0 : 1);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_LENS_INFO_AVAILABLE_FOCAL_LENGTHS,
                      focalLengths);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_LENS_INFO_AVAILABLE_OPTICAL_STABILIZATION,
                      offModes);
    addCharacteristicOne<float>(&builder, &characteristicKeys,
                                MetadataTag::ANDROID_LENS_INFO_MINIMUM_FOCUS_DISTANCE,
                                0.1f);
    addCharacteristicOne<uint8_t>(&builder, &characteristicKeys,
                                  MetadataTag::ANDROID_LENS_INFO_FOCUS_DISTANCE_CALIBRATION,
                                  1);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_NOISE_REDUCTION_AVAILABLE_NOISE_REDUCTION_MODES,
                      offModes);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_REQUEST_MAX_NUM_OUTPUT_STREAMS,
                      maxOutputStreams);
    addCharacteristicOne<int32_t>(&builder, &characteristicKeys,
                                  MetadataTag::ANDROID_REQUEST_MAX_NUM_INPUT_STREAMS, 0);
    addCharacteristicOne<uint8_t>(&builder, &characteristicKeys,
                                  MetadataTag::ANDROID_REQUEST_PIPELINE_MAX_DEPTH, 4);
    addCharacteristicOne<int32_t>(&builder, &characteristicKeys,
                                  MetadataTag::ANDROID_REQUEST_PARTIAL_RESULT_COUNT, 1);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_REQUEST_AVAILABLE_CAPABILITIES,
                      capabilities);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS,
                      kAvailableRequestKeys);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_REQUEST_AVAILABLE_RESULT_KEYS,
                      kAvailableResultKeys);
    addEmptyCharacteristic<int32_t>(
            &builder, &characteristicKeys,
            MetadataTag::ANDROID_REQUEST_AVAILABLE_SESSION_KEYS);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_SCALER_AVAILABLE_MAX_DIGITAL_ZOOM,
                      maximumDigitalZoom);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
                      kStreamConfigurations);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS,
                      kMinFrameDurations);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_SCALER_AVAILABLE_STALL_DURATIONS,
                      kStallDurations);
    addCharacteristicOne<uint8_t>(&builder, &characteristicKeys,
                                  MetadataTag::ANDROID_SCALER_CROPPING_TYPE, 0);
    addCharacteristicOne<int32_t>(&builder, &characteristicKeys,
                                  MetadataTag::ANDROID_SENSOR_ORIENTATION,
                                  frontFacing ? 270 : 90);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_SENSOR_AVAILABLE_TEST_PATTERN_MODES,
                      testPatterns);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE, activeArray);
    addCharacteristicOne<int64_t>(&builder, &characteristicKeys,
                                  MetadataTag::ANDROID_SENSOR_INFO_MAX_FRAME_DURATION,
                                  66'666'666LL);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_SENSOR_INFO_PHYSICAL_SIZE, physicalSize);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE, pixelArray);
    addCharacteristicOne<uint8_t>(&builder, &characteristicKeys,
                                  MetadataTag::ANDROID_SENSOR_INFO_TIMESTAMP_SOURCE, 1);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE,
                      activeArray);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_SENSOR_INFO_SENSITIVITY_RANGE,
                      sensitivityRange);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_SENSOR_INFO_EXPOSURE_TIME_RANGE,
                      exposureTimeRange);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_SHADING_AVAILABLE_MODES, offModes);
    addCharacteristic(&builder, &characteristicKeys,
                      MetadataTag::ANDROID_STATISTICS_INFO_AVAILABLE_FACE_DETECT_MODES,
                      offModes);
    addCharacteristicOne<int32_t>(&builder, &characteristicKeys,
                                  MetadataTag::ANDROID_STATISTICS_INFO_MAX_FACE_COUNT, 0);
    addCharacteristic(
            &builder, &characteristicKeys,
            MetadataTag::ANDROID_STATISTICS_INFO_AVAILABLE_HOT_PIXEL_MAP_MODES,
            offModes);
    addCharacteristic(
            &builder, &characteristicKeys,
            MetadataTag::ANDROID_STATISTICS_INFO_AVAILABLE_LENS_SHADING_MAP_MODES,
            offModes);
    addCharacteristicOne<uint8_t>(&builder, &characteristicKeys,
                                  MetadataTag::ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL, 0);
    addCharacteristicOne<int32_t>(&builder, &characteristicKeys,
                                  MetadataTag::ANDROID_SYNC_MAX_LATENCY, -1);

    addCharacteristicKeyList(&builder, &characteristicKeys);
    return builder.finish(output, error);
}

bool buildDefaultRequest(RequestTemplate requestTemplate, CameraMetadata* output,
                         std::string* error) {
    if (error != nullptr) error->clear();
    if (output == nullptr) return fail(error, "null default request output");
    output->metadata.clear();

    RequestSettings settings;
    switch (requestTemplate) {
        case RequestTemplate::PREVIEW:
            settings.captureIntent = 1;
            break;
        case RequestTemplate::STILL_CAPTURE:
            settings.captureIntent = 2;
            break;
        case RequestTemplate::VIDEO_RECORD:
            settings.captureIntent = 3;
            break;
        case RequestTemplate::VIDEO_SNAPSHOT:
            settings.captureIntent = 4;
            break;
        case RequestTemplate::ZERO_SHUTTER_LAG:
            settings.captureIntent = 5;
            break;
        case RequestTemplate::MANUAL:
            settings.captureIntent = 6;
            settings.controlMode = 0;
            settings.afMode = 0;
            break;
        default:
            return fail(error, "unsupported default request template");
    }

    if (!validateSettings(settings, error)) return false;
    MetadataBuilder builder;
    addImplementedControls(&builder, settings);
    return builder.finish(output, error);
}

bool parseRequestSettings(const CameraMetadata& metadata,
                          const RequestSettings* previous,
                          RequestSettings* output, std::string* error) {
    if (error != nullptr) error->clear();
    if (output == nullptr) return fail(error, "null parsed request output");
    if (metadata.metadata.empty()) {
        if (previous == nullptr) {
            return fail(error, "empty request settings have no previous settings");
        }
        if (!validateSettings(*previous, error)) return false;
        *output = *previous;
        return true;
    }

    CheckedMetadata checked;
    if (!checked.copyFrom(metadata, error)) return false;

    RequestSettings parsed;
    std::array<bool, static_cast<size_t>(ParsedField::Count)> seen{};
    const size_t entryCount = get_camera_metadata_entry_count(checked.get());
    for (size_t index = 0; index < entryCount; ++index) {
        camera_metadata_ro_entry_t entry{};
        if (get_camera_metadata_ro_entry(checked.get(), index, &entry) != 0) {
            return fail(error, "unable to read validated camera metadata entry");
        }
        const int declaredType = get_camera_metadata_tag_type(entry.tag);
        if (declaredType < 0 || entry.type != static_cast<uint8_t>(declaredType)) {
            return fail(error, "camera metadata contains an unknown or mistyped tag");
        }

        switch (entry.tag) {
            case tagValue(MetadataTag::ANDROID_COLOR_CORRECTION_ABERRATION_MODE):
                if (!claimEntry(&seen, ParsedField::AberrationMode, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.aberrationMode = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_CONTROL_AE_ANTIBANDING_MODE):
                if (!claimEntry(&seen, ParsedField::AeAntibandingMode, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.aeAntibandingMode = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION):
                if (!claimEntry(&seen, ParsedField::AeExposureCompensation, entry,
                                CAMERA_METADATA_TYPE_INT32, 1, error)) return false;
                parsed.aeExposureCompensation = entry.data.i32[0];
                break;
            case tagValue(MetadataTag::ANDROID_CONTROL_AE_LOCK):
                if (!claimEntry(&seen, ParsedField::AeLock, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.aeLock = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_CONTROL_AE_MODE):
                if (!claimEntry(&seen, ParsedField::AeMode, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.aeMode = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_CONTROL_AE_TARGET_FPS_RANGE):
                if (!claimEntry(&seen, ParsedField::AeTargetFpsRange, entry,
                                CAMERA_METADATA_TYPE_INT32, 2, error)) return false;
                std::copy_n(entry.data.i32, 2, parsed.aeTargetFpsRange.begin());
                break;
            case tagValue(MetadataTag::ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER):
                if (!claimEntry(&seen, ParsedField::AePrecaptureTrigger, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.aePrecaptureTrigger = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_CONTROL_AF_MODE):
                if (!claimEntry(&seen, ParsedField::AfMode, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.afMode = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_CONTROL_AF_TRIGGER):
                if (!claimEntry(&seen, ParsedField::AfTrigger, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.afTrigger = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_CONTROL_AWB_LOCK):
                if (!claimEntry(&seen, ParsedField::AwbLock, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.awbLock = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_CONTROL_AWB_MODE):
                if (!claimEntry(&seen, ParsedField::AwbMode, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.awbMode = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_CONTROL_CAPTURE_INTENT):
                if (!claimEntry(&seen, ParsedField::CaptureIntent, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.captureIntent = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_CONTROL_EFFECT_MODE):
                if (!claimEntry(&seen, ParsedField::EffectMode, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.effectMode = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_CONTROL_MODE):
                if (!claimEntry(&seen, ParsedField::ControlMode, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.controlMode = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_CONTROL_SCENE_MODE):
                if (!claimEntry(&seen, ParsedField::SceneMode, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.sceneMode = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_CONTROL_VIDEO_STABILIZATION_MODE):
                if (!claimEntry(&seen, ParsedField::VideoStabilizationMode, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.videoStabilizationMode = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_FLASH_MODE):
                if (!claimEntry(&seen, ParsedField::FlashMode, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.flashMode = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_JPEG_ORIENTATION):
                if (!claimEntry(&seen, ParsedField::JpegOrientation, entry,
                                CAMERA_METADATA_TYPE_INT32, 1, error)) return false;
                parsed.jpegOrientation = entry.data.i32[0];
                break;
            case tagValue(MetadataTag::ANDROID_JPEG_QUALITY):
                if (!claimEntry(&seen, ParsedField::JpegQuality, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.jpegQuality = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_LENS_OPTICAL_STABILIZATION_MODE):
                if (!claimEntry(&seen, ParsedField::LensOpticalStabilizationMode,
                                entry, CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.lensOpticalStabilizationMode = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_NOISE_REDUCTION_MODE):
                if (!claimEntry(&seen, ParsedField::NoiseReductionMode, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.noiseReductionMode = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_REQUEST_ID):
                if (!claimEntry(&seen, ParsedField::RequestId, entry,
                                CAMERA_METADATA_TYPE_INT32, 1, error)) return false;
                parsed.requestId = entry.data.i32[0];
                break;
            case tagValue(MetadataTag::ANDROID_SCALER_CROP_REGION):
                if (!claimEntry(&seen, ParsedField::CropRegion, entry,
                                CAMERA_METADATA_TYPE_INT32, 4, error)) return false;
                std::copy_n(entry.data.i32, 4, parsed.cropRegion.begin());
                break;
            case tagValue(MetadataTag::ANDROID_SENSOR_TEST_PATTERN_MODE):
                if (!claimEntry(&seen, ParsedField::TestPatternMode, entry,
                                CAMERA_METADATA_TYPE_INT32, 1, error)) return false;
                if (entry.data.i32[0] < 0 || entry.data.i32[0] > 255) {
                    return fail(error, "test-pattern mode is out of range");
                }
                parsed.testPatternMode = static_cast<uint8_t>(entry.data.i32[0]);
                break;
            case tagValue(MetadataTag::ANDROID_STATISTICS_FACE_DETECT_MODE):
                if (!claimEntry(&seen, ParsedField::FaceDetectMode, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.faceDetectMode = entry.data.u8[0];
                break;
            case tagValue(MetadataTag::ANDROID_STATISTICS_HOT_PIXEL_MAP_MODE):
                if (!claimEntry(&seen, ParsedField::HotPixelMapMode, entry,
                                CAMERA_METADATA_TYPE_BYTE, 1, error)) return false;
                parsed.hotPixelMapMode = entry.data.u8[0];
                break;
            default:
                // Recognized but unadvertised standard tags are safely ignored. The
                // framework may add internal request bookkeeping tags.
                break;
        }
    }

    if (!validateSettings(parsed, error)) return false;
    *output = std::move(parsed);
    return true;
}

bool buildResultMetadata(const RequestSettings& settings, const FrameTiming& timing,
                         CameraMetadata* output, std::string* error) {
    if (error != nullptr) error->clear();
    if (output == nullptr) return fail(error, "null result metadata output");
    output->metadata.clear();
    if (!validateSettings(settings, error)) return false;
    if (timing.timestampNs < 0 || timing.frameDurationNs <= 0 ||
        timing.frameDurationNs > 66'666'666LL || timing.exposureTimeNs < 100'000LL ||
        timing.exposureTimeNs > timing.frameDurationNs || timing.sensitivity < 50 ||
        timing.sensitivity > 800 || timing.pipelineDepth == 0 ||
        timing.pipelineDepth > 4) {
        return fail(error, "frame timing is outside advertised limits");
    }

    MetadataBuilder builder;
    addImplementedControls(&builder, settings);

    const uint8_t aeState = settings.controlMode == 0 ? 0 :
            (settings.aeLock == 1 ? 3 : 2);  // inactive/locked/converged
    const uint8_t afState =
            settings.controlMode == 0 || settings.afMode == 0 || settings.afTrigger == 2
                    ? 0
                    : (settings.afTrigger == 1 ? 4 : 0);  // focused-locked/inactive
    const uint8_t awbState = settings.controlMode == 0 ? 0 :
            (settings.awbLock == 1 ? 3 : 2);  // inactive/locked/converged
    builder.addOne(MetadataTag::ANDROID_CONTROL_AE_STATE, aeState);
    builder.addOne(MetadataTag::ANDROID_CONTROL_AF_STATE, afState);
    builder.addOne(MetadataTag::ANDROID_CONTROL_AWB_STATE, awbState);
    builder.addOne<uint8_t>(MetadataTag::ANDROID_FLASH_STATE, 0);  // unavailable
    builder.addOne<uint8_t>(MetadataTag::ANDROID_LENS_STATE, 0);   // stationary
    builder.addOne(MetadataTag::ANDROID_REQUEST_PIPELINE_DEPTH,
                   timing.pipelineDepth);
    builder.addOne(MetadataTag::ANDROID_SENSOR_EXPOSURE_TIME,
                   timing.exposureTimeNs);
    builder.addOne(MetadataTag::ANDROID_SENSOR_FRAME_DURATION,
                   timing.frameDurationNs);
    builder.addOne(MetadataTag::ANDROID_SENSOR_SENSITIVITY, timing.sensitivity);
    builder.addOne(MetadataTag::ANDROID_SENSOR_TIMESTAMP, timing.timestampNs);
    return builder.finish(output, error);
}

}  // namespace camera_provider
