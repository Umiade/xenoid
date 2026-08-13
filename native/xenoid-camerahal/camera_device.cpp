#include "camera_device.h"

#include <aidl/android/hardware/camera/common/Status.h>
#include <aidl/android/hardware/camera/device/ICameraDeviceCallback.h>
#include <aidl/android/hardware/camera/device/ICameraInjectionSession.h>
#include <aidl/android/hardware/camera/device/StreamRotation.h>
#include <aidl/android/hardware/camera/device/StreamType.h>
#include <aidl/android/hardware/camera/metadata/RequestAvailableDynamicRangeProfilesMap.h>
#include <aidl/android/hardware/camera/metadata/ScalerAvailableStreamUseCases.h>
#include <aidl/android/hardware/camera/metadata/SensorPixelMode.h>
#include <aidl/android/hardware/graphics/common/BufferUsage.h>
#include <aidl/android/hardware/graphics/common/PixelFormat.h>
#include <android/log.h>

#include <array>
#include <cstdint>
#include <mutex>
#include <utility>

#include "camera_session.h"

namespace camera_provider {
namespace {

namespace camera = aidl::android::hardware::camera;
namespace graphics = aidl::android::hardware::graphics::common;
using camera::common::Status;
using camera::device::HalStream;
using camera::device::StreamConfiguration;
using ndk::ScopedAStatus;


constexpr int64_t kProducerUsage =
        static_cast<int64_t>(graphics::BufferUsage::CPU_WRITE_OFTEN) |
        static_cast<int64_t>(graphics::BufferUsage::CAMERA_OUTPUT);
constexpr int64_t kUnsupportedUsage =
        static_cast<int64_t>(graphics::BufferUsage::PROTECTED);

ScopedAStatus halError(Status status, const char* message) {
    return ScopedAStatus::fromServiceSpecificErrorWithMessage(
            static_cast<int32_t>(status), message);
}

bool fail(std::string* error, const char* message) {
    if (error != nullptr) *error = message;
    return false;
}


}  // namespace

struct CameraOpenState {
    std::mutex mutex;
    bool open = false;
    uint64_t generation = 0;
};

bool validateStreamConfiguration(const CameraProfile& profile,
        const StreamConfiguration& configuration, bool validateStreamIds,
        std::vector<HalStream>* halStreams,
        std::vector<StreamDescriptor>* streamDescriptors, std::string* error) {
    if (halStreams != nullptr) halStreams->clear();
    if (streamDescriptors != nullptr) streamDescriptors->clear();
    if (configuration.operationMode != camera::device::StreamConfigurationMode::NORMAL_MODE) {
        return fail(error, "only normal stream mode is supported");
    }
    if (configuration.multiResolutionInputImage) {
        return fail(error, "multi-resolution input is not supported");
    }
    if (configuration.streams.empty() || configuration.streams.size() > 3) {
        return fail(error, "stream count is unsupported");
    }

    size_t blobCount = 0;
    size_t nonStallingCount = 0;
    for (size_t index = 0; index < configuration.streams.size(); ++index) {
        const auto& stream = configuration.streams[index];
        if (stream.streamType != camera::device::StreamType::OUTPUT) {
            return fail(error, "input streams are not supported");
        }
        if (validateStreamIds) {
            if (stream.id < 0) return fail(error, "stream id is invalid");
            for (size_t earlier = 0; earlier < index; ++earlier) {
                if (configuration.streams[earlier].id == stream.id) {
                    return fail(error, "stream ids must be unique");
                }
            }
        }
        const int32_t requestedFormat = static_cast<int32_t>(stream.format);
        if (findCameraOutputSize(profile, requestedFormat,
                                 stream.width, stream.height) == nullptr) {
            return fail(error, "format and size tuple is not advertised");
        }
        if (requestedFormat == kBlobFormat) {
            ++blobCount;
        } else {
            ++nonStallingCount;
        }
        if (blobCount > 1 || nonStallingCount > 2) {
            return fail(error, "stream count exceeds advertised output limits");
        }
        if (stream.rotation != camera::device::StreamRotation::ROTATION_0) {
            return fail(error, "stream rotation is not supported");
        }
        if (!stream.physicalCameraId.empty()) {
            return fail(error, "physical camera streams are not supported");
        }
        if (stream.groupId != -1) {
            return fail(error, "multi-resolution output groups are not supported");
        }
        for (const auto pixelMode : stream.sensorPixelModesUsed) {
            if (pixelMode != camera::metadata::SensorPixelMode::ANDROID_SENSOR_PIXEL_MODE_DEFAULT) {
                return fail(error, "maximum-resolution sensor mode is not supported");
            }
        }
        const int64_t dynamicRange = static_cast<int64_t>(stream.dynamicRangeProfile);
        if (dynamicRange != 0 && dynamicRange != static_cast<int64_t>(
                camera::metadata::RequestAvailableDynamicRangeProfilesMap::
                        ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD)) {
            return fail(error, "dynamic range profile is not supported");
        }
        if (stream.useCase != camera::metadata::ScalerAvailableStreamUseCases::
                ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT) {
            return fail(error, "stream use case is not supported");
        }
        const int64_t consumerUsage = static_cast<int64_t>(stream.usage);
        if ((consumerUsage & kUnsupportedUsage) != 0) {
            return fail(error, "protected buffer usage is not supported");
        }

        const int32_t overrideFormat = requestedFormat == kImplementationDefinedFormat
                ? kRgba8888Format
                : requestedFormat;
        if (halStreams != nullptr) {
            HalStream halStream;
            halStream.id = stream.id;
            halStream.overrideFormat = static_cast<graphics::PixelFormat>(overrideFormat);
            halStream.producerUsage = static_cast<graphics::BufferUsage>(kProducerUsage);
            halStream.consumerUsage = static_cast<graphics::BufferUsage>(0);
            halStream.maxBuffers = 4;
            halStream.overrideDataSpace = stream.dataSpace;
            halStream.physicalCameraId.clear();
            halStream.supportOffline = false;
            halStreams->push_back(std::move(halStream));
        }
        if (streamDescriptors != nullptr) {
            StreamDescriptor descriptor;
            descriptor.id = stream.id;
            descriptor.width = stream.width;
            descriptor.height = stream.height;
            descriptor.requestedFormat = requestedFormat;
            descriptor.overrideFormat = overrideFormat;
            descriptor.usage = consumerUsage | kProducerUsage;
            descriptor.videoEncoder = (consumerUsage & static_cast<int64_t>(
                    graphics::BufferUsage::VIDEO_ENCODER)) != 0;
            streamDescriptors->push_back(std::move(descriptor));
        }
    }
    if (error != nullptr) error->clear();
    return true;
}

CameraDevice::CameraDevice(
        const CameraProfile& profile,
        std::function<void(bool, bool)> onTorchStateChanged)
    : profile_(profile),
      onTorchStateChanged_(std::move(onTorchStateChanged)),
      openState_(std::make_shared<CameraOpenState>()) {
    std::string error;
    metadataOk_ = buildStaticMetadata(profile_, &characteristics_, &error);
}

ScopedAStatus CameraDevice::getCameraCharacteristics(CameraMetadata* out) {
    if (!metadataOk_) return halError(Status::INTERNAL_ERROR, "metadata build failed");
    *out = characteristics_;
    return ScopedAStatus::ok();
}

ScopedAStatus CameraDevice::getPhysicalCameraCharacteristics(
        const std::string&, CameraMetadata* out) {
    out->metadata.clear();
    return halError(Status::ILLEGAL_ARGUMENT, "no physical sub-camera");
}

ScopedAStatus CameraDevice::getResourceCost(camera::common::CameraResourceCost* out) {
    out->resourceCost = 50;
    out->conflictingDevices.clear();
    return ScopedAStatus::ok();
}

ScopedAStatus CameraDevice::isStreamCombinationSupported(
        const StreamConfiguration& streams, bool* out) {
    std::string error;
    *out = validateStreamConfiguration(
            profile_, streams, false, nullptr, nullptr, &error);
    if (!*out) {
        __android_log_print(ANDROID_LOG_WARN, "camera-provider",
                "unsupported stream combination: %s; %s", error.c_str(),
                streams.toString().c_str());
    }
    return ScopedAStatus::ok();
}

ScopedAStatus CameraDevice::open(
        const std::shared_ptr<camera::device::ICameraDeviceCallback>& callback,
        std::shared_ptr<camera::device::ICameraDeviceSession>* out) {
    out->reset();
    if (callback == nullptr) {
        return halError(Status::ILLEGAL_ARGUMENT, "camera callback is null");
    }
    if (!metadataOk_) {
        return halError(Status::INTERNAL_ERROR, "metadata build failed");
    }
    uint64_t openGeneration = 0;
    {
        std::lock_guard<std::mutex> lock(openState_->mutex);
        if (openState_->open) {
            return halError(Status::CAMERA_IN_USE, "camera is already open");
        }
        openState_->open = true;
        openGeneration = ++openState_->generation;
    }
    {
        std::lock_guard<std::mutex> lock(torchMutex_);
        torchOn_ = false;
    }
    if (profile_.flashAvailable && onTorchStateChanged_) {
        onTorchStateChanged_(true, false);
    }

    const std::weak_ptr<CameraOpenState> weakState = openState_;
    try {
        const auto onTorchStateChanged = onTorchStateChanged_;
        const bool flashAvailable = profile_.flashAvailable;
        auto session = ndk::SharedRefBase::make<CameraSession>(
                profile_, callback,
                [weakState, openGeneration, onTorchStateChanged,
                 flashAvailable] {
                    bool closed = false;
                    if (const auto state = weakState.lock()) {
                        std::lock_guard<std::mutex> lock(state->mutex);
                        if (state->generation == openGeneration &&
                            state->open) {
                            state->open = false;
                            closed = true;
                        }
                    }
                    if (closed && flashAvailable &&
                        onTorchStateChanged) {
                        onTorchStateChanged(false, false);
                    }
                });
        if (!session->ready()) {
            session.reset();
            std::lock_guard<std::mutex> lock(openState_->mutex);
            if (openState_->generation == openGeneration) {
                openState_->open = false;
            }
            if (profile_.flashAvailable && onTorchStateChanged_) {
                onTorchStateChanged_(false, false);
            }
            return halError(Status::INTERNAL_ERROR, "camera session initialization failed");
        }
        *out = std::move(session);
    } catch (...) {
        std::lock_guard<std::mutex> lock(openState_->mutex);
        if (openState_->generation == openGeneration) {
            openState_->open = false;
        }
        if (profile_.flashAvailable && onTorchStateChanged_) {
            onTorchStateChanged_(false, false);
        }
        return halError(Status::INTERNAL_ERROR, "camera session creation failed");
    }
    return ScopedAStatus::ok();
}

ScopedAStatus CameraDevice::openInjectionSession(
        const std::shared_ptr<camera::device::ICameraDeviceCallback>&,
        std::shared_ptr<camera::device::ICameraInjectionSession>* out) {
    out->reset();
    return halError(Status::OPERATION_NOT_SUPPORTED, "operation is not supported");
}

ScopedAStatus CameraDevice::setTorchMode(bool on) {
    if (!profile_.flashAvailable) {
        return halError(Status::OPERATION_NOT_SUPPORTED,
                        "flash is not available");
    }
    {
        std::lock_guard<std::mutex> openLock(openState_->mutex);
        if (openState_->open) {
            return halError(Status::CAMERA_IN_USE, "camera is open");
        }
    }
    {
        std::lock_guard<std::mutex> torchLock(torchMutex_);
        torchOn_ = on;
    }
    if (onTorchStateChanged_) onTorchStateChanged_(false, on);
    return ScopedAStatus::ok();
}

ScopedAStatus CameraDevice::turnOnTorchWithStrengthLevel(
        int32_t torchStrength) {
    if (!profile_.flashAvailable) {
        return halError(Status::OPERATION_NOT_SUPPORTED,
                        "flash is not available");
    }
    if (torchStrength != 1) {
        return halError(Status::ILLEGAL_ARGUMENT,
                        "torch strength must be one");
    }
    return setTorchMode(true);
}

ScopedAStatus CameraDevice::getTorchStrengthLevel(int32_t* out) {
    *out = 0;
    if (!profile_.flashAvailable) {
        return halError(Status::OPERATION_NOT_SUPPORTED,
                        "flash is not available");
    }
    *out = 1;
    return ScopedAStatus::ok();
}

}  // namespace camera_provider
