#pragma once

#include <aidl/android/hardware/camera/device/BnCameraDevice.h>
#include <aidl/android/hardware/camera/device/HalStream.h>
#include <aidl/android/hardware/camera/device/StreamConfiguration.h>

#include <cstdint>
#include <memory>
#include <string>
#include <mutex>
#include <functional>
#include <vector>

#include "camera_metadata.h"
#include "camera_types.h"

namespace camera_provider {

struct CameraOpenState;

bool validateStreamConfiguration(
        const CameraProfile& profile,
        const aidl::android::hardware::camera::device::StreamConfiguration&
                configuration,
        bool validateStreamIds,
        std::vector<aidl::android::hardware::camera::device::HalStream>*
                halStreams,
        std::vector<StreamDescriptor>* streamDescriptors,
        std::string* error);

class CameraDevice final : public aidl::android::hardware::camera::device::BnCameraDevice {
public:
    CameraDevice(
            const CameraProfile& profile,
            std::function<void(bool, bool)> onTorchStateChanged);

    ndk::ScopedAStatus getCameraCharacteristics(CameraMetadata* out) override;
    ndk::ScopedAStatus getPhysicalCameraCharacteristics(
            const std::string& physicalCameraId, CameraMetadata* out) override;
    ndk::ScopedAStatus getResourceCost(
            aidl::android::hardware::camera::common::CameraResourceCost* out) override;
    ndk::ScopedAStatus isStreamCombinationSupported(
            const aidl::android::hardware::camera::device::StreamConfiguration& streams,
            bool* out) override;
    ndk::ScopedAStatus open(
            const std::shared_ptr<aidl::android::hardware::camera::device::ICameraDeviceCallback>&
                    callback,
            std::shared_ptr<aidl::android::hardware::camera::device::ICameraDeviceSession>* out)
            override;
    ndk::ScopedAStatus openInjectionSession(
            const std::shared_ptr<aidl::android::hardware::camera::device::ICameraDeviceCallback>&
                    callback,
            std::shared_ptr<aidl::android::hardware::camera::device::ICameraInjectionSession>* out)
            override;
    ndk::ScopedAStatus setTorchMode(bool on) override;
    ndk::ScopedAStatus turnOnTorchWithStrengthLevel(int32_t torchStrength) override;
    ndk::ScopedAStatus getTorchStrengthLevel(int32_t* out) override;

private:
    const CameraProfile& profile_;
    std::function<void(bool, bool)> onTorchStateChanged_;
    std::mutex torchMutex_;
    bool torchOn_ = false;
    std::shared_ptr<CameraOpenState> openState_;
    CameraMetadata characteristics_;
    bool metadataOk_ = false;
};

}  // namespace camera_provider
