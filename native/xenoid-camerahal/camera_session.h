#pragma once

#include <aidl/android/hardware/camera/device/BnCameraDeviceSession.h>
#include <aidl/android/hardware/camera/device/BufferCache.h>
#include <aidl/android/hardware/camera/device/CameraOfflineSessionInfo.h>
#include <aidl/android/hardware/camera/device/CaptureRequest.h>
#include <aidl/android/hardware/camera/device/HalStream.h>
#include <aidl/android/hardware/camera/device/ICameraDeviceCallback.h>
#include <aidl/android/hardware/camera/device/ICameraOfflineSession.h>
#include <aidl/android/hardware/camera/device/StreamConfiguration.h>
#include <aidl/android/hardware/common/fmq/MQDescriptor.h>
#include <aidl/android/hardware/common/fmq/SynchronizedReadWrite.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "camera_metadata.h"

namespace camera_provider {

class CameraSession final
    : public aidl::android::hardware::camera::device::BnCameraDeviceSession {
public:
    explicit CameraSession(
            const CameraProfile& profile,
            std::shared_ptr<aidl::android::hardware::camera::device::ICameraDeviceCallback>
                    callback,
            std::function<void()> onClosed) noexcept;
    ~CameraSession() override;
    bool ready() const;

    ndk::ScopedAStatus close() override;
    ndk::ScopedAStatus configureStreams(
            const aidl::android::hardware::camera::device::StreamConfiguration&
                    requestedConfiguration,
            std::vector<aidl::android::hardware::camera::device::HalStream>* out) override;
    ndk::ScopedAStatus constructDefaultRequestSettings(RequestTemplate type,
            CameraMetadata* out) override;
    ndk::ScopedAStatus flush() override;
    ndk::ScopedAStatus getCaptureRequestMetadataQueue(
            aidl::android::hardware::common::fmq::MQDescriptor<int8_t,
                    aidl::android::hardware::common::fmq::SynchronizedReadWrite>* out) override;
    ndk::ScopedAStatus getCaptureResultMetadataQueue(
            aidl::android::hardware::common::fmq::MQDescriptor<int8_t,
                    aidl::android::hardware::common::fmq::SynchronizedReadWrite>* out) override;
    ndk::ScopedAStatus isReconfigurationRequired(const CameraMetadata& oldSessionParams,
            const CameraMetadata& newSessionParams, bool* out) override;
    ndk::ScopedAStatus processCaptureRequest(
            const std::vector<aidl::android::hardware::camera::device::CaptureRequest>& requests,
            const std::vector<aidl::android::hardware::camera::device::BufferCache>&
                    cachesToRemove,
            int32_t* out) override;
    ndk::ScopedAStatus signalStreamFlush(const std::vector<int32_t>& streamIds,
            int32_t streamConfigCounter) override;
    ndk::ScopedAStatus switchToOffline(const std::vector<int32_t>& streamsToKeep,
            aidl::android::hardware::camera::device::CameraOfflineSessionInfo* offlineSessionInfo,
            std::shared_ptr<aidl::android::hardware::camera::device::ICameraOfflineSession>* out)
            override;
    ndk::ScopedAStatus repeatingRequestEnd(int32_t frameNumber,
            const std::vector<int32_t>& streamIds) override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace camera_provider
