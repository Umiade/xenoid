#include <aidl/android/hardware/camera/common/Status.h>
#include <aidl/android/hardware/camera/common/VendorTagSection.h>
#include <aidl/android/hardware/camera/provider/BnCameraProvider.h>
#include <aidl/android/hardware/camera/common/TorchModeStatus.h>
#include <aidl/android/hardware/camera/provider/CameraIdAndStreamCombination.h>
#include <aidl/android/hardware/camera/provider/ConcurrentCameraIdCombination.h>
#include <aidl/android/hardware/camera/provider/ICameraProviderCallback.h>
#include <android/binder_status.h>
#include <android/log.h>

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "camera_device.h"

struct AIBinder;
extern "C" {
binder_status_t AServiceManager_addService(AIBinder*, const char*);
void ABinderProcess_startThreadPool(void);
void ABinderProcess_joinThreadPool(void);
}

namespace camera_provider {
namespace {

namespace camera = aidl::android::hardware::camera;
using camera::common::Status;
using ndk::ScopedAStatus;

constexpr const char* kBackDeviceName = "device@1.0/internal/0";
constexpr const char* kFrontDeviceName = "device@1.0/internal/1";
constexpr const char* kServiceName =
        "android.hardware.camera.provider.ICameraProvider/internal/0";

ScopedAStatus halError(Status status, const char* message) {
    return ScopedAStatus::fromServiceSpecificErrorWithMessage(
            static_cast<int32_t>(status), message);
}

class CameraProvider final : public camera::provider::BnCameraProvider {
public:
    CameraProvider()
        : backDevice_(ndk::SharedRefBase::make<CameraDevice>(
                  kCameraProfiles[0],
                  [this](bool inUse, bool on) {
                      reportRearTorch(inUse, on);
                  })),
          frontDevice_(ndk::SharedRefBase::make<CameraDevice>(
                  kCameraProfiles[1],
                  std::function<void(bool, bool)>{})) {}

    ScopedAStatus setCallback(
            const std::shared_ptr<camera::provider::ICameraProviderCallback>& callback) override {
        if (callback == nullptr) {
            return halError(Status::ILLEGAL_ARGUMENT,
                            "camera provider callback is null");
        }
        std::lock_guard<std::mutex> lock(mutex_);
        callback_ = callback;
        return ScopedAStatus::ok();
    }

    void reportRearTorch(bool inUse, bool on) {
        std::shared_ptr<camera::provider::ICameraProviderCallback> callback;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            callback = callback_;
        }
        if (callback != nullptr) {
            callback->torchModeStatusChange(
                    kBackDeviceName,
                    inUse ? camera::common::TorchModeStatus::NOT_AVAILABLE
                          : on ? camera::common::TorchModeStatus::AVAILABLE_ON
                               : camera::common::TorchModeStatus::AVAILABLE_OFF);
        }
    }

    ScopedAStatus getVendorTags(std::vector<camera::common::VendorTagSection>* out) override {
        out->clear();
        return ScopedAStatus::ok();
    }

    ScopedAStatus getCameraIdList(std::vector<std::string>* out) override {
        *out = {kBackDeviceName, kFrontDeviceName};
        return ScopedAStatus::ok();
    }

    ScopedAStatus getCameraDeviceInterface(const std::string& name,
            std::shared_ptr<camera::device::ICameraDevice>* out) override {
        if (name == kBackDeviceName) {
            *out = backDevice_;
        } else if (name == kFrontDeviceName) {
            *out = frontDevice_;
        } else {
            out->reset();
            return halError(Status::ILLEGAL_ARGUMENT, "unknown camera name");
        }
        return ScopedAStatus::ok();
    }

    ScopedAStatus notifyDeviceStateChange(int64_t) override {
        return ScopedAStatus::ok();
    }

    ScopedAStatus getConcurrentCameraIds(
            std::vector<camera::provider::ConcurrentCameraIdCombination>* out) override {
        out->clear();
        return ScopedAStatus::ok();
    }

    ScopedAStatus isConcurrentStreamCombinationSupported(
            const std::vector<camera::provider::CameraIdAndStreamCombination>&,
            bool* out) override {
        *out = false;
        return ScopedAStatus::ok();
    }

private:
    std::shared_ptr<CameraDevice> backDevice_;
    std::shared_ptr<CameraDevice> frontDevice_;
    std::shared_ptr<camera::provider::ICameraProviderCallback> callback_;
    std::mutex mutex_;
};

}  // namespace

int runCameraProvider() {
    ABinderProcess_startThreadPool();
    auto provider = ndk::SharedRefBase::make<CameraProvider>();
    const binder_status_t status = AServiceManager_addService(
            provider->asBinder().get(), kServiceName);
    if (status != STATUS_OK) {
        __android_log_print(ANDROID_LOG_ERROR, "camera-provider",
                "addService(%s) failed: %d", kServiceName, status);
        return 1;
    }
    __android_log_print(ANDROID_LOG_INFO, "camera-provider",
            "registered %s with %s and %s", kServiceName,
            kBackDeviceName, kFrontDeviceName);
    ABinderProcess_joinThreadPool();
    return 0;
}

}  // namespace camera_provider

int main() {
    return camera_provider::runCameraProvider();
}
