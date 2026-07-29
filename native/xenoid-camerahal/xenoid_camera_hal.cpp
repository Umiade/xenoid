#include <aidl/android/hardware/camera/provider/BnCameraProvider.h>
#include <aidl/android/hardware/camera/provider/ICameraProviderCallback.h>
#include <aidl/android/hardware/camera/provider/CameraIdAndStreamCombination.h>
#include <aidl/android/hardware/camera/provider/ConcurrentCameraIdCombination.h>
#include <aidl/android/hardware/camera/device/BnCameraDevice.h>
#include <aidl/android/hardware/camera/device/CameraMetadata.h>
#include <aidl/android/hardware/camera/device/StreamConfiguration.h>
#include <aidl/android/hardware/camera/device/ICameraDeviceCallback.h>
#include <aidl/android/hardware/camera/device/ICameraDeviceSession.h>
#include <aidl/android/hardware/camera/device/ICameraInjectionSession.h>
#include <aidl/android/hardware/camera/common/CameraResourceCost.h>
#include <aidl/android/hardware/camera/common/Status.h>
#include <aidl/android/hardware/camera/common/VendorTagSection.h>
#include <android/binder_status.h>
#include <android/log.h>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

struct AIBinder;
extern "C" {
binder_status_t AServiceManager_addService(AIBinder*, const char*);
void ABinderProcess_startThreadPool(void);
void ABinderProcess_joinThreadPool(void);
}

namespace cam = aidl::android::hardware::camera;
using cam::common::Status;
using ndk::ScopedAStatus;

struct camera_metadata;
using camera_metadata_t = camera_metadata;
extern "C" camera_metadata_t* allocate_camera_metadata(size_t entry_capacity, size_t data_capacity);
extern "C" void free_camera_metadata(camera_metadata_t* metadata);
extern "C" int add_camera_metadata_entry(camera_metadata_t* dst, uint32_t tag,
                                           const void* data, size_t data_count);
extern "C" size_t get_camera_metadata_size(const camera_metadata_t* metadata);
struct CameraMetadataRational {
    int32_t numerator;
    int32_t denominator;
};

static constexpr const char* kBackDeviceName = "device@1.0/internal/0";
static constexpr const char* kFrontDeviceName = "device@1.0/internal/1";
static constexpr const char* kServiceName =
        "android.hardware.camera.provider.ICameraProvider/internal/0";

static ScopedAStatus halError(Status status, const char* message) {
    return ScopedAStatus::fromServiceSpecificErrorWithMessage(
            static_cast<int32_t>(status), message);
}

class MetadataBuilder {
public:
    MetadataBuilder() : data_(allocate_camera_metadata(128, 8192)) {}
    ~MetadataBuilder() { if (data_) free_camera_metadata(data_); }

    template <typename T>
    void add(uint32_t tag, const T* values, size_t count) {
        if (!data_ || add_camera_metadata_entry(data_, tag, values, count) != 0) {
            ok_ = false;
            return;
        }
        characteristicTags_.push_back(static_cast<int32_t>(tag));
    }

    template <typename T, size_t N>
    void add(uint32_t tag, const T (&values)[N]) { add(tag, values, N); }

    template <typename T>
    void addOne(uint32_t tag, T value) { add(tag, &value, 1); }

    bool finish(cam::device::CameraMetadata* out) {
        static constexpr uint32_t kAvailableCharacteristicsKeys = 0x000c000f;
        characteristicTags_.push_back(static_cast<int32_t>(kAvailableCharacteristicsKeys));
        std::sort(characteristicTags_.begin(), characteristicTags_.end());
        characteristicTags_.erase(
                std::unique(characteristicTags_.begin(), characteristicTags_.end()),
                characteristicTags_.end());
        if (!data_ || add_camera_metadata_entry(data_, kAvailableCharacteristicsKeys,
                characteristicTags_.data(), characteristicTags_.size()) != 0) {
            ok_ = false;
        }
        if (!ok_) return false;
        const size_t size = get_camera_metadata_size(data_);
        const auto* begin = reinterpret_cast<const uint8_t*>(data_);
        out->metadata.assign(begin, begin + size);
        return true;
    }

private:
    camera_metadata_t* data_ = nullptr;
    std::vector<int32_t> characteristicTags_;
    bool ok_ = true;
};

static bool buildCharacteristics(bool frontFacing, cam::device::CameraMetadata* out) {
    MetadataBuilder m;
    const uint8_t zero8[] = {0};
    const uint8_t controlModes[] = {0, 1};
    const uint8_t afModes[] = {0, 1};
    const uint8_t aeAntibanding[] = {0, 1, 2, 3};
    const uint8_t aeModes[] = {1};
    const uint8_t awbModes[] = {1};
    const int32_t maxRegions[] = {0, 0, 0};
    const int32_t aeCompensationRange[] = {0, 0};
    const CameraMetadataRational aeCompensationStep = {0, 1};
    const int32_t thumbnailSizes[] = {0, 0, 176, 144, 240, 160, 320, 240};
    const int32_t fpsRanges[] = {15, 30, 30, 30};
    const int32_t maxOutputStreams[] = {0, 3, 1};
    const int32_t activeArray[] = {0, 0, 1920, 1080};
    const int32_t pixelArray[] = {1920, 1080};
    const int32_t testPatterns[] = {0};
    const int32_t streamConfigs[] = {
        0x21, 1920, 1080, 0, 0x23, 1920, 1080, 0, 0x22, 1920, 1080, 0,
        0x21, 1280,  720, 0, 0x23, 1280,  720, 0, 0x22, 1280,  720, 0,
        0x21,  640,  480, 0, 0x23,  640,  480, 0, 0x22,  640,  480, 0,
    };
    const int64_t minFrameDurations[] = {
        0x21, 1920, 1080, 33333333LL, 0x23, 1920, 1080, 33333333LL,
        0x22, 1920, 1080, 33333333LL, 0x21, 1280, 720, 33333333LL,
        0x23, 1280, 720, 33333333LL, 0x22, 1280, 720, 33333333LL,
        0x21, 640, 480, 33333333LL, 0x23, 640, 480, 33333333LL,
        0x22, 640, 480, 33333333LL,
    };
    const int64_t stallDurations[] = {
        0x21, 1920, 1080, 100000000LL, 0x23, 1920, 1080, 0,
        0x22, 1920, 1080, 0, 0x21, 1280, 720, 70000000LL,
        0x23, 1280, 720, 0, 0x22, 1280, 720, 0,
        0x21, 640, 480, 40000000LL, 0x23, 640, 480, 0,
        0x22, 640, 480, 0,
    };
    const float physicalSize[] = {5.76f, 4.29f};
    const float focalLengths[] = {4.38f};
    const float oneFloat[] = {1.0f};
    const int32_t requestKeys[] = {
        0x00000003, 0x00010000, 0x00010001, 0x00010002, 0x00010003,
        0x00010005, 0x00010006, 0x00010007, 0x00010009, 0x0001000a,
        0x0001000b, 0x0001000d, 0x0001000e, 0x0001000f, 0x00010010,
        0x00010011, 0x00040002, 0x00070003, 0x00070004, 0x00070005,
        0x00070006, 0x00080004, 0x000a0000, 0x000d0000, 0x000e0018,
        0x00110000, 0x00110003,
    };
    const int32_t resultKeys[] = {
        0x00000003, 0x00010000, 0x00010001, 0x00010002, 0x00010003,
        0x00010005, 0x00010006, 0x00010007, 0x00010009, 0x0001000a,
        0x0001000b, 0x0001000d, 0x0001000e, 0x0001000f, 0x00010010,
        0x00010011, 0x0001001f, 0x00010020, 0x00010022, 0x00040002,
        0x00040005, 0x00070003, 0x00070004, 0x00070005, 0x00070006,
        0x00080004, 0x000a0000, 0x000c0009, 0x000d0000, 0x000e0010,
        0x00110000, 0x00110003, 0x0011000e, 0x00110010,
    };

    m.add(0x00000004, zero8);                  // aberration modes: off
    m.add(0x00010012, aeAntibanding);
    m.add(0x00010013, aeModes);
    m.add(0x00010014, fpsRanges);
    m.add(0x00010015, aeCompensationRange);
    m.addOne(0x00010016, aeCompensationStep);   // rational 0/1
    m.add(0x00010017, afModes);
    m.add(0x00010018, zero8);                   // effects: off
    m.add(0x00010019, zero8);                   // scenes: disabled
    m.add(0x0001001a, zero8);                   // video stabilization: off
    m.add(0x0001001b, awbModes);
    m.add(0x0001001c, maxRegions);
    m.addOne<uint8_t>(0x00010024, 0);           // AE lock unavailable
    m.addOne<uint8_t>(0x00010025, 0);           // AWB lock unavailable
    m.add(0x00010026, controlModes);
    m.add(0x00030002, zero8);                   // edge modes: off
    m.addOne<uint8_t>(0x00050000, 0);           // no flash
    m.add(0x00060001, zero8);                   // hot pixel modes: off
    m.add(0x00070007, thumbnailSizes);
    m.addOne<int32_t>(0x00070008, 13 * 1024 * 1024);
    m.addOne<uint8_t>(0x00080005, frontFacing ? 0 : 1);
    m.add(0x00090002, focalLengths);
    m.add(0x00090003, zero8);                   // OIS off
    m.addOne<float>(0x00090005, 0.1f);
    m.addOne<uint8_t>(0x00090007, 1);           // approximate focus calibration
    m.add(0x000a0002, zero8);                   // noise reduction: off
    m.add(0x000c0006, maxOutputStreams);
    m.addOne<int32_t>(0x000c0008, 0);
    m.addOne<uint8_t>(0x000c000a, 4);
    m.addOne<int32_t>(0x000c000b, 1);
    m.addOne<uint8_t>(0x000c000c, 0);           // backward compatible
    m.add(0x000c000d, requestKeys);
    m.add(0x000c000e, resultKeys);
    m.add(0x000d0004, oneFloat);
    m.add(0x000d000a, streamConfigs);
    m.add(0x000d000b, minFrameDurations);
    m.add(0x000d000c, stallDurations);
    m.addOne<uint8_t>(0x000d000d, 0);           // center-only crop
    m.addOne<int32_t>(0x000e000e, frontFacing ? 270 : 90);
    m.add(0x000e0019, testPatterns);
    m.add(0x000f0000, activeArray);
    m.addOne<int64_t>(0x000f0004, 66666666LL);
    m.add(0x000f0005, physicalSize);
    m.add(0x000f0006, pixelArray);
    m.addOne<uint8_t>(0x000f0008, 0);
    m.add(0x000f000a, activeArray);
    m.add(0x00100002, zero8);                   // shading modes: off
    m.add(0x00120000, zero8);                   // face detection: off
    m.addOne<int32_t>(0x00120002, 0);
    m.add(0x00120006, zero8);
    m.add(0x00120007, zero8);
    m.addOne<uint8_t>(0x00150000, 0);           // LIMITED
    m.addOne<int32_t>(0x00170001, -1);          // sync latency unknown
    return m.finish(out);
}

class XenoidCameraDevice final : public cam::device::BnCameraDevice {
public:
    explicit XenoidCameraDevice(bool frontFacing) {
        metadataOk_ = buildCharacteristics(frontFacing, &characteristics_);
    }

    ScopedAStatus getCameraCharacteristics(cam::device::CameraMetadata* out) override {
        if (!metadataOk_) return halError(Status::INTERNAL_ERROR, "metadata build failed");
        *out = characteristics_;
        return ScopedAStatus::ok();
    }
    ScopedAStatus getPhysicalCameraCharacteristics(const std::string&,
            cam::device::CameraMetadata*) override {
        return halError(Status::ILLEGAL_ARGUMENT, "no physical sub-camera");
    }
    ScopedAStatus getResourceCost(cam::common::CameraResourceCost* out) override {
        out->resourceCost = 50;
        out->conflictingDevices.clear();
        return ScopedAStatus::ok();
    }
    ScopedAStatus isStreamCombinationSupported(
            const cam::device::StreamConfiguration&, bool* out) override {
        *out = false;
        return ScopedAStatus::ok();
    }
    ScopedAStatus open(const std::shared_ptr<cam::device::ICameraDeviceCallback>&,
            std::shared_ptr<cam::device::ICameraDeviceSession>* out) override {
        out->reset();
        return halError(Status::OPERATION_NOT_SUPPORTED, "capture not implemented");
    }
    ScopedAStatus openInjectionSession(
            const std::shared_ptr<cam::device::ICameraDeviceCallback>&,
            std::shared_ptr<cam::device::ICameraInjectionSession>* out) override {
        out->reset();
        return halError(Status::OPERATION_NOT_SUPPORTED, "injection not supported");
    }
    ScopedAStatus setTorchMode(bool) override {
        return halError(Status::OPERATION_NOT_SUPPORTED, "no flash");
    }
    ScopedAStatus turnOnTorchWithStrengthLevel(int32_t) override {
        return halError(Status::OPERATION_NOT_SUPPORTED, "no flash");
    }
    ScopedAStatus getTorchStrengthLevel(int32_t* out) override {
        *out = 0;
        return halError(Status::OPERATION_NOT_SUPPORTED, "no flash");
    }

private:
    cam::device::CameraMetadata characteristics_;
    bool metadataOk_ = false;
};

class XenoidCameraProvider final : public cam::provider::BnCameraProvider {
public:
    XenoidCameraProvider()
        : backDevice_(ndk::SharedRefBase::make<XenoidCameraDevice>(false)),
          frontDevice_(ndk::SharedRefBase::make<XenoidCameraDevice>(true)) {}

    ScopedAStatus setCallback(
            const std::shared_ptr<cam::provider::ICameraProviderCallback>& callback) override {
        std::lock_guard<std::mutex> lock(mutex_);
        callback_ = callback;
        return ScopedAStatus::ok();
    }
    ScopedAStatus getVendorTags(std::vector<cam::common::VendorTagSection>* out) override {
        out->clear();
        return ScopedAStatus::ok();
    }
    ScopedAStatus getCameraIdList(std::vector<std::string>* out) override {
        *out = {kBackDeviceName, kFrontDeviceName};
        return ScopedAStatus::ok();
    }
    ScopedAStatus getCameraDeviceInterface(const std::string& name,
            std::shared_ptr<cam::device::ICameraDevice>* out) override {
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
            std::vector<cam::provider::ConcurrentCameraIdCombination>* out) override {
        out->clear();
        return ScopedAStatus::ok();
    }
    ScopedAStatus isConcurrentStreamCombinationSupported(
            const std::vector<cam::provider::CameraIdAndStreamCombination>&,
            bool* out) override {
        *out = false;
        return ScopedAStatus::ok();
    }

private:
    std::shared_ptr<XenoidCameraDevice> backDevice_;
    std::shared_ptr<XenoidCameraDevice> frontDevice_;
    std::shared_ptr<cam::provider::ICameraProviderCallback> callback_;
    std::mutex mutex_;
};

int main() {
    ABinderProcess_startThreadPool();
    auto provider = ndk::SharedRefBase::make<XenoidCameraProvider>();
    const binder_status_t status = AServiceManager_addService(
            provider->asBinder().get(), kServiceName);
    if (status != STATUS_OK) {
        __android_log_print(ANDROID_LOG_ERROR, "xenoid-camerahal",
                "addService(%s) failed: %d", kServiceName, status);
        return 1;
    }
    __android_log_print(ANDROID_LOG_INFO, "xenoid-camerahal",
            "registered %s with %s and %s",
            kServiceName, kBackDeviceName, kFrontDeviceName);
    ABinderProcess_joinThreadPool();
    return 0;
}
