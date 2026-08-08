#include <aidl/android/hardware/radio/RadioError.h>
#include <aidl/android/hardware/radio/RadioResponseInfo.h>
#include <aidl/android/hardware/radio/RadioResponseType.h>
#include <aidl/android/hardware/radio/config/BnRadioConfig.h>
#include <aidl/android/hardware/radio/config/IRadioConfigIndication.h>
#include <aidl/android/hardware/radio/config/IRadioConfigResponse.h>
#include <aidl/android/hardware/radio/config/PhoneCapability.h>
#include <aidl/android/hardware/radio/config/SimPortInfo.h>
#include <aidl/android/hardware/radio/config/SimSlotStatus.h>
#include <aidl/android/hardware/radio/config/SlotPortMapping.h>

extern "C" {
binder_status_t AServiceManager_addService(AIBinder*, const char*);
void ABinderProcess_setThreadPoolMaxThreadCount(uint32_t);
void ABinderProcess_joinThreadPool(void);
}
#include <android/log.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace radio = aidl::android::hardware::radio;
namespace config = aidl::android::hardware::radio::config;

namespace {
constexpr const char* kLogTag = "xenoid-radio-config";

radio::RadioResponseInfo responseInfo(int32_t serial, radio::RadioError error = radio::RadioError::NONE) {
    radio::RadioResponseInfo info;
    info.type = radio::RadioResponseType::SOLICITED;
    info.serial = serial;
    info.error = error;
    return info;
}

class RadioConfigService final : public config::BnRadioConfig {
public:
    ::ndk::ScopedAStatus getHalDeviceCapabilities(int32_t serial) override {
        auto response = responseSnapshot();
        if (!response) return notReady();
        return response->getHalDeviceCapabilitiesResponse(responseInfo(serial), false);
    }

    ::ndk::ScopedAStatus getNumOfLiveModems(int32_t serial) override {
        auto response = responseSnapshot();
        if (!response) return notReady();
        return response->getNumOfLiveModemsResponse(responseInfo(serial), 1);
    }

    ::ndk::ScopedAStatus getPhoneCapability(int32_t serial) override {
        auto response = responseSnapshot();
        if (!response) return notReady();
        config::PhoneCapability capability;
        capability.maxActiveData = 1;
        capability.maxActiveInternetData = 1;
        capability.isInternetLingeringSupported = false;
        capability.logicalModemIds = {0};
        return response->getPhoneCapabilityResponse(responseInfo(serial), capability);
    }

    ::ndk::ScopedAStatus getSimSlotsStatus(int32_t serial) override {
        auto response = responseSnapshot();
        if (!response) return notReady();
        config::SimPortInfo port;
        port.iccId = "";
        port.logicalSlotId = 0;
        port.portActive = true;
        config::SimSlotStatus slot;
        slot.cardState = 1;
        slot.atr = "3B9F96801FC7A0231200000000000000";
        slot.eid = "";
        slot.portInfo = {port};
        return response->getSimSlotsStatusResponse(responseInfo(serial), {slot});
    }

    ::ndk::ScopedAStatus setNumOfLiveModems(int32_t serial, int8_t number) override {
        auto response = responseSnapshot();
        if (!response) return notReady();
        radio::RadioError error = number == 1 ? radio::RadioError::NONE : radio::RadioError::INVALID_ARGUMENTS;
        return response->setNumOfLiveModemsResponse(responseInfo(serial, error));
    }

    ::ndk::ScopedAStatus setPreferredDataModem(int32_t serial, int8_t modemId) override {
        auto response = responseSnapshot();
        if (!response) return notReady();
        radio::RadioError error = modemId == 0 ? radio::RadioError::NONE : radio::RadioError::INVALID_ARGUMENTS;
        return response->setPreferredDataModemResponse(responseInfo(serial, error));
    }

    ::ndk::ScopedAStatus setResponseFunctions(
            const std::shared_ptr<config::IRadioConfigResponse>& response,
            const std::shared_ptr<config::IRadioConfigIndication>& indication) override {
        if (!response || !indication) {
            return ::ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        std::lock_guard<std::mutex> lock(mutex_);
        response_ = response;
        indication_ = indication;
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus setSimSlotsMapping(
            int32_t serial, const std::vector<config::SlotPortMapping>& mapping) override {
        auto response = responseSnapshot();
        if (!response) return notReady();
        bool valid = mapping.size() == 1 && mapping[0].physicalSlotId == 0 && mapping[0].portId == 0;
        radio::RadioError error = valid ? radio::RadioError::NONE : radio::RadioError::INVALID_ARGUMENTS;
        return response->setSimSlotsMappingResponse(responseInfo(serial, error));
    }

private:
    static ::ndk::ScopedAStatus notReady() {
        return ::ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
    }

    std::shared_ptr<config::IRadioConfigResponse> responseSnapshot() {
        std::lock_guard<std::mutex> lock(mutex_);
        return response_;
    }

    std::mutex mutex_;
    std::shared_ptr<config::IRadioConfigResponse> response_;
    std::shared_ptr<config::IRadioConfigIndication> indication_;
};
}  // namespace

int main() {
    ABinderProcess_setThreadPoolMaxThreadCount(1);
    auto service = ndk::SharedRefBase::make<RadioConfigService>();
    std::string instance = std::string(config::IRadioConfig::descriptor) + "/default";
    binder_status_t status = AServiceManager_addService(service->asBinder().get(), instance.c_str());
    if (status != STATUS_OK) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "registration failed: %d", status);
        return 1;
    }
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "registered %s", instance.c_str());
    ABinderProcess_joinThreadPool();
    return 1;
}
