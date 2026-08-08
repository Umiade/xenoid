/*
 * This file is auto-generated.  DO NOT MODIFY.
 */
#pragma once

#include "aidl/android/hardware/radio/config/IRadioConfig.h"

#include <android/binder_ibinder.h>

namespace aidl {
namespace android {
namespace hardware {
namespace radio {
namespace config {
class BpRadioConfig : public ::ndk::BpCInterface<IRadioConfig> {
public:
  explicit BpRadioConfig(const ::ndk::SpAIBinder& binder);
  virtual ~BpRadioConfig();

  ::ndk::ScopedAStatus getHalDeviceCapabilities(int32_t in_serial) override;
  ::ndk::ScopedAStatus getNumOfLiveModems(int32_t in_serial) override;
  ::ndk::ScopedAStatus getPhoneCapability(int32_t in_serial) override;
  ::ndk::ScopedAStatus getSimSlotsStatus(int32_t in_serial) override;
  ::ndk::ScopedAStatus setNumOfLiveModems(int32_t in_serial, int8_t in_numOfLiveModems) override;
  ::ndk::ScopedAStatus setPreferredDataModem(int32_t in_serial, int8_t in_modemId) override;
  ::ndk::ScopedAStatus setResponseFunctions(const std::shared_ptr<::aidl::android::hardware::radio::config::IRadioConfigResponse>& in_radioConfigResponse, const std::shared_ptr<::aidl::android::hardware::radio::config::IRadioConfigIndication>& in_radioConfigIndication) override;
  ::ndk::ScopedAStatus setSimSlotsMapping(int32_t in_serial, const std::vector<::aidl::android::hardware::radio::config::SlotPortMapping>& in_slotMap) override;
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) override;
  int32_t _aidl_cached_version = -1;
  std::string _aidl_cached_hash = "-1";
  std::mutex _aidl_cached_hash_mutex;
};
}  // namespace config
}  // namespace radio
}  // namespace hardware
}  // namespace android
}  // namespace aidl
