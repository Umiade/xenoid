/*
 * This file is auto-generated.  DO NOT MODIFY.
 */
#pragma once

#include "aidl/android/hardware/radio/config/IRadioConfigResponse.h"

#include <android/binder_ibinder.h>

namespace aidl {
namespace android {
namespace hardware {
namespace radio {
namespace config {
class BpRadioConfigResponse : public ::ndk::BpCInterface<IRadioConfigResponse> {
public:
  explicit BpRadioConfigResponse(const ::ndk::SpAIBinder& binder);
  virtual ~BpRadioConfigResponse();

  ::ndk::ScopedAStatus getHalDeviceCapabilitiesResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info, bool in_modemReducedFeatureSet1) override;
  ::ndk::ScopedAStatus getNumOfLiveModemsResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info, int8_t in_numOfLiveModems) override;
  ::ndk::ScopedAStatus getPhoneCapabilityResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info, const ::aidl::android::hardware::radio::config::PhoneCapability& in_phoneCapability) override;
  ::ndk::ScopedAStatus getSimSlotsStatusResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info, const std::vector<::aidl::android::hardware::radio::config::SimSlotStatus>& in_slotStatus) override;
  ::ndk::ScopedAStatus setNumOfLiveModemsResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info) override;
  ::ndk::ScopedAStatus setPreferredDataModemResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info) override;
  ::ndk::ScopedAStatus setSimSlotsMappingResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info) override;
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
