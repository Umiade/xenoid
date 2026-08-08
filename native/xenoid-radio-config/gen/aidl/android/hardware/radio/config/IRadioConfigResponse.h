/*
 * This file is auto-generated.  DO NOT MODIFY.
 */
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <aidl/android/hardware/radio/RadioResponseInfo.h>
#include <aidl/android/hardware/radio/config/PhoneCapability.h>
#include <aidl/android/hardware/radio/config/SimSlotStatus.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl::android::hardware::radio {
class RadioResponseInfo;
}  // namespace aidl::android::hardware::radio
namespace aidl::android::hardware::radio::config {
class PhoneCapability;
class SimSlotStatus;
}  // namespace aidl::android::hardware::radio::config
namespace aidl {
namespace android {
namespace hardware {
namespace radio {
namespace config {
class IRadioConfigResponseDelegator;

class IRadioConfigResponse : public ::ndk::ICInterface {
public:
  typedef IRadioConfigResponseDelegator DefaultDelegator;
  static const char* descriptor;
  IRadioConfigResponse();
  virtual ~IRadioConfigResponse();

  static inline const int32_t version = 1;
  static inline const std::string hash = "dd9c3f8e21930f9b4c46a4125bd5f5cec90318ec";
  static constexpr uint32_t TRANSACTION_getHalDeviceCapabilitiesResponse = FIRST_CALL_TRANSACTION + 0;
  static constexpr uint32_t TRANSACTION_getNumOfLiveModemsResponse = FIRST_CALL_TRANSACTION + 1;
  static constexpr uint32_t TRANSACTION_getPhoneCapabilityResponse = FIRST_CALL_TRANSACTION + 2;
  static constexpr uint32_t TRANSACTION_getSimSlotsStatusResponse = FIRST_CALL_TRANSACTION + 3;
  static constexpr uint32_t TRANSACTION_setNumOfLiveModemsResponse = FIRST_CALL_TRANSACTION + 4;
  static constexpr uint32_t TRANSACTION_setPreferredDataModemResponse = FIRST_CALL_TRANSACTION + 5;
  static constexpr uint32_t TRANSACTION_setSimSlotsMappingResponse = FIRST_CALL_TRANSACTION + 6;

  static std::shared_ptr<IRadioConfigResponse> fromBinder(const ::ndk::SpAIBinder& binder);
  static binder_status_t writeToParcel(AParcel* parcel, const std::shared_ptr<IRadioConfigResponse>& instance);
  static binder_status_t readFromParcel(const AParcel* parcel, std::shared_ptr<IRadioConfigResponse>* instance);
  static bool setDefaultImpl(const std::shared_ptr<IRadioConfigResponse>& impl);
  static const std::shared_ptr<IRadioConfigResponse>& getDefaultImpl();
  virtual ::ndk::ScopedAStatus getHalDeviceCapabilitiesResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info, bool in_modemReducedFeatureSet1) = 0;
  virtual ::ndk::ScopedAStatus getNumOfLiveModemsResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info, int8_t in_numOfLiveModems) = 0;
  virtual ::ndk::ScopedAStatus getPhoneCapabilityResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info, const ::aidl::android::hardware::radio::config::PhoneCapability& in_phoneCapability) = 0;
  virtual ::ndk::ScopedAStatus getSimSlotsStatusResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info, const std::vector<::aidl::android::hardware::radio::config::SimSlotStatus>& in_slotStatus) = 0;
  virtual ::ndk::ScopedAStatus setNumOfLiveModemsResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info) = 0;
  virtual ::ndk::ScopedAStatus setPreferredDataModemResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info) = 0;
  virtual ::ndk::ScopedAStatus setSimSlotsMappingResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) = 0;
private:
  static std::shared_ptr<IRadioConfigResponse> default_impl;
};
class IRadioConfigResponseDefault : public IRadioConfigResponse {
public:
  ::ndk::ScopedAStatus getHalDeviceCapabilitiesResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info, bool in_modemReducedFeatureSet1) override;
  ::ndk::ScopedAStatus getNumOfLiveModemsResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info, int8_t in_numOfLiveModems) override;
  ::ndk::ScopedAStatus getPhoneCapabilityResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info, const ::aidl::android::hardware::radio::config::PhoneCapability& in_phoneCapability) override;
  ::ndk::ScopedAStatus getSimSlotsStatusResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info, const std::vector<::aidl::android::hardware::radio::config::SimSlotStatus>& in_slotStatus) override;
  ::ndk::ScopedAStatus setNumOfLiveModemsResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info) override;
  ::ndk::ScopedAStatus setPreferredDataModemResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info) override;
  ::ndk::ScopedAStatus setSimSlotsMappingResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info) override;
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) override;
  ::ndk::SpAIBinder asBinder() override;
  bool isRemote() override;
};
}  // namespace config
}  // namespace radio
}  // namespace hardware
}  // namespace android
}  // namespace aidl
