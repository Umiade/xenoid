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
#include <aidl/android/hardware/radio/config/IRadioConfigIndication.h>
#include <aidl/android/hardware/radio/config/IRadioConfigResponse.h>
#include <aidl/android/hardware/radio/config/SlotPortMapping.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl::android::hardware::radio::config {
class IRadioConfigIndication;
class IRadioConfigResponse;
class SlotPortMapping;
}  // namespace aidl::android::hardware::radio::config
namespace aidl {
namespace android {
namespace hardware {
namespace radio {
namespace config {
class IRadioConfigDelegator;

class IRadioConfig : public ::ndk::ICInterface {
public:
  typedef IRadioConfigDelegator DefaultDelegator;
  static const char* descriptor;
  IRadioConfig();
  virtual ~IRadioConfig();

  static inline const int32_t version = 1;
  static inline const std::string hash = "dd9c3f8e21930f9b4c46a4125bd5f5cec90318ec";
  static constexpr uint32_t TRANSACTION_getHalDeviceCapabilities = FIRST_CALL_TRANSACTION + 0;
  static constexpr uint32_t TRANSACTION_getNumOfLiveModems = FIRST_CALL_TRANSACTION + 1;
  static constexpr uint32_t TRANSACTION_getPhoneCapability = FIRST_CALL_TRANSACTION + 2;
  static constexpr uint32_t TRANSACTION_getSimSlotsStatus = FIRST_CALL_TRANSACTION + 3;
  static constexpr uint32_t TRANSACTION_setNumOfLiveModems = FIRST_CALL_TRANSACTION + 4;
  static constexpr uint32_t TRANSACTION_setPreferredDataModem = FIRST_CALL_TRANSACTION + 5;
  static constexpr uint32_t TRANSACTION_setResponseFunctions = FIRST_CALL_TRANSACTION + 6;
  static constexpr uint32_t TRANSACTION_setSimSlotsMapping = FIRST_CALL_TRANSACTION + 7;

  static std::shared_ptr<IRadioConfig> fromBinder(const ::ndk::SpAIBinder& binder);
  static binder_status_t writeToParcel(AParcel* parcel, const std::shared_ptr<IRadioConfig>& instance);
  static binder_status_t readFromParcel(const AParcel* parcel, std::shared_ptr<IRadioConfig>* instance);
  static bool setDefaultImpl(const std::shared_ptr<IRadioConfig>& impl);
  static const std::shared_ptr<IRadioConfig>& getDefaultImpl();
  virtual ::ndk::ScopedAStatus getHalDeviceCapabilities(int32_t in_serial) = 0;
  virtual ::ndk::ScopedAStatus getNumOfLiveModems(int32_t in_serial) = 0;
  virtual ::ndk::ScopedAStatus getPhoneCapability(int32_t in_serial) = 0;
  virtual ::ndk::ScopedAStatus getSimSlotsStatus(int32_t in_serial) = 0;
  virtual ::ndk::ScopedAStatus setNumOfLiveModems(int32_t in_serial, int8_t in_numOfLiveModems) = 0;
  virtual ::ndk::ScopedAStatus setPreferredDataModem(int32_t in_serial, int8_t in_modemId) = 0;
  virtual ::ndk::ScopedAStatus setResponseFunctions(const std::shared_ptr<::aidl::android::hardware::radio::config::IRadioConfigResponse>& in_radioConfigResponse, const std::shared_ptr<::aidl::android::hardware::radio::config::IRadioConfigIndication>& in_radioConfigIndication) = 0;
  virtual ::ndk::ScopedAStatus setSimSlotsMapping(int32_t in_serial, const std::vector<::aidl::android::hardware::radio::config::SlotPortMapping>& in_slotMap) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) = 0;
private:
  static std::shared_ptr<IRadioConfig> default_impl;
};
class IRadioConfigDefault : public IRadioConfig {
public:
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
  ::ndk::SpAIBinder asBinder() override;
  bool isRemote() override;
};
}  // namespace config
}  // namespace radio
}  // namespace hardware
}  // namespace android
}  // namespace aidl
