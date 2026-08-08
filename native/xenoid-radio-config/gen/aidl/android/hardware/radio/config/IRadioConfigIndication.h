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
#include <aidl/android/hardware/radio/RadioIndicationType.h>
#include <aidl/android/hardware/radio/config/SimSlotStatus.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl::android::hardware::radio::config {
class SimSlotStatus;
}  // namespace aidl::android::hardware::radio::config
namespace aidl {
namespace android {
namespace hardware {
namespace radio {
namespace config {
class IRadioConfigIndicationDelegator;

class IRadioConfigIndication : public ::ndk::ICInterface {
public:
  typedef IRadioConfigIndicationDelegator DefaultDelegator;
  static const char* descriptor;
  IRadioConfigIndication();
  virtual ~IRadioConfigIndication();

  static inline const int32_t version = 1;
  static inline const std::string hash = "dd9c3f8e21930f9b4c46a4125bd5f5cec90318ec";
  static constexpr uint32_t TRANSACTION_simSlotsStatusChanged = FIRST_CALL_TRANSACTION + 0;

  static std::shared_ptr<IRadioConfigIndication> fromBinder(const ::ndk::SpAIBinder& binder);
  static binder_status_t writeToParcel(AParcel* parcel, const std::shared_ptr<IRadioConfigIndication>& instance);
  static binder_status_t readFromParcel(const AParcel* parcel, std::shared_ptr<IRadioConfigIndication>* instance);
  static bool setDefaultImpl(const std::shared_ptr<IRadioConfigIndication>& impl);
  static const std::shared_ptr<IRadioConfigIndication>& getDefaultImpl();
  virtual ::ndk::ScopedAStatus simSlotsStatusChanged(::aidl::android::hardware::radio::RadioIndicationType in_type, const std::vector<::aidl::android::hardware::radio::config::SimSlotStatus>& in_slotStatus) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) = 0;
private:
  static std::shared_ptr<IRadioConfigIndication> default_impl;
};
class IRadioConfigIndicationDefault : public IRadioConfigIndication {
public:
  ::ndk::ScopedAStatus simSlotsStatusChanged(::aidl::android::hardware::radio::RadioIndicationType in_type, const std::vector<::aidl::android::hardware::radio::config::SimSlotStatus>& in_slotStatus) override;
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
