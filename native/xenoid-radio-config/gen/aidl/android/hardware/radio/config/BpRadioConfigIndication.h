/*
 * This file is auto-generated.  DO NOT MODIFY.
 */
#pragma once

#include "aidl/android/hardware/radio/config/IRadioConfigIndication.h"

#include <android/binder_ibinder.h>

namespace aidl {
namespace android {
namespace hardware {
namespace radio {
namespace config {
class BpRadioConfigIndication : public ::ndk::BpCInterface<IRadioConfigIndication> {
public:
  explicit BpRadioConfigIndication(const ::ndk::SpAIBinder& binder);
  virtual ~BpRadioConfigIndication();

  ::ndk::ScopedAStatus simSlotsStatusChanged(::aidl::android::hardware::radio::RadioIndicationType in_type, const std::vector<::aidl::android::hardware::radio::config::SimSlotStatus>& in_slotStatus) override;
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
