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
#include <android/binder_parcelable_utils.h>
#include <android/binder_to_string.h>
#include <aidl/android/hardware/radio/config/SimPortInfo.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl::android::hardware::radio::config {
class SimPortInfo;
}  // namespace aidl::android::hardware::radio::config
namespace aidl {
namespace android {
namespace hardware {
namespace radio {
namespace config {
class SimSlotStatus {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  int32_t cardState = 0;
  std::string atr;
  std::string eid;
  std::vector<::aidl::android::hardware::radio::config::SimPortInfo> portInfo;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator==(const SimSlotStatus& _rhs) const {
    return std::tie(cardState, atr, eid, portInfo) == std::tie(_rhs.cardState, _rhs.atr, _rhs.eid, _rhs.portInfo);
  }
  inline bool operator<(const SimSlotStatus& _rhs) const {
    return std::tie(cardState, atr, eid, portInfo) < std::tie(_rhs.cardState, _rhs.atr, _rhs.eid, _rhs.portInfo);
  }
  inline bool operator!=(const SimSlotStatus& _rhs) const {
    return !(*this == _rhs);
  }
  inline bool operator>(const SimSlotStatus& _rhs) const {
    return _rhs < *this;
  }
  inline bool operator>=(const SimSlotStatus& _rhs) const {
    return !(*this < _rhs);
  }
  inline bool operator<=(const SimSlotStatus& _rhs) const {
    return !(_rhs < *this);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream _aidl_os;
    _aidl_os << "SimSlotStatus{";
    _aidl_os << "cardState: " << ::android::internal::ToString(cardState);
    _aidl_os << ", atr: " << ::android::internal::ToString(atr);
    _aidl_os << ", eid: " << ::android::internal::ToString(eid);
    _aidl_os << ", portInfo: " << ::android::internal::ToString(portInfo);
    _aidl_os << "}";
    return _aidl_os.str();
  }
};
}  // namespace config
}  // namespace radio
}  // namespace hardware
}  // namespace android
}  // namespace aidl
