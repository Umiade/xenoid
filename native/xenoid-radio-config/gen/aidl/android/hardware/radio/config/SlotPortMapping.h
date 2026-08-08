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
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace radio {
namespace config {
class SlotPortMapping {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  int32_t physicalSlotId = 0;
  int32_t portId = 0;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator==(const SlotPortMapping& _rhs) const {
    return std::tie(physicalSlotId, portId) == std::tie(_rhs.physicalSlotId, _rhs.portId);
  }
  inline bool operator<(const SlotPortMapping& _rhs) const {
    return std::tie(physicalSlotId, portId) < std::tie(_rhs.physicalSlotId, _rhs.portId);
  }
  inline bool operator!=(const SlotPortMapping& _rhs) const {
    return !(*this == _rhs);
  }
  inline bool operator>(const SlotPortMapping& _rhs) const {
    return _rhs < *this;
  }
  inline bool operator>=(const SlotPortMapping& _rhs) const {
    return !(*this < _rhs);
  }
  inline bool operator<=(const SlotPortMapping& _rhs) const {
    return !(_rhs < *this);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream _aidl_os;
    _aidl_os << "SlotPortMapping{";
    _aidl_os << "physicalSlotId: " << ::android::internal::ToString(physicalSlotId);
    _aidl_os << ", portId: " << ::android::internal::ToString(portId);
    _aidl_os << "}";
    return _aidl_os.str();
  }
};
}  // namespace config
}  // namespace radio
}  // namespace hardware
}  // namespace android
}  // namespace aidl
