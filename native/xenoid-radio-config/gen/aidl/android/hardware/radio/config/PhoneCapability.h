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
class PhoneCapability {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  int8_t maxActiveData = 0;
  int8_t maxActiveInternetData = 0;
  bool isInternetLingeringSupported = false;
  std::vector<uint8_t> logicalModemIds;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator==(const PhoneCapability& _rhs) const {
    return std::tie(maxActiveData, maxActiveInternetData, isInternetLingeringSupported, logicalModemIds) == std::tie(_rhs.maxActiveData, _rhs.maxActiveInternetData, _rhs.isInternetLingeringSupported, _rhs.logicalModemIds);
  }
  inline bool operator<(const PhoneCapability& _rhs) const {
    return std::tie(maxActiveData, maxActiveInternetData, isInternetLingeringSupported, logicalModemIds) < std::tie(_rhs.maxActiveData, _rhs.maxActiveInternetData, _rhs.isInternetLingeringSupported, _rhs.logicalModemIds);
  }
  inline bool operator!=(const PhoneCapability& _rhs) const {
    return !(*this == _rhs);
  }
  inline bool operator>(const PhoneCapability& _rhs) const {
    return _rhs < *this;
  }
  inline bool operator>=(const PhoneCapability& _rhs) const {
    return !(*this < _rhs);
  }
  inline bool operator<=(const PhoneCapability& _rhs) const {
    return !(_rhs < *this);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream _aidl_os;
    _aidl_os << "PhoneCapability{";
    _aidl_os << "maxActiveData: " << ::android::internal::ToString(maxActiveData);
    _aidl_os << ", maxActiveInternetData: " << ::android::internal::ToString(maxActiveInternetData);
    _aidl_os << ", isInternetLingeringSupported: " << ::android::internal::ToString(isInternetLingeringSupported);
    _aidl_os << ", logicalModemIds: " << ::android::internal::ToString(logicalModemIds);
    _aidl_os << "}";
    return _aidl_os.str();
  }
};
}  // namespace config
}  // namespace radio
}  // namespace hardware
}  // namespace android
}  // namespace aidl
