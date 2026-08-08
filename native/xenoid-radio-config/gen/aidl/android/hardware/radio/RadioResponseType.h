/*
 * This file is auto-generated.  DO NOT MODIFY.
 */
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_enums.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace radio {
enum class RadioResponseType : int32_t {
  SOLICITED = 0,
  SOLICITED_ACK = 1,
  SOLICITED_ACK_EXP = 2,
};

}  // namespace radio
}  // namespace hardware
}  // namespace android
}  // namespace aidl
namespace aidl {
namespace android {
namespace hardware {
namespace radio {
[[nodiscard]] static inline std::string toString(RadioResponseType val) {
  switch(val) {
  case RadioResponseType::SOLICITED:
    return "SOLICITED";
  case RadioResponseType::SOLICITED_ACK:
    return "SOLICITED_ACK";
  case RadioResponseType::SOLICITED_ACK_EXP:
    return "SOLICITED_ACK_EXP";
  default:
    return std::to_string(static_cast<int32_t>(val));
  }
}
}  // namespace radio
}  // namespace hardware
}  // namespace android
}  // namespace aidl
namespace ndk {
namespace internal {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template <>
constexpr inline std::array<aidl::android::hardware::radio::RadioResponseType, 3> enum_values<aidl::android::hardware::radio::RadioResponseType> = {
  aidl::android::hardware::radio::RadioResponseType::SOLICITED,
  aidl::android::hardware::radio::RadioResponseType::SOLICITED_ACK,
  aidl::android::hardware::radio::RadioResponseType::SOLICITED_ACK_EXP,
};
#pragma clang diagnostic pop
}  // namespace internal
}  // namespace ndk
