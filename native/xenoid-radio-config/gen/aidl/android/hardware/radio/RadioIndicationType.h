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
enum class RadioIndicationType : int32_t {
  UNSOLICITED = 0,
  UNSOLICITED_ACK_EXP = 1,
};

}  // namespace radio
}  // namespace hardware
}  // namespace android
}  // namespace aidl
namespace aidl {
namespace android {
namespace hardware {
namespace radio {
[[nodiscard]] static inline std::string toString(RadioIndicationType val) {
  switch(val) {
  case RadioIndicationType::UNSOLICITED:
    return "UNSOLICITED";
  case RadioIndicationType::UNSOLICITED_ACK_EXP:
    return "UNSOLICITED_ACK_EXP";
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
constexpr inline std::array<aidl::android::hardware::radio::RadioIndicationType, 2> enum_values<aidl::android::hardware::radio::RadioIndicationType> = {
  aidl::android::hardware::radio::RadioIndicationType::UNSOLICITED,
  aidl::android::hardware::radio::RadioIndicationType::UNSOLICITED_ACK_EXP,
};
#pragma clang diagnostic pop
}  // namespace internal
}  // namespace ndk
