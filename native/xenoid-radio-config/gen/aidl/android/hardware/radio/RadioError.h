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
enum class RadioError : int32_t {
  NONE = 0,
  RADIO_NOT_AVAILABLE = 1,
  GENERIC_FAILURE = 2,
  PASSWORD_INCORRECT = 3,
  SIM_PIN2 = 4,
  SIM_PUK2 = 5,
  REQUEST_NOT_SUPPORTED = 6,
  CANCELLED = 7,
  OP_NOT_ALLOWED_DURING_VOICE_CALL = 8,
  OP_NOT_ALLOWED_BEFORE_REG_TO_NW = 9,
  SMS_SEND_FAIL_RETRY = 10,
  SIM_ABSENT = 11,
  SUBSCRIPTION_NOT_AVAILABLE = 12,
  MODE_NOT_SUPPORTED = 13,
  FDN_CHECK_FAILURE = 14,
  ILLEGAL_SIM_OR_ME = 15,
  MISSING_RESOURCE = 16,
  NO_SUCH_ELEMENT = 17,
  DIAL_MODIFIED_TO_USSD = 18,
  DIAL_MODIFIED_TO_SS = 19,
  DIAL_MODIFIED_TO_DIAL = 20,
  USSD_MODIFIED_TO_DIAL = 21,
  USSD_MODIFIED_TO_SS = 22,
  USSD_MODIFIED_TO_USSD = 23,
  SS_MODIFIED_TO_DIAL = 24,
  SS_MODIFIED_TO_USSD = 25,
  SUBSCRIPTION_NOT_SUPPORTED = 26,
  SS_MODIFIED_TO_SS = 27,
  LCE_NOT_SUPPORTED = 36,
  NO_MEMORY = 37,
  INTERNAL_ERR = 38,
  SYSTEM_ERR = 39,
  MODEM_ERR = 40,
  INVALID_STATE = 41,
  NO_RESOURCES = 42,
  SIM_ERR = 43,
  INVALID_ARGUMENTS = 44,
  INVALID_SIM_STATE = 45,
  INVALID_MODEM_STATE = 46,
  INVALID_CALL_ID = 47,
  NO_SMS_TO_ACK = 48,
  NETWORK_ERR = 49,
  REQUEST_RATE_LIMITED = 50,
  SIM_BUSY = 51,
  SIM_FULL = 52,
  NETWORK_REJECT = 53,
  OPERATION_NOT_ALLOWED = 54,
  EMPTY_RECORD = 55,
  INVALID_SMS_FORMAT = 56,
  ENCODING_ERR = 57,
  INVALID_SMSC_ADDRESS = 58,
  NO_SUCH_ENTRY = 59,
  NETWORK_NOT_READY = 60,
  NOT_PROVISIONED = 61,
  NO_SUBSCRIPTION = 62,
  NO_NETWORK_FOUND = 63,
  DEVICE_IN_USE = 64,
  ABORTED = 65,
  INVALID_RESPONSE = 66,
  OEM_ERROR_1 = 501,
  OEM_ERROR_2 = 502,
  OEM_ERROR_3 = 503,
  OEM_ERROR_4 = 504,
  OEM_ERROR_5 = 505,
  OEM_ERROR_6 = 506,
  OEM_ERROR_7 = 507,
  OEM_ERROR_8 = 508,
  OEM_ERROR_9 = 509,
  OEM_ERROR_10 = 510,
  OEM_ERROR_11 = 511,
  OEM_ERROR_12 = 512,
  OEM_ERROR_13 = 513,
  OEM_ERROR_14 = 514,
  OEM_ERROR_15 = 515,
  OEM_ERROR_16 = 516,
  OEM_ERROR_17 = 517,
  OEM_ERROR_18 = 518,
  OEM_ERROR_19 = 519,
  OEM_ERROR_20 = 520,
  OEM_ERROR_21 = 521,
  OEM_ERROR_22 = 522,
  OEM_ERROR_23 = 523,
  OEM_ERROR_24 = 524,
  OEM_ERROR_25 = 525,
  SIMULTANEOUS_SMS_AND_CALL_NOT_ALLOWED = 67,
  ACCESS_BARRED = 68,
  BLOCKED_DUE_TO_CALL = 69,
  RF_HARDWARE_ISSUE = 70,
  NO_RF_CALIBRATION_INFO = 71,
};

}  // namespace radio
}  // namespace hardware
}  // namespace android
}  // namespace aidl
namespace aidl {
namespace android {
namespace hardware {
namespace radio {
[[nodiscard]] static inline std::string toString(RadioError val) {
  switch(val) {
  case RadioError::NONE:
    return "NONE";
  case RadioError::RADIO_NOT_AVAILABLE:
    return "RADIO_NOT_AVAILABLE";
  case RadioError::GENERIC_FAILURE:
    return "GENERIC_FAILURE";
  case RadioError::PASSWORD_INCORRECT:
    return "PASSWORD_INCORRECT";
  case RadioError::SIM_PIN2:
    return "SIM_PIN2";
  case RadioError::SIM_PUK2:
    return "SIM_PUK2";
  case RadioError::REQUEST_NOT_SUPPORTED:
    return "REQUEST_NOT_SUPPORTED";
  case RadioError::CANCELLED:
    return "CANCELLED";
  case RadioError::OP_NOT_ALLOWED_DURING_VOICE_CALL:
    return "OP_NOT_ALLOWED_DURING_VOICE_CALL";
  case RadioError::OP_NOT_ALLOWED_BEFORE_REG_TO_NW:
    return "OP_NOT_ALLOWED_BEFORE_REG_TO_NW";
  case RadioError::SMS_SEND_FAIL_RETRY:
    return "SMS_SEND_FAIL_RETRY";
  case RadioError::SIM_ABSENT:
    return "SIM_ABSENT";
  case RadioError::SUBSCRIPTION_NOT_AVAILABLE:
    return "SUBSCRIPTION_NOT_AVAILABLE";
  case RadioError::MODE_NOT_SUPPORTED:
    return "MODE_NOT_SUPPORTED";
  case RadioError::FDN_CHECK_FAILURE:
    return "FDN_CHECK_FAILURE";
  case RadioError::ILLEGAL_SIM_OR_ME:
    return "ILLEGAL_SIM_OR_ME";
  case RadioError::MISSING_RESOURCE:
    return "MISSING_RESOURCE";
  case RadioError::NO_SUCH_ELEMENT:
    return "NO_SUCH_ELEMENT";
  case RadioError::DIAL_MODIFIED_TO_USSD:
    return "DIAL_MODIFIED_TO_USSD";
  case RadioError::DIAL_MODIFIED_TO_SS:
    return "DIAL_MODIFIED_TO_SS";
  case RadioError::DIAL_MODIFIED_TO_DIAL:
    return "DIAL_MODIFIED_TO_DIAL";
  case RadioError::USSD_MODIFIED_TO_DIAL:
    return "USSD_MODIFIED_TO_DIAL";
  case RadioError::USSD_MODIFIED_TO_SS:
    return "USSD_MODIFIED_TO_SS";
  case RadioError::USSD_MODIFIED_TO_USSD:
    return "USSD_MODIFIED_TO_USSD";
  case RadioError::SS_MODIFIED_TO_DIAL:
    return "SS_MODIFIED_TO_DIAL";
  case RadioError::SS_MODIFIED_TO_USSD:
    return "SS_MODIFIED_TO_USSD";
  case RadioError::SUBSCRIPTION_NOT_SUPPORTED:
    return "SUBSCRIPTION_NOT_SUPPORTED";
  case RadioError::SS_MODIFIED_TO_SS:
    return "SS_MODIFIED_TO_SS";
  case RadioError::LCE_NOT_SUPPORTED:
    return "LCE_NOT_SUPPORTED";
  case RadioError::NO_MEMORY:
    return "NO_MEMORY";
  case RadioError::INTERNAL_ERR:
    return "INTERNAL_ERR";
  case RadioError::SYSTEM_ERR:
    return "SYSTEM_ERR";
  case RadioError::MODEM_ERR:
    return "MODEM_ERR";
  case RadioError::INVALID_STATE:
    return "INVALID_STATE";
  case RadioError::NO_RESOURCES:
    return "NO_RESOURCES";
  case RadioError::SIM_ERR:
    return "SIM_ERR";
  case RadioError::INVALID_ARGUMENTS:
    return "INVALID_ARGUMENTS";
  case RadioError::INVALID_SIM_STATE:
    return "INVALID_SIM_STATE";
  case RadioError::INVALID_MODEM_STATE:
    return "INVALID_MODEM_STATE";
  case RadioError::INVALID_CALL_ID:
    return "INVALID_CALL_ID";
  case RadioError::NO_SMS_TO_ACK:
    return "NO_SMS_TO_ACK";
  case RadioError::NETWORK_ERR:
    return "NETWORK_ERR";
  case RadioError::REQUEST_RATE_LIMITED:
    return "REQUEST_RATE_LIMITED";
  case RadioError::SIM_BUSY:
    return "SIM_BUSY";
  case RadioError::SIM_FULL:
    return "SIM_FULL";
  case RadioError::NETWORK_REJECT:
    return "NETWORK_REJECT";
  case RadioError::OPERATION_NOT_ALLOWED:
    return "OPERATION_NOT_ALLOWED";
  case RadioError::EMPTY_RECORD:
    return "EMPTY_RECORD";
  case RadioError::INVALID_SMS_FORMAT:
    return "INVALID_SMS_FORMAT";
  case RadioError::ENCODING_ERR:
    return "ENCODING_ERR";
  case RadioError::INVALID_SMSC_ADDRESS:
    return "INVALID_SMSC_ADDRESS";
  case RadioError::NO_SUCH_ENTRY:
    return "NO_SUCH_ENTRY";
  case RadioError::NETWORK_NOT_READY:
    return "NETWORK_NOT_READY";
  case RadioError::NOT_PROVISIONED:
    return "NOT_PROVISIONED";
  case RadioError::NO_SUBSCRIPTION:
    return "NO_SUBSCRIPTION";
  case RadioError::NO_NETWORK_FOUND:
    return "NO_NETWORK_FOUND";
  case RadioError::DEVICE_IN_USE:
    return "DEVICE_IN_USE";
  case RadioError::ABORTED:
    return "ABORTED";
  case RadioError::INVALID_RESPONSE:
    return "INVALID_RESPONSE";
  case RadioError::OEM_ERROR_1:
    return "OEM_ERROR_1";
  case RadioError::OEM_ERROR_2:
    return "OEM_ERROR_2";
  case RadioError::OEM_ERROR_3:
    return "OEM_ERROR_3";
  case RadioError::OEM_ERROR_4:
    return "OEM_ERROR_4";
  case RadioError::OEM_ERROR_5:
    return "OEM_ERROR_5";
  case RadioError::OEM_ERROR_6:
    return "OEM_ERROR_6";
  case RadioError::OEM_ERROR_7:
    return "OEM_ERROR_7";
  case RadioError::OEM_ERROR_8:
    return "OEM_ERROR_8";
  case RadioError::OEM_ERROR_9:
    return "OEM_ERROR_9";
  case RadioError::OEM_ERROR_10:
    return "OEM_ERROR_10";
  case RadioError::OEM_ERROR_11:
    return "OEM_ERROR_11";
  case RadioError::OEM_ERROR_12:
    return "OEM_ERROR_12";
  case RadioError::OEM_ERROR_13:
    return "OEM_ERROR_13";
  case RadioError::OEM_ERROR_14:
    return "OEM_ERROR_14";
  case RadioError::OEM_ERROR_15:
    return "OEM_ERROR_15";
  case RadioError::OEM_ERROR_16:
    return "OEM_ERROR_16";
  case RadioError::OEM_ERROR_17:
    return "OEM_ERROR_17";
  case RadioError::OEM_ERROR_18:
    return "OEM_ERROR_18";
  case RadioError::OEM_ERROR_19:
    return "OEM_ERROR_19";
  case RadioError::OEM_ERROR_20:
    return "OEM_ERROR_20";
  case RadioError::OEM_ERROR_21:
    return "OEM_ERROR_21";
  case RadioError::OEM_ERROR_22:
    return "OEM_ERROR_22";
  case RadioError::OEM_ERROR_23:
    return "OEM_ERROR_23";
  case RadioError::OEM_ERROR_24:
    return "OEM_ERROR_24";
  case RadioError::OEM_ERROR_25:
    return "OEM_ERROR_25";
  case RadioError::SIMULTANEOUS_SMS_AND_CALL_NOT_ALLOWED:
    return "SIMULTANEOUS_SMS_AND_CALL_NOT_ALLOWED";
  case RadioError::ACCESS_BARRED:
    return "ACCESS_BARRED";
  case RadioError::BLOCKED_DUE_TO_CALL:
    return "BLOCKED_DUE_TO_CALL";
  case RadioError::RF_HARDWARE_ISSUE:
    return "RF_HARDWARE_ISSUE";
  case RadioError::NO_RF_CALIBRATION_INFO:
    return "NO_RF_CALIBRATION_INFO";
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
constexpr inline std::array<aidl::android::hardware::radio::RadioError, 89> enum_values<aidl::android::hardware::radio::RadioError> = {
  aidl::android::hardware::radio::RadioError::NONE,
  aidl::android::hardware::radio::RadioError::RADIO_NOT_AVAILABLE,
  aidl::android::hardware::radio::RadioError::GENERIC_FAILURE,
  aidl::android::hardware::radio::RadioError::PASSWORD_INCORRECT,
  aidl::android::hardware::radio::RadioError::SIM_PIN2,
  aidl::android::hardware::radio::RadioError::SIM_PUK2,
  aidl::android::hardware::radio::RadioError::REQUEST_NOT_SUPPORTED,
  aidl::android::hardware::radio::RadioError::CANCELLED,
  aidl::android::hardware::radio::RadioError::OP_NOT_ALLOWED_DURING_VOICE_CALL,
  aidl::android::hardware::radio::RadioError::OP_NOT_ALLOWED_BEFORE_REG_TO_NW,
  aidl::android::hardware::radio::RadioError::SMS_SEND_FAIL_RETRY,
  aidl::android::hardware::radio::RadioError::SIM_ABSENT,
  aidl::android::hardware::radio::RadioError::SUBSCRIPTION_NOT_AVAILABLE,
  aidl::android::hardware::radio::RadioError::MODE_NOT_SUPPORTED,
  aidl::android::hardware::radio::RadioError::FDN_CHECK_FAILURE,
  aidl::android::hardware::radio::RadioError::ILLEGAL_SIM_OR_ME,
  aidl::android::hardware::radio::RadioError::MISSING_RESOURCE,
  aidl::android::hardware::radio::RadioError::NO_SUCH_ELEMENT,
  aidl::android::hardware::radio::RadioError::DIAL_MODIFIED_TO_USSD,
  aidl::android::hardware::radio::RadioError::DIAL_MODIFIED_TO_SS,
  aidl::android::hardware::radio::RadioError::DIAL_MODIFIED_TO_DIAL,
  aidl::android::hardware::radio::RadioError::USSD_MODIFIED_TO_DIAL,
  aidl::android::hardware::radio::RadioError::USSD_MODIFIED_TO_SS,
  aidl::android::hardware::radio::RadioError::USSD_MODIFIED_TO_USSD,
  aidl::android::hardware::radio::RadioError::SS_MODIFIED_TO_DIAL,
  aidl::android::hardware::radio::RadioError::SS_MODIFIED_TO_USSD,
  aidl::android::hardware::radio::RadioError::SUBSCRIPTION_NOT_SUPPORTED,
  aidl::android::hardware::radio::RadioError::SS_MODIFIED_TO_SS,
  aidl::android::hardware::radio::RadioError::LCE_NOT_SUPPORTED,
  aidl::android::hardware::radio::RadioError::NO_MEMORY,
  aidl::android::hardware::radio::RadioError::INTERNAL_ERR,
  aidl::android::hardware::radio::RadioError::SYSTEM_ERR,
  aidl::android::hardware::radio::RadioError::MODEM_ERR,
  aidl::android::hardware::radio::RadioError::INVALID_STATE,
  aidl::android::hardware::radio::RadioError::NO_RESOURCES,
  aidl::android::hardware::radio::RadioError::SIM_ERR,
  aidl::android::hardware::radio::RadioError::INVALID_ARGUMENTS,
  aidl::android::hardware::radio::RadioError::INVALID_SIM_STATE,
  aidl::android::hardware::radio::RadioError::INVALID_MODEM_STATE,
  aidl::android::hardware::radio::RadioError::INVALID_CALL_ID,
  aidl::android::hardware::radio::RadioError::NO_SMS_TO_ACK,
  aidl::android::hardware::radio::RadioError::NETWORK_ERR,
  aidl::android::hardware::radio::RadioError::REQUEST_RATE_LIMITED,
  aidl::android::hardware::radio::RadioError::SIM_BUSY,
  aidl::android::hardware::radio::RadioError::SIM_FULL,
  aidl::android::hardware::radio::RadioError::NETWORK_REJECT,
  aidl::android::hardware::radio::RadioError::OPERATION_NOT_ALLOWED,
  aidl::android::hardware::radio::RadioError::EMPTY_RECORD,
  aidl::android::hardware::radio::RadioError::INVALID_SMS_FORMAT,
  aidl::android::hardware::radio::RadioError::ENCODING_ERR,
  aidl::android::hardware::radio::RadioError::INVALID_SMSC_ADDRESS,
  aidl::android::hardware::radio::RadioError::NO_SUCH_ENTRY,
  aidl::android::hardware::radio::RadioError::NETWORK_NOT_READY,
  aidl::android::hardware::radio::RadioError::NOT_PROVISIONED,
  aidl::android::hardware::radio::RadioError::NO_SUBSCRIPTION,
  aidl::android::hardware::radio::RadioError::NO_NETWORK_FOUND,
  aidl::android::hardware::radio::RadioError::DEVICE_IN_USE,
  aidl::android::hardware::radio::RadioError::ABORTED,
  aidl::android::hardware::radio::RadioError::INVALID_RESPONSE,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_1,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_2,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_3,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_4,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_5,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_6,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_7,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_8,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_9,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_10,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_11,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_12,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_13,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_14,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_15,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_16,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_17,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_18,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_19,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_20,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_21,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_22,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_23,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_24,
  aidl::android::hardware::radio::RadioError::OEM_ERROR_25,
  aidl::android::hardware::radio::RadioError::SIMULTANEOUS_SMS_AND_CALL_NOT_ALLOWED,
  aidl::android::hardware::radio::RadioError::ACCESS_BARRED,
  aidl::android::hardware::radio::RadioError::BLOCKED_DUE_TO_CALL,
  aidl::android::hardware::radio::RadioError::RF_HARDWARE_ISSUE,
  aidl::android::hardware::radio::RadioError::NO_RF_CALIBRATION_INFO,
};
#pragma clang diagnostic pop
}  // namespace internal
}  // namespace ndk
