/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
///////////////////////////////////////////////////////////////////////////////
// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
///////////////////////////////////////////////////////////////////////////////

// This file is a snapshot of an AIDL file. Do not edit it manually. There are
// two cases:
// 1). this is a frozen version file - do not edit this in any case.
// 2). this is a 'current' file. If you make a backwards compatible change to
//     the interface (from the latest frozen version), the build system will
//     prompt you to update this file with `m <name>-update-api`.
//
// You must not make a backward incompatible change to any AIDL file built
// with the aidl_interface module type with versions property set. The module
// type is used to build AIDL files in a way that they can be used across
// independently updatable components of the system. If a device is shipped
// with such a backward incompatible change, it has a high risk of breaking
// later when a module using the interface is updated, e.g., Mainline modules.

package android.hardware.radio;
@Backing(type="int") @JavaDerive(toString=true) @VintfStability
enum RadioError {
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
}
