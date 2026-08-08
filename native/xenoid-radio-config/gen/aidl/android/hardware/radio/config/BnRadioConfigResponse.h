/*
 * This file is auto-generated.  DO NOT MODIFY.
 */
#pragma once

#include "aidl/android/hardware/radio/config/IRadioConfigResponse.h"

#include <android/binder_ibinder.h>
#include <cassert>

#ifndef __BIONIC__
#ifndef __assert2
#define __assert2(a,b,c,d) ((void)0)
#endif
#endif

namespace aidl {
namespace android {
namespace hardware {
namespace radio {
namespace config {
class BnRadioConfigResponse : public ::ndk::BnCInterface<IRadioConfigResponse> {
public:
  BnRadioConfigResponse();
  virtual ~BnRadioConfigResponse();
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) final;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) final;
protected:
  ::ndk::SpAIBinder createBinder() override;
private:
};
class IRadioConfigResponseDelegator : public BnRadioConfigResponse {
public:
  explicit IRadioConfigResponseDelegator(const std::shared_ptr<IRadioConfigResponse> &impl) : _impl(impl) {
     int32_t _impl_ver = 0;
     if (!impl->getInterfaceVersion(&_impl_ver).isOk()) {;
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Delegator failed to get version of the implementation.");
     }
     if (_impl_ver != IRadioConfigResponse::version) {
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Mismatched versions of delegator and implementation is not allowed.");
     }
  }

  ::ndk::ScopedAStatus getHalDeviceCapabilitiesResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info, bool in_modemReducedFeatureSet1) override {
    return _impl->getHalDeviceCapabilitiesResponse(in_info, in_modemReducedFeatureSet1);
  }
  ::ndk::ScopedAStatus getNumOfLiveModemsResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info, int8_t in_numOfLiveModems) override {
    return _impl->getNumOfLiveModemsResponse(in_info, in_numOfLiveModems);
  }
  ::ndk::ScopedAStatus getPhoneCapabilityResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info, const ::aidl::android::hardware::radio::config::PhoneCapability& in_phoneCapability) override {
    return _impl->getPhoneCapabilityResponse(in_info, in_phoneCapability);
  }
  ::ndk::ScopedAStatus getSimSlotsStatusResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info, const std::vector<::aidl::android::hardware::radio::config::SimSlotStatus>& in_slotStatus) override {
    return _impl->getSimSlotsStatusResponse(in_info, in_slotStatus);
  }
  ::ndk::ScopedAStatus setNumOfLiveModemsResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info) override {
    return _impl->setNumOfLiveModemsResponse(in_info);
  }
  ::ndk::ScopedAStatus setPreferredDataModemResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info) override {
    return _impl->setPreferredDataModemResponse(in_info);
  }
  ::ndk::ScopedAStatus setSimSlotsMappingResponse(const ::aidl::android::hardware::radio::RadioResponseInfo& in_info) override {
    return _impl->setSimSlotsMappingResponse(in_info);
  }
protected:
private:
  std::shared_ptr<IRadioConfigResponse> _impl;
};

}  // namespace config
}  // namespace radio
}  // namespace hardware
}  // namespace android
}  // namespace aidl
