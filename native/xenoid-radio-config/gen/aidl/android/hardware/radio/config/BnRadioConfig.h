/*
 * This file is auto-generated.  DO NOT MODIFY.
 */
#pragma once

#include "aidl/android/hardware/radio/config/IRadioConfig.h"

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
class BnRadioConfig : public ::ndk::BnCInterface<IRadioConfig> {
public:
  BnRadioConfig();
  virtual ~BnRadioConfig();
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) final;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) final;
protected:
  ::ndk::SpAIBinder createBinder() override;
private:
};
class IRadioConfigDelegator : public BnRadioConfig {
public:
  explicit IRadioConfigDelegator(const std::shared_ptr<IRadioConfig> &impl) : _impl(impl) {
     int32_t _impl_ver = 0;
     if (!impl->getInterfaceVersion(&_impl_ver).isOk()) {;
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Delegator failed to get version of the implementation.");
     }
     if (_impl_ver != IRadioConfig::version) {
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Mismatched versions of delegator and implementation is not allowed.");
     }
  }

  ::ndk::ScopedAStatus getHalDeviceCapabilities(int32_t in_serial) override {
    return _impl->getHalDeviceCapabilities(in_serial);
  }
  ::ndk::ScopedAStatus getNumOfLiveModems(int32_t in_serial) override {
    return _impl->getNumOfLiveModems(in_serial);
  }
  ::ndk::ScopedAStatus getPhoneCapability(int32_t in_serial) override {
    return _impl->getPhoneCapability(in_serial);
  }
  ::ndk::ScopedAStatus getSimSlotsStatus(int32_t in_serial) override {
    return _impl->getSimSlotsStatus(in_serial);
  }
  ::ndk::ScopedAStatus setNumOfLiveModems(int32_t in_serial, int8_t in_numOfLiveModems) override {
    return _impl->setNumOfLiveModems(in_serial, in_numOfLiveModems);
  }
  ::ndk::ScopedAStatus setPreferredDataModem(int32_t in_serial, int8_t in_modemId) override {
    return _impl->setPreferredDataModem(in_serial, in_modemId);
  }
  ::ndk::ScopedAStatus setResponseFunctions(const std::shared_ptr<::aidl::android::hardware::radio::config::IRadioConfigResponse>& in_radioConfigResponse, const std::shared_ptr<::aidl::android::hardware::radio::config::IRadioConfigIndication>& in_radioConfigIndication) override {
    return _impl->setResponseFunctions(in_radioConfigResponse, in_radioConfigIndication);
  }
  ::ndk::ScopedAStatus setSimSlotsMapping(int32_t in_serial, const std::vector<::aidl::android::hardware::radio::config::SlotPortMapping>& in_slotMap) override {
    return _impl->setSimSlotsMapping(in_serial, in_slotMap);
  }
protected:
private:
  std::shared_ptr<IRadioConfig> _impl;
};

}  // namespace config
}  // namespace radio
}  // namespace hardware
}  // namespace android
}  // namespace aidl
