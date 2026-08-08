/*
 * This file is auto-generated.  DO NOT MODIFY.
 */
#pragma once

#include "aidl/android/hardware/radio/config/IRadioConfigIndication.h"

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
class BnRadioConfigIndication : public ::ndk::BnCInterface<IRadioConfigIndication> {
public:
  BnRadioConfigIndication();
  virtual ~BnRadioConfigIndication();
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) final;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) final;
protected:
  ::ndk::SpAIBinder createBinder() override;
private:
};
class IRadioConfigIndicationDelegator : public BnRadioConfigIndication {
public:
  explicit IRadioConfigIndicationDelegator(const std::shared_ptr<IRadioConfigIndication> &impl) : _impl(impl) {
     int32_t _impl_ver = 0;
     if (!impl->getInterfaceVersion(&_impl_ver).isOk()) {;
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Delegator failed to get version of the implementation.");
     }
     if (_impl_ver != IRadioConfigIndication::version) {
        __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "Mismatched versions of delegator and implementation is not allowed.");
     }
  }

  ::ndk::ScopedAStatus simSlotsStatusChanged(::aidl::android::hardware::radio::RadioIndicationType in_type, const std::vector<::aidl::android::hardware::radio::config::SimSlotStatus>& in_slotStatus) override {
    return _impl->simSlotsStatusChanged(in_type, in_slotStatus);
  }
protected:
private:
  std::shared_ptr<IRadioConfigIndication> _impl;
};

}  // namespace config
}  // namespace radio
}  // namespace hardware
}  // namespace android
}  // namespace aidl
