/*
 * This file is auto-generated.  DO NOT MODIFY.
 */
#include "aidl/android/hardware/radio/config/IRadioConfigIndication.h"

#include <android/binder_parcel_utils.h>
#include <aidl/android/hardware/radio/config/BnRadioConfigIndication.h>
#include <aidl/android/hardware/radio/config/BpRadioConfigIndication.h>

namespace aidl {
namespace android {
namespace hardware {
namespace radio {
namespace config {
static binder_status_t _aidl_android_hardware_radio_config_IRadioConfigIndication_onTransact(AIBinder* _aidl_binder, transaction_code_t _aidl_code, const AParcel* _aidl_in, AParcel* _aidl_out) {
  (void)_aidl_in;
  (void)_aidl_out;
  binder_status_t _aidl_ret_status = STATUS_UNKNOWN_TRANSACTION;
  std::shared_ptr<BnRadioConfigIndication> _aidl_impl = std::static_pointer_cast<BnRadioConfigIndication>(::ndk::ICInterface::asInterface(_aidl_binder));
  switch (_aidl_code) {
    case (FIRST_CALL_TRANSACTION + 0 /*simSlotsStatusChanged*/): {
      ::aidl::android::hardware::radio::RadioIndicationType in_type;
      std::vector<::aidl::android::hardware::radio::config::SimSlotStatus> in_slotStatus;

      _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_type);
      if (_aidl_ret_status != STATUS_OK) break;

      _aidl_ret_status = ::ndk::AParcel_readData(_aidl_in, &in_slotStatus);
      if (_aidl_ret_status != STATUS_OK) break;

      ::ndk::ScopedAStatus _aidl_status = _aidl_impl->simSlotsStatusChanged(in_type, in_slotStatus);
      _aidl_ret_status = STATUS_OK;
      break;
    }
    case (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/): {
      int32_t _aidl_return;

      ::ndk::ScopedAStatus _aidl_status = _aidl_impl->getInterfaceVersion(&_aidl_return);
      _aidl_ret_status = AParcel_writeStatusHeader(_aidl_out, _aidl_status.get());
      if (_aidl_ret_status != STATUS_OK) break;

      if (!AStatus_isOk(_aidl_status.get())) break;

      _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_out, _aidl_return);
      if (_aidl_ret_status != STATUS_OK) break;

      break;
    }
    case (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/): {
      std::string _aidl_return;

      ::ndk::ScopedAStatus _aidl_status = _aidl_impl->getInterfaceHash(&_aidl_return);
      _aidl_ret_status = AParcel_writeStatusHeader(_aidl_out, _aidl_status.get());
      if (_aidl_ret_status != STATUS_OK) break;

      if (!AStatus_isOk(_aidl_status.get())) break;

      _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_out, _aidl_return);
      if (_aidl_ret_status != STATUS_OK) break;

      break;
    }
  }
  return _aidl_ret_status;
}

static AIBinder_Class* _g_aidl_android_hardware_radio_config_IRadioConfigIndication_clazz = ::ndk::ICInterface::defineClass(IRadioConfigIndication::descriptor, _aidl_android_hardware_radio_config_IRadioConfigIndication_onTransact);

BpRadioConfigIndication::BpRadioConfigIndication(const ::ndk::SpAIBinder& binder) : BpCInterface(binder) {}
BpRadioConfigIndication::~BpRadioConfigIndication() {}

::ndk::ScopedAStatus BpRadioConfigIndication::simSlotsStatusChanged(::aidl::android::hardware::radio::RadioIndicationType in_type, const std::vector<::aidl::android::hardware::radio::config::SimSlotStatus>& in_slotStatus) {
  binder_status_t _aidl_ret_status = STATUS_OK;
  ::ndk::ScopedAStatus _aidl_status;
  ::ndk::ScopedAParcel _aidl_in;
  ::ndk::ScopedAParcel _aidl_out;

  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_type);
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_in.get(), in_slotStatus);
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = AIBinder_transact(
    asBinder().get(),
    (FIRST_CALL_TRANSACTION + 0 /*simSlotsStatusChanged*/),
    _aidl_in.getR(),
    _aidl_out.getR(),
    FLAG_ONEWAY
    #ifdef BINDER_STABILITY_SUPPORT
    | FLAG_PRIVATE_LOCAL
    #endif  // BINDER_STABILITY_SUPPORT
    );
  if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRadioConfigIndication::getDefaultImpl()) {
    _aidl_status = IRadioConfigIndication::getDefaultImpl()->simSlotsStatusChanged(in_type, in_slotStatus);
    goto _aidl_status_return;
  }
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_error:
  _aidl_status.set(AStatus_fromStatus(_aidl_ret_status));
  _aidl_status_return:
  return _aidl_status;
}
::ndk::ScopedAStatus BpRadioConfigIndication::getInterfaceVersion(int32_t* _aidl_return) {
  binder_status_t _aidl_ret_status = STATUS_OK;
  ::ndk::ScopedAStatus _aidl_status;
  if (_aidl_cached_version != -1) {
    *_aidl_return = _aidl_cached_version;
    _aidl_status.set(AStatus_fromStatus(_aidl_ret_status));
    return _aidl_status;
  }
  ::ndk::ScopedAParcel _aidl_in;
  ::ndk::ScopedAParcel _aidl_out;

  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = AIBinder_transact(
    asBinder().get(),
    (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/),
    _aidl_in.getR(),
    _aidl_out.getR(),
    0
    #ifdef BINDER_STABILITY_SUPPORT
    | FLAG_PRIVATE_LOCAL
    #endif  // BINDER_STABILITY_SUPPORT
    );
  if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRadioConfigIndication::getDefaultImpl()) {
    _aidl_status = IRadioConfigIndication::getDefaultImpl()->getInterfaceVersion(_aidl_return);
    goto _aidl_status_return;
  }
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = AParcel_readStatusHeader(_aidl_out.get(), _aidl_status.getR());
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  if (!AStatus_isOk(_aidl_status.get())) goto _aidl_status_return;
  _aidl_ret_status = ::ndk::AParcel_readData(_aidl_out.get(), _aidl_return);
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_cached_version = *_aidl_return;
  _aidl_error:
  _aidl_status.set(AStatus_fromStatus(_aidl_ret_status));
  _aidl_status_return:
  return _aidl_status;
}
::ndk::ScopedAStatus BpRadioConfigIndication::getInterfaceHash(std::string* _aidl_return) {
  binder_status_t _aidl_ret_status = STATUS_OK;
  ::ndk::ScopedAStatus _aidl_status;
  const std::lock_guard<std::mutex> lock(_aidl_cached_hash_mutex);
  if (_aidl_cached_hash != "-1") {
    *_aidl_return = _aidl_cached_hash;
    _aidl_status.set(AStatus_fromStatus(_aidl_ret_status));
    return _aidl_status;
  }
  ::ndk::ScopedAParcel _aidl_in;
  ::ndk::ScopedAParcel _aidl_out;

  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = AIBinder_transact(
    asBinder().get(),
    (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/),
    _aidl_in.getR(),
    _aidl_out.getR(),
    0
    #ifdef BINDER_STABILITY_SUPPORT
    | FLAG_PRIVATE_LOCAL
    #endif  // BINDER_STABILITY_SUPPORT
    );
  if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IRadioConfigIndication::getDefaultImpl()) {
    _aidl_status = IRadioConfigIndication::getDefaultImpl()->getInterfaceHash(_aidl_return);
    goto _aidl_status_return;
  }
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = AParcel_readStatusHeader(_aidl_out.get(), _aidl_status.getR());
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  if (!AStatus_isOk(_aidl_status.get())) goto _aidl_status_return;
  _aidl_ret_status = ::ndk::AParcel_readData(_aidl_out.get(), _aidl_return);
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_cached_hash = *_aidl_return;
  _aidl_error:
  _aidl_status.set(AStatus_fromStatus(_aidl_ret_status));
  _aidl_status_return:
  return _aidl_status;
}
// Source for BnRadioConfigIndication
BnRadioConfigIndication::BnRadioConfigIndication() {}
BnRadioConfigIndication::~BnRadioConfigIndication() {}
::ndk::SpAIBinder BnRadioConfigIndication::createBinder() {
  AIBinder* binder = AIBinder_new(_g_aidl_android_hardware_radio_config_IRadioConfigIndication_clazz, static_cast<void*>(this));
  #ifdef BINDER_STABILITY_SUPPORT
  AIBinder_markVintfStability(binder);
  #endif  // BINDER_STABILITY_SUPPORT
  return ::ndk::SpAIBinder(binder);
}
::ndk::ScopedAStatus BnRadioConfigIndication::getInterfaceVersion(int32_t* _aidl_return) {
  *_aidl_return = IRadioConfigIndication::version;
  return ::ndk::ScopedAStatus(AStatus_newOk());
}
::ndk::ScopedAStatus BnRadioConfigIndication::getInterfaceHash(std::string* _aidl_return) {
  *_aidl_return = IRadioConfigIndication::hash;
  return ::ndk::ScopedAStatus(AStatus_newOk());
}
// Source for IRadioConfigIndication
const char* IRadioConfigIndication::descriptor = "android.hardware.radio.config.IRadioConfigIndication";
IRadioConfigIndication::IRadioConfigIndication() {}
IRadioConfigIndication::~IRadioConfigIndication() {}


std::shared_ptr<IRadioConfigIndication> IRadioConfigIndication::fromBinder(const ::ndk::SpAIBinder& binder) {
  if (!AIBinder_associateClass(binder.get(), _g_aidl_android_hardware_radio_config_IRadioConfigIndication_clazz)) {
    #if __ANDROID_API__ >= 31
    const AIBinder_Class* originalClass = AIBinder_getClass(binder.get());
    if (originalClass == nullptr) return nullptr;
    if (0 == strcmp(AIBinder_Class_getDescriptor(originalClass), descriptor)) {
      return ::ndk::SharedRefBase::make<BpRadioConfigIndication>(binder);
    }
    #endif
    return nullptr;
  }
  std::shared_ptr<::ndk::ICInterface> interface = ::ndk::ICInterface::asInterface(binder.get());
  if (interface) {
    return std::static_pointer_cast<IRadioConfigIndication>(interface);
  }
  return ::ndk::SharedRefBase::make<BpRadioConfigIndication>(binder);
}

binder_status_t IRadioConfigIndication::writeToParcel(AParcel* parcel, const std::shared_ptr<IRadioConfigIndication>& instance) {
  return AParcel_writeStrongBinder(parcel, instance ? instance->asBinder().get() : nullptr);
}
binder_status_t IRadioConfigIndication::readFromParcel(const AParcel* parcel, std::shared_ptr<IRadioConfigIndication>* instance) {
  ::ndk::SpAIBinder binder;
  binder_status_t status = AParcel_readStrongBinder(parcel, binder.getR());
  if (status != STATUS_OK) return status;
  *instance = IRadioConfigIndication::fromBinder(binder);
  return STATUS_OK;
}
bool IRadioConfigIndication::setDefaultImpl(const std::shared_ptr<IRadioConfigIndication>& impl) {
  // Only one user of this interface can use this function
  // at a time. This is a heuristic to detect if two different
  // users in the same process use this function.
  assert(!IRadioConfigIndication::default_impl);
  if (impl) {
    IRadioConfigIndication::default_impl = impl;
    return true;
  }
  return false;
}
const std::shared_ptr<IRadioConfigIndication>& IRadioConfigIndication::getDefaultImpl() {
  return IRadioConfigIndication::default_impl;
}
std::shared_ptr<IRadioConfigIndication> IRadioConfigIndication::default_impl = nullptr;
::ndk::ScopedAStatus IRadioConfigIndicationDefault::simSlotsStatusChanged(::aidl::android::hardware::radio::RadioIndicationType /*in_type*/, const std::vector<::aidl::android::hardware::radio::config::SimSlotStatus>& /*in_slotStatus*/) {
  ::ndk::ScopedAStatus _aidl_status;
  _aidl_status.set(AStatus_fromStatus(STATUS_UNKNOWN_TRANSACTION));
  return _aidl_status;
}
::ndk::ScopedAStatus IRadioConfigIndicationDefault::getInterfaceVersion(int32_t* _aidl_return) {
  *_aidl_return = 0;
  return ::ndk::ScopedAStatus(AStatus_newOk());
}
::ndk::ScopedAStatus IRadioConfigIndicationDefault::getInterfaceHash(std::string* _aidl_return) {
  *_aidl_return = "";
  return ::ndk::ScopedAStatus(AStatus_newOk());
}
::ndk::SpAIBinder IRadioConfigIndicationDefault::asBinder() {
  return ::ndk::SpAIBinder();
}
bool IRadioConfigIndicationDefault::isRemote() {
  return false;
}
}  // namespace config
}  // namespace radio
}  // namespace hardware
}  // namespace android
}  // namespace aidl
