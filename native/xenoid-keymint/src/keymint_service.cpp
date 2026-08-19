// Standalone KeyMint HAL service (Android 12+). Registers the TEESimulator
// router device as android.hardware.security.keymint.IKeyMintDevice/default so
// keystore2 reaches it through ordinary binder resolution — the integration for
// runtimes that have no hardware KeyMint HAL (emulators, containers), where
// keystore2's in-process km_compat fallback never traverses AIBinder_transact
// and the injected hook has nothing to intercept.
//
// The service is a pure engine like the injected lib: it binds the @teesim
// control socket and serves no key material until the daemon pushes a resolved
// profile set. Pair it with a "*" target profile so every request is served by
// the TA; requests arriving before the first push fail cleanly.

#include <android/binder_manager.h>
#include <android/binder_process.h>

#include <aidl/android/hardware/security/keymint/IKeyMintDevice.h>

#include <csignal>
#include <string>

#include "control.h"
#include "logging.hpp"

// keymint_router.cpp
extern "C" AIBinder* teesim_router_new_sim_device(int32_t security_level);

// The router's ForwardGuard calls into the hook translation unit, which this
// service deliberately does not link: there is no hook here, so the forwarding
// flag is a no-op.
extern "C" void teesim_hook_set_forwarding(bool /*forwarding*/) {}

int main() {
  using aidl::android::hardware::security::keymint::IKeyMintDevice;
  // The control server writes responses with plain write(2); a client that
  // closes early would otherwise kill this standalone process with SIGPIPE.
  // (Injected into keystore2 this was inherited: the Rust runtime ignores
  // SIGPIPE for the whole process.)
  std::signal(SIGPIPE, SIG_IGN);
  teesim_control_start();
  ABinderProcess_setThreadPoolMaxThreadCount(4);
  ABinderProcess_startThreadPool();
  // SecurityLevel 1 = TrustedEnvironment: the level keystore2's default
  // key operations resolve to once an AIDL KeyMint HAL is declared.
  AIBinder* dev = teesim_router_new_sim_device(1);
  if (dev == nullptr) {
    LOGE("TEESimulator KeyMint service: failed to create device");
    return 1;
  }
  const std::string instance = std::string(IKeyMintDevice::descriptor) + "/default";
  const binder_status_t status = AServiceManager_addService(dev, instance.c_str());
  if (status != STATUS_OK) {
    LOGE("TEESimulator KeyMint service: addService %s failed (%d)", instance.c_str(), status);
    return 1;
  }
  LOGI("TEESimulator KeyMint service: serving %s (awaiting config push)", instance.c_str());
  ABinderProcess_joinThreadPool();
  return 0;
}
