// NDK half of the DRM identity probe: reads the Widevine deviceUniqueId and
// plugin metadata through AMediaDrm_* exactly as a native fingerprint SDK
// would, and reports them as JSON for comparison with the Java path.
#include <jni.h>
#include <media/NdkMediaDrm.h>
#include <dlfcn.h>
#include <sys/system_properties.h>
#include <android/log.h>

#include <cstdint>
#include <string>

namespace {

const uint8_t kWidevineUuid[16] = {
    0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce,
    0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed,
};
constexpr int kCloseStressIterations = 8;

static std::string hexOf(const uint8_t *data, size_t size) {
  static const char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(size * 2);
  for (size_t i = 0; i < size; ++i) {
    out.push_back(digits[data[i] >> 4]);
    out.push_back(digits[data[i] & 15]);
  }
  return out;
}

static std::string quote(const std::string &value) {
  std::string out = "\"";
  for (char item : value) {
    if (item == '\\' || item == '"') out.push_back('\\');
    out.push_back(item);
  }
  out.push_back('"');
  return out;
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_org_example_drmidentityprobe_ProbeActivity_nativeProbe(
    JNIEnv *env, jclass) {
  std::string out = "{";
  __android_log_write(4, "XenoidDrmIdentityProbe", "PHASE ndk-isCrypto");
  bool supported = AMediaDrm_isCryptoSchemeSupported(kWidevineUuid, nullptr);
  out += "\"supported\":" + std::string(supported ? "true" : "false");
  __android_log_write(4, "XenoidDrmIdentityProbe", "PHASE ndk-createByUUID");
  AMediaDrm *drm = AMediaDrm_createByUUID(kWidevineUuid);
  if (drm == nullptr) {
    out += ",\"ok\":false,\"error\":\"create_by_uuid_failed\"}";
    return env->NewStringUTF(out.c_str());
  }

  // App-visibility assertion: the staged identity property must behave as a
  // nonexistent property inside this app process (the DRM bridge reads it
  // through the real RTLD_NEXT symbols, bypassing this interposition).
  const void *hiddenPropInfo = __system_property_find("persist.xenoid.drm.id");
  char hiddenPropValue[PROP_VALUE_MAX];
  hiddenPropValue[0] = '\0';
  int hiddenPropLength =
      __system_property_get("persist.xenoid.drm.id", hiddenPropValue);
  out += ",\"hiddenPropFindNull\":"
      + std::string(hiddenPropInfo == nullptr ? "true" : "false");
  out += ",\"hiddenPropGetLength\":" + std::to_string(hiddenPropLength);
  out += ",\"hiddenPropGetValueEmpty\":"
      + std::string(hiddenPropValue[0] == '\0' ? "true" : "false");

  const char *vendor = nullptr;
  const char *version = nullptr;
  const char *description = nullptr;
  const char *algorithms = nullptr;
  const char *security = nullptr;
  if (AMediaDrm_getPropertyString(drm, "vendor", &vendor) == AMEDIA_OK && vendor) {
    out += ",\"vendor\":" + quote(vendor);
  }
  if (AMediaDrm_getPropertyString(drm, "version", &version) == AMEDIA_OK && version) {
    out += ",\"version\":" + quote(version);
  }
  if (AMediaDrm_getPropertyString(drm, "description", &description) == AMEDIA_OK
      && description) {
    out += ",\"description\":" + quote(description);
  }
  if (AMediaDrm_getPropertyString(drm, "algorithms", &algorithms) == AMEDIA_OK
      && algorithms) {
    out += ",\"algorithms\":" + quote(algorithms);
  }
  if (AMediaDrm_getPropertyString(drm, "securityLevel", &security) == AMEDIA_OK
      && security) {
    out += ",\"securityLevel\":" + quote(security);
  }

  AMediaDrmByteArray deviceId = {};
  std::string deviceIdHex;
  if (AMediaDrm_getPropertyByteArray(drm, "deviceUniqueId", &deviceId)
          == AMEDIA_OK && deviceId.ptr != nullptr) {
    deviceIdHex = hexOf(deviceId.ptr, deviceId.length);
    out += ",\"deviceUniqueId\":" + quote(deviceIdHex);
  }
  AMediaDrmByteArray sameObjectRepeatedId = {};
  bool secondReadSucceeded =
      AMediaDrm_getPropertyByteArray(
              drm, "deviceUniqueId", &sameObjectRepeatedId) == AMEDIA_OK
      && sameObjectRepeatedId.ptr != nullptr;
  bool sameObjectRepeatMatches =
      secondReadSucceeded
      && deviceIdHex == hexOf(
              sameObjectRepeatedId.ptr, sameObjectRepeatedId.length);
  // Two consecutive reads on ONE object must both deliver exactly 16 bytes;
  // this regresses the android::Vector clear-then-refill reuse bug.
  bool sameObjectRepeatBytes16 =
      deviceId.ptr != nullptr && sameObjectRepeatedId.ptr != nullptr
      && deviceId.length == 16 && sameObjectRepeatedId.length == 16;
  out += ",\"sameObjectRepeatDeviceUniqueIdMatches\":"
      + std::string(sameObjectRepeatMatches ? "true" : "false");
  out += ",\"sameObjectRepeatDeviceUniqueIdBytes16\":"
      + std::string(sameObjectRepeatBytes16 ? "true" : "false");

  AMediaDrm_release(drm);
  AMediaDrm *repeated = AMediaDrm_createByUUID(kWidevineUuid);
  bool repeatMatches = false;
  if (repeated != nullptr) {
    AMediaDrmByteArray repeatedId = {};
    if (AMediaDrm_getPropertyByteArray(repeated, "deviceUniqueId", &repeatedId)
            == AMEDIA_OK && repeatedId.ptr != nullptr) {
      repeatMatches = deviceIdHex == hexOf(repeatedId.ptr, repeatedId.length);
    }
    AMediaDrm_release(repeated);
  }
  out += ",\"repeatCreateSucceeded\":"
      + std::string(repeated != nullptr ? "true" : "false");
  out += ",\"repeatDeviceUniqueIdMatches\":"
      + std::string(repeatMatches ? "true" : "false");
  bool closeStressSucceeded = true;
  for (int iteration = 0; iteration < kCloseStressIterations; ++iteration) {
    AMediaDrm *closeStress = AMediaDrm_createByUUID(kWidevineUuid);
    if (closeStress == nullptr) {
      closeStressSucceeded = false;
      continue;
    }
    AMediaDrmByteArray closeStressId = {};
    if (AMediaDrm_getPropertyByteArray(
            closeStress, "deviceUniqueId", &closeStressId) != AMEDIA_OK
        || closeStressId.ptr == nullptr
        || deviceIdHex != hexOf(closeStressId.ptr, closeStressId.length)) {
      closeStressSucceeded = false;
    }
    AMediaDrm_release(closeStress);
  }
  out += ",\"closeStressIterations\":" + std::to_string(kCloseStressIterations);
  out += ",\"closeStressSucceeded\":"
      + std::string(closeStressSucceeded ? "true" : "false");
  out += ",\"ok\":true}";
  return env->NewStringUTF(out.c_str());
}
