#include <aidl/android/hardware/radio/RadioError.h>
#include <aidl/android/hardware/radio/RadioResponseInfo.h>
#include <aidl/android/hardware/radio/RadioResponseType.h>
#include <aidl/android/hardware/radio/config/BnRadioConfig.h>
#include <aidl/android/hardware/radio/config/IRadioConfigIndication.h>
#include <aidl/android/hardware/radio/config/IRadioConfigResponse.h>
#include <aidl/android/hardware/radio/config/PhoneCapability.h>
#include <aidl/android/hardware/radio/config/SimPortInfo.h>
#include <aidl/android/hardware/radio/config/SimSlotStatus.h>
#include <aidl/android/hardware/radio/config/SlotPortMapping.h>

extern "C" {
binder_status_t AServiceManager_addService(AIBinder*, const char*);
void ABinderProcess_setThreadPoolMaxThreadCount(uint32_t);
void ABinderProcess_joinThreadPool(void);
}
#include <android/log.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace radio = aidl::android::hardware::radio;
namespace config = aidl::android::hardware::radio::config;

namespace {
constexpr const char* kLogTag = "xenoid-radio-config";
constexpr const char* kProfilePath = "/data/vendor/radio/xenoid/profile.v1";
constexpr char kProfileMagic[] = "XENOID_PROFILE_V1";
constexpr uint32_t kProfileVersion = 1;
constexpr uint32_t kProfileFields = 21;
constexpr size_t kProfileMaxBytes = 64 * 1024;

struct Sha256Context {
    uint32_t state[8];
    uint64_t bits;
    uint8_t block[64];
    size_t used;
};

constexpr uint32_t kSha256Constants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

uint32_t rotateRight(uint32_t value, unsigned count) {
    return (value >> count) | (value << (32u - count));
}

uint32_t readBe32(const uint8_t* value) {
    return (static_cast<uint32_t>(value[0]) << 24)
            | (static_cast<uint32_t>(value[1]) << 16)
            | (static_cast<uint32_t>(value[2]) << 8)
            | static_cast<uint32_t>(value[3]);
}

void writeBe32(uint8_t* output, uint32_t value) {
    output[0] = static_cast<uint8_t>(value >> 24);
    output[1] = static_cast<uint8_t>(value >> 16);
    output[2] = static_cast<uint8_t>(value >> 8);
    output[3] = static_cast<uint8_t>(value);
}

void sha256Transform(Sha256Context* context, const uint8_t block[64]) {
    uint32_t words[64];
    for (size_t index = 0; index < 16; ++index) {
        words[index] = readBe32(block + index * 4);
    }
    for (size_t index = 16; index < 64; ++index) {
        uint32_t first = rotateRight(words[index - 15], 7)
                ^ rotateRight(words[index - 15], 18) ^ (words[index - 15] >> 3);
        uint32_t second = rotateRight(words[index - 2], 17)
                ^ rotateRight(words[index - 2], 19) ^ (words[index - 2] >> 10);
        words[index] = words[index - 16] + first + words[index - 7] + second;
    }
    uint32_t a = context->state[0];
    uint32_t b = context->state[1];
    uint32_t c = context->state[2];
    uint32_t d = context->state[3];
    uint32_t e = context->state[4];
    uint32_t f = context->state[5];
    uint32_t g = context->state[6];
    uint32_t h = context->state[7];
    for (size_t index = 0; index < 64; ++index) {
        uint32_t s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t temporary1 = h + s1 + choice + kSha256Constants[index] + words[index];
        uint32_t s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temporary2 = s0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temporary1;
        d = c;
        c = b;
        b = a;
        a = temporary1 + temporary2;
    }
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}

void sha256Init(Sha256Context* context) {
    std::memset(context, 0, sizeof(*context));
    context->state[0] = 0x6a09e667u;
    context->state[1] = 0xbb67ae85u;
    context->state[2] = 0x3c6ef372u;
    context->state[3] = 0xa54ff53au;
    context->state[4] = 0x510e527fu;
    context->state[5] = 0x9b05688cu;
    context->state[6] = 0x1f83d9abu;
    context->state[7] = 0x5be0cd19u;
}

void sha256Update(Sha256Context* context, const uint8_t* value, size_t length) {
    context->bits += static_cast<uint64_t>(length) * 8u;
    while (length) {
        size_t available = sizeof(context->block) - context->used;
        size_t count = length < available ? length : available;
        std::memcpy(context->block + context->used, value, count);
        context->used += count;
        value += count;
        length -= count;
        if (context->used == sizeof(context->block)) {
            sha256Transform(context, context->block);
            context->used = 0;
        }
    }
}

void sha256Final(Sha256Context* context, uint8_t output[32]) {
    context->block[context->used++] = 0x80;
    if (context->used > 56) {
        std::memset(context->block + context->used, 0, 64 - context->used);
        sha256Transform(context, context->block);
        context->used = 0;
    }
    std::memset(context->block + context->used, 0, 56 - context->used);
    for (size_t index = 0; index < 8; ++index) {
        context->block[63 - index] = static_cast<uint8_t>(context->bits >> (index * 8));
    }
    sha256Transform(context, context->block);
    for (size_t index = 0; index < 8; ++index) {
        writeBe32(output + index * 4, context->state[index]);
    }
    std::memset(context, 0, sizeof(*context));
}

struct RadioProfile {
    char mcc[4], mnc[4], imsi[16], iccid[21], msisdn[17];
    char carrier[129], apn[129], locales[129], timezone[129], digest[65];
    uint32_t tac, eci, pci, earfcn, band, cqi, timingAdvance, bandwidthKhz;
    int32_t rsrp, rsrq, rssnr;
};

uint16_t fieldId(const uint8_t* value) {
    return static_cast<uint16_t>((static_cast<uint16_t>(value[0]) << 8) | value[1]);
}

int copyStringField(char* output, size_t capacity, const uint8_t* value, size_t length) {
    if (!length || length >= capacity || std::memchr(value, 0, length)) return -1;
    std::memcpy(output, value, length);
    output[length] = 0;
    return 0;
}

int parseNumericField(uint32_t* output, const uint8_t* value, size_t length) {
    if (length != 4) return -1;
    *output = readBe32(value);
    return 0;
}

int parseSignedField(int32_t* output, const uint8_t* value, size_t length) {
    uint32_t encoded;
    if (parseNumericField(&encoded, value, length) != 0) return -1;
    *output = static_cast<int32_t>(encoded);
    return 0;
}

int validateProfileValues(const RadioProfile& value) {
    size_t mccLength = std::strlen(value.mcc);
    size_t mncLength = std::strlen(value.mnc);
    if (mccLength != 3 || (mncLength != 2 && mncLength != 3)
            || std::strlen(value.imsi) != 15 || std::strlen(value.iccid) != 20
            || value.msisdn[0] != '+' || std::strlen(value.digest) != 64
            || value.tac < 1 || value.tac > 65535 || value.eci < 1
            || value.eci > 268435455 || value.pci > 503 || value.earfcn > 262143
            || value.band < 1 || value.band > 256 || value.rsrp > -44
            || value.rsrp < -140 || value.rsrq > -3 || value.rsrq < -20
            || value.rssnr < -200 || value.rssnr > 300 || value.cqi > 15
            || value.bandwidthKhz != 10000) {
        return -1;
    }
    for (const char* cursor = value.mcc; *cursor; ++cursor) {
        if (*cursor < '0' || *cursor > '9') return -1;
    }
    for (const char* cursor = value.mnc; *cursor; ++cursor) {
        if (*cursor < '0' || *cursor > '9') return -1;
    }
    for (const char* cursor = value.imsi; *cursor; ++cursor) {
        if (*cursor < '0' || *cursor > '9') return -1;
    }
    for (const char* cursor = value.iccid; *cursor; ++cursor) {
        if (*cursor < '0' || *cursor > '9') return -1;
    }
    return std::strncmp(value.imsi, value.mcc, 3) == 0
                    && std::strncmp(value.imsi + 3, value.mnc, mncLength) == 0
            ? 0
            : -1;
}

int parseProfile(const uint8_t* file, size_t length, RadioProfile* output) {
    const size_t headerSize = sizeof(kProfileMagic) + 8;
    if (length < headerSize + 32 || length > kProfileMaxBytes
            || std::memcmp(file, kProfileMagic, sizeof(kProfileMagic)) != 0
            || readBe32(file + sizeof(kProfileMagic)) != kProfileVersion
            || readBe32(file + sizeof(kProfileMagic) + 4) != kProfileFields) {
        return -1;
    }
    const uint8_t* cursor = file + headerSize;
    const uint8_t* digest = file + length - 32;
    Sha256Context hash;
    uint8_t actual[32];
    sha256Init(&hash);
    sha256Update(&hash, cursor, static_cast<size_t>(digest - cursor));
    sha256Final(&hash, actual);
    if (std::memcmp(actual, digest, sizeof(actual)) != 0) return -1;
    std::memset(output, 0, sizeof(*output));
    uint16_t previous = 0;
    unsigned seen = 0;
    while (cursor < digest) {
        if (static_cast<size_t>(digest - cursor) < 6) return -1;
        uint16_t id = fieldId(cursor);
        uint32_t fieldLength = readBe32(cursor + 2);
        cursor += 6;
        if (id <= previous || id < 1 || id > kProfileFields || fieldLength == 0
                || fieldLength > 8192
                || static_cast<size_t>(digest - cursor) < fieldLength) {
            return -1;
        }
        const uint8_t* value = cursor;
        int result = 0;
        switch (id) {
            case 1:
                result = copyStringField(output->mcc, sizeof(output->mcc), value, fieldLength);
                break;
            case 2:
                result = copyStringField(output->mnc, sizeof(output->mnc), value, fieldLength);
                break;
            case 3:
                result = copyStringField(output->imsi, sizeof(output->imsi), value, fieldLength);
                break;
            case 4:
                result = copyStringField(output->iccid, sizeof(output->iccid), value, fieldLength);
                break;
            case 5:
                result = copyStringField(
                        output->msisdn, sizeof(output->msisdn), value, fieldLength);
                break;
            case 6:
                result = copyStringField(
                        output->carrier, sizeof(output->carrier), value, fieldLength);
                break;
            case 7:
                result = copyStringField(output->apn, sizeof(output->apn), value, fieldLength);
                break;
            case 8:
                result = parseNumericField(&output->tac, value, fieldLength);
                break;
            case 9:
                result = parseNumericField(&output->eci, value, fieldLength);
                break;
            case 10:
                result = parseNumericField(&output->pci, value, fieldLength);
                break;
            case 11:
                result = parseNumericField(&output->earfcn, value, fieldLength);
                break;
            case 12:
                result = parseNumericField(&output->band, value, fieldLength);
                break;
            case 13:
                result = parseSignedField(&output->rsrp, value, fieldLength);
                break;
            case 14:
                result = parseSignedField(&output->rsrq, value, fieldLength);
                break;
            case 15:
                result = parseSignedField(&output->rssnr, value, fieldLength);
                break;
            case 16:
                result = parseNumericField(&output->cqi, value, fieldLength);
                break;
            case 17:
                result = parseNumericField(&output->timingAdvance, value, fieldLength);
                break;
            case 18:
                result = copyStringField(
                        output->locales, sizeof(output->locales), value, fieldLength);
                break;
            case 19:
                result = copyStringField(
                        output->timezone, sizeof(output->timezone), value, fieldLength);
                break;
            case 20:
                result = copyStringField(
                        output->digest, sizeof(output->digest), value, fieldLength);
                break;
            case 21:
                result = parseNumericField(&output->bandwidthKhz, value, fieldLength);
                break;
            default:
                return -1;
        }
        if (result != 0) return -1;
        cursor += fieldLength;
        previous = id;
        ++seen;
    }
    return cursor == digest && seen == kProfileFields && validateProfileValues(*output) == 0
            ? 0
            : -1;
}

bool loadProfileIccid(std::string* iccId) {
    iccId->clear();
    int descriptor = open(kProfilePath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return false;
    struct stat info;
    if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0
            || info.st_size > static_cast<off_t>(kProfileMaxBytes)
            || (info.st_mode & 0777) != 0640 || info.st_uid != 1001 || info.st_gid != 1001) {
        close(descriptor);
        return false;
    }
    size_t length = static_cast<size_t>(info.st_size);
    auto* data = static_cast<uint8_t*>(std::malloc(length));
    if (!data) {
        close(descriptor);
        return false;
    }
    RadioProfile profile{};
    size_t used = 0;
    bool loaded = false;
    while (used < length) {
        ssize_t count = read(descriptor, data + used, length - used);
        if (count <= 0) goto done;
        used += static_cast<size_t>(count);
    }
    if (read(descriptor, data, 1) != 0) goto done;
    if (parseProfile(data, length, &profile) != 0) goto done;
    *iccId = profile.iccid;
    loaded = true;
done:
    std::memset(&profile, 0, sizeof(profile));
    std::memset(data, 0, length);
    std::free(data);
    close(descriptor);
    return loaded;
}

void logProfileFallbackOnce() {
    static std::atomic_flag logged = ATOMIC_FLAG_INIT;
    if (!logged.test_and_set()) {
        __android_log_print(
                ANDROID_LOG_WARN, kLogTag, "staged cellular profile unavailable or invalid");
    }
}

radio::RadioResponseInfo responseInfo(int32_t serial, radio::RadioError error = radio::RadioError::NONE) {
    radio::RadioResponseInfo info;
    info.type = radio::RadioResponseType::SOLICITED;
    info.serial = serial;
    info.error = error;
    return info;
}

class RadioConfigService final : public config::BnRadioConfig {
public:
    ::ndk::ScopedAStatus getHalDeviceCapabilities(int32_t serial) override {
        auto response = responseSnapshot();
        if (!response) return notReady();
        return response->getHalDeviceCapabilitiesResponse(responseInfo(serial), false);
    }

    ::ndk::ScopedAStatus getNumOfLiveModems(int32_t serial) override {
        auto response = responseSnapshot();
        if (!response) return notReady();
        return response->getNumOfLiveModemsResponse(responseInfo(serial), 1);
    }

    ::ndk::ScopedAStatus getPhoneCapability(int32_t serial) override {
        auto response = responseSnapshot();
        if (!response) return notReady();
        config::PhoneCapability capability;
        capability.maxActiveData = 1;
        capability.maxActiveInternetData = 1;
        capability.isInternetLingeringSupported = false;
        capability.logicalModemIds = {0};
        return response->getPhoneCapabilityResponse(responseInfo(serial), capability);
    }

    ::ndk::ScopedAStatus getSimSlotsStatus(int32_t serial) override {
        auto response = responseSnapshot();
        if (!response) return notReady();
        config::SimPortInfo port;
        // The legacy RIL encodes this same staged ICCID into EF 0x2fe2; decoding
        // that EF's swapped-nibble BCD yields this byte-identical ASCII value.
        if (!loadProfileIccid(&port.iccId)) logProfileFallbackOnce();
        port.logicalSlotId = 0;
        port.portActive = true;
        config::SimSlotStatus slot;
        slot.cardState = 1;
        slot.atr = "3B9F96801FC7A0231200000000000000";
        slot.eid = "";
        slot.portInfo = {port};
        return response->getSimSlotsStatusResponse(responseInfo(serial), {slot});
    }

    ::ndk::ScopedAStatus setNumOfLiveModems(int32_t serial, int8_t number) override {
        auto response = responseSnapshot();
        if (!response) return notReady();
        radio::RadioError error = number == 1 ? radio::RadioError::NONE : radio::RadioError::INVALID_ARGUMENTS;
        return response->setNumOfLiveModemsResponse(responseInfo(serial, error));
    }

    ::ndk::ScopedAStatus setPreferredDataModem(int32_t serial, int8_t modemId) override {
        auto response = responseSnapshot();
        if (!response) return notReady();
        radio::RadioError error = modemId == 0 ? radio::RadioError::NONE : radio::RadioError::INVALID_ARGUMENTS;
        return response->setPreferredDataModemResponse(responseInfo(serial, error));
    }

    ::ndk::ScopedAStatus setResponseFunctions(
            const std::shared_ptr<config::IRadioConfigResponse>& response,
            const std::shared_ptr<config::IRadioConfigIndication>& indication) override {
        if (!response || !indication) {
            return ::ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        std::lock_guard<std::mutex> lock(mutex_);
        response_ = response;
        indication_ = indication;
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus setSimSlotsMapping(
            int32_t serial, const std::vector<config::SlotPortMapping>& mapping) override {
        auto response = responseSnapshot();
        if (!response) return notReady();
        bool valid = mapping.size() == 1 && mapping[0].physicalSlotId == 0 && mapping[0].portId == 0;
        radio::RadioError error = valid ? radio::RadioError::NONE : radio::RadioError::INVALID_ARGUMENTS;
        return response->setSimSlotsMappingResponse(responseInfo(serial, error));
    }

private:
    static ::ndk::ScopedAStatus notReady() {
        return ::ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
    }

    std::shared_ptr<config::IRadioConfigResponse> responseSnapshot() {
        std::lock_guard<std::mutex> lock(mutex_);
        return response_;
    }

    std::mutex mutex_;
    std::shared_ptr<config::IRadioConfigResponse> response_;
    std::shared_ptr<config::IRadioConfigIndication> indication_;
};
}  // namespace

int main() {
    ABinderProcess_setThreadPoolMaxThreadCount(1);
    auto service = ndk::SharedRefBase::make<RadioConfigService>();
    std::string instance = std::string(config::IRadioConfig::descriptor) + "/default";
    binder_status_t status = AServiceManager_addService(service->asBinder().get(), instance.c_str());
    if (status != STATUS_OK) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "registration failed: %d", status);
        return 1;
    }
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "registered %s", instance.c_str());
    ABinderProcess_joinThreadPool();
    return 1;
}
