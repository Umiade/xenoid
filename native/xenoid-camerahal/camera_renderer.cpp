#include "camera_renderer.h"

#include <array>
#include <android/bitmap.h>
#include <android/data_space.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>
#include <ctime>
#include <sys/random.h>
#include <sys/system_properties.h>
#include <time.h>

#include "camera_buffer.h"

namespace camera_provider {
namespace {

constexpr uint16_t kCameraJpegBlobId = 0x00ff;

struct JpegBlobFooter {
    uint16_t id;
    uint16_t padding;
    uint32_t size;
};

static_assert(sizeof(JpegBlobFooter) == 8);
static_assert(offsetof(JpegBlobFooter, size) == 4);

bool fail(std::string* error, const char* message) {
    if (error != nullptr) {
        *error = message;
    }
    return false;
}

bool checkedMultiply(size_t left, size_t right, size_t* result) {
    if (left != 0 && right > std::numeric_limits<size_t>::max() / left) {
        return false;
    }
    *result = left * right;
    return true;
}

bool checkedAdd(size_t left, size_t right, size_t* result) {
    if (right > std::numeric_limits<size_t>::max() - left) {
        return false;
    }
    *result = left + right;
    return true;
}

bool rangeFits(size_t offset, size_t length, size_t capacity) {
    return offset <= capacity && length <= capacity - offset;
}

uint8_t clampByte(int value) {
    return static_cast<uint8_t>(std::clamp(value, 0, 255));
}

uint64_t mix64(uint64_t value) {
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30U)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27U)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31U);
}

uint32_t normalizedCoordinate(int32_t coordinate, int32_t extent) {
    const uint64_t numerator =
            (static_cast<uint64_t>(coordinate) * 2U + 1U) * UINT64_C(65535);
    return static_cast<uint32_t>(numerator /
                                 (static_cast<uint64_t>(extent) * 2U));
}

uint32_t triangle16(uint64_t value) {
    const uint32_t phase = static_cast<uint32_t>(value & UINT64_C(0xffff));
    return phase <= 32767U ? phase : 65535U - phase;
}

int32_t smoothTriangle(uint64_t phase, uint64_t period, int32_t amplitude) {
    if (period < 2U || amplitude <= 0) {
        return 0;
    }
    const uint64_t half = period / 2U;
    const uint64_t position = phase % period;
    if (position <= half) {
        return -amplitude + static_cast<int32_t>(
                static_cast<uint64_t>(amplitude) * 2U * position / half);
    }
    const uint64_t descendingLength = period - half;
    return amplitude - static_cast<int32_t>(
            static_cast<uint64_t>(amplitude) * 2U * (position - half) /
            descendingLength);
}

int32_t interpolatedNoise(uint64_t first, uint64_t second, uint16_t blend,
                          unsigned shift, int32_t radius) {
    const uint64_t range = static_cast<uint64_t>(radius) * 2U + 1U;
    const int32_t firstValue =
            static_cast<int32_t>((first >> shift) % range) - radius;
    const int32_t secondValue =
            static_cast<int32_t>((second >> shift) % range) - radius;
    const int32_t weighted = firstValue * (256 - blend) + secondValue * blend;
    return weighted >= 0 ? (weighted + 128) / 256 : (weighted - 128) / 256;
}

void rotateVector(int32_t rotation, int32_t x, int32_t y, int32_t* rotatedX,
                  int32_t* rotatedY) {
    switch (rotation) {
        case 90:
            *rotatedX = -y;
            *rotatedY = x;
            break;
        case 180:
            *rotatedX = -x;
            *rotatedY = -y;
            break;
        case 270:
            *rotatedX = y;
            *rotatedY = -x;
            break;
        default:
            *rotatedX = x;
            *rotatedY = y;
            break;
    }
}

int64_t mappedCoordinate(int32_t coordinate, int32_t destinationExtent,
                         int32_t sourceExtent, int32_t scaleNumerator,
                         int32_t scaleDenominator, int32_t motion) {
    const __int128 centered =
            static_cast<__int128>(coordinate) * 2 + 1 - destinationExtent;
    __int128 value = centered * scaleDenominator * 65536;
    value /= static_cast<__int128>(scaleNumerator) * 2;
    value += static_cast<__int128>(sourceExtent - 1) * 32768;
    value += motion;
    const __int128 maximum =
            static_cast<__int128>(sourceExtent - 1) * 65536;
    if (value <= 0) {
        return 0;
    }
    if (value >= maximum) {
        return static_cast<int64_t>(maximum);
    }
    return static_cast<int64_t>(value);
}

void rgbToYuv(uint8_t red, uint8_t green, uint8_t blue, uint8_t* y,
              uint8_t* u, uint8_t* v) {
    const int r = red;
    const int g = green;
    const int b = blue;
    *y = clampByte(((66 * r + 129 * g + 25 * b + 128) >> 8) + 16);
    *u = clampByte((-38 * r - 74 * g + 112 * b + 32896) >> 8);
    *v = clampByte((112 * r - 94 * g - 18 * b + 32896) >> 8);
}

constexpr size_t kExifSegmentCapacity = 2048;
constexpr size_t kExifTiffOffset = 10;
constexpr uint16_t kTiffTypeAscii = 2;
constexpr uint16_t kTiffTypeShort = 3;
constexpr uint16_t kTiffTypeLong = 4;
constexpr uint16_t kTiffTypeRational = 5;
constexpr uint16_t kTiffTypeUndefined = 7;
constexpr uint16_t kTiffTypeSignedRational = 10;

struct ExifSegment {
    std::array<uint8_t, kExifSegmentCapacity> bytes{};
    size_t size = 0;
};

struct IfdWriter {
    ExifSegment* segment = nullptr;
    size_t entriesOffset = 0;
    uint16_t entryCount = 0;
    uint16_t nextEntry = 0;
};

void encodeLittleEndian16(uint16_t value, uint8_t* destination) {
    destination[0] = static_cast<uint8_t>(value);
    destination[1] = static_cast<uint8_t>(value >> 8U);
}

void encodeLittleEndian32(uint32_t value, uint8_t* destination) {
    destination[0] = static_cast<uint8_t>(value);
    destination[1] = static_cast<uint8_t>(value >> 8U);
    destination[2] = static_cast<uint8_t>(value >> 16U);
    destination[3] = static_cast<uint8_t>(value >> 24U);
}

bool appendExifBytes(ExifSegment* segment, const void* source, size_t size) {
    if (segment == nullptr || (source == nullptr && size != 0) ||
        !rangeFits(segment->size, size, segment->bytes.size())) {
        return false;
    }
    if (size != 0) {
        std::memcpy(segment->bytes.data() + segment->size, source, size);
        segment->size += size;
    }
    return true;
}

bool reserveExifBytes(ExifSegment* segment, size_t size) {
    if (segment == nullptr ||
        !rangeFits(segment->size, size, segment->bytes.size())) {
        return false;
    }
    std::memset(segment->bytes.data() + segment->size, 0, size);
    segment->size += size;
    return true;
}

bool alignExifData(ExifSegment* segment, size_t alignment) {
    if (segment == nullptr || segment->size < kExifTiffOffset ||
        alignment == 0) {
        return false;
    }
    const size_t relativeOffset = segment->size - kExifTiffOffset;
    const size_t padding =
            (alignment - (relativeOffset % alignment)) % alignment;
    return reserveExifBytes(segment, padding);
}

bool beginIfd(ExifSegment* segment, uint16_t entryCount, IfdWriter* writer,
              uint32_t* tiffOffset) {
    if (segment == nullptr || writer == nullptr || tiffOffset == nullptr ||
        !alignExifData(segment, 2U)) {
        return false;
    }
    const size_t relativeOffset = segment->size - kExifTiffOffset;
    if (relativeOffset > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    uint8_t encodedCount[2];
    encodeLittleEndian16(entryCount, encodedCount);
    if (!appendExifBytes(segment, encodedCount, sizeof(encodedCount))) {
        return false;
    }
    size_t entriesSize;
    size_t reservedSize;
    if (!checkedMultiply(static_cast<size_t>(entryCount), 12U, &entriesSize) ||
        !checkedAdd(entriesSize, 4U, &reservedSize) ||
        !reserveExifBytes(segment, reservedSize)) {
        return false;
    }
    writer->segment = segment;
    writer->entriesOffset = segment->size - reservedSize;
    writer->entryCount = entryCount;
    writer->nextEntry = 0;
    *tiffOffset = static_cast<uint32_t>(relativeOffset);
    return true;
}

bool writeIfdEntry(IfdWriter* writer, uint16_t tag, uint16_t type,
                   uint32_t count, const uint8_t* value, size_t valueSize,
                   size_t alignment) {
    if (writer == nullptr || writer->segment == nullptr ||
        writer->nextEntry >= writer->entryCount ||
        (value == nullptr && valueSize != 0)) {
        return false;
    }
    size_t entryDelta;
    size_t entryOffset;
    if (!checkedMultiply(static_cast<size_t>(writer->nextEntry), 12U,
                         &entryDelta) ||
        !checkedAdd(writer->entriesOffset, entryDelta, &entryOffset) ||
        !rangeFits(entryOffset, 12U, writer->segment->bytes.size())) {
        return false;
    }

    uint8_t* const entry = writer->segment->bytes.data() + entryOffset;
    encodeLittleEndian16(tag, entry);
    encodeLittleEndian16(type, entry + 2U);
    encodeLittleEndian32(count, entry + 4U);
    std::memset(entry + 8U, 0, 4U);
    if (valueSize <= 4U) {
        if (valueSize != 0) {
            std::memcpy(entry + 8U, value, valueSize);
        }
    } else {
        if (!alignExifData(writer->segment, alignment)) {
            return false;
        }
        const size_t relativeOffset =
                writer->segment->size - kExifTiffOffset;
        if (relativeOffset > std::numeric_limits<uint32_t>::max() ||
            !appendExifBytes(writer->segment, value, valueSize)) {
            return false;
        }
        encodeLittleEndian32(static_cast<uint32_t>(relativeOffset), entry + 8U);
    }
    ++writer->nextEntry;
    return true;
}

bool writeIfdAscii(IfdWriter* writer, uint16_t tag, const char* value) {
    if (value == nullptr) {
        return false;
    }
    const size_t length = std::strlen(value) + 1U;
    if (length > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    return writeIfdEntry(writer, tag, kTiffTypeAscii,
                         static_cast<uint32_t>(length),
                         reinterpret_cast<const uint8_t*>(value), length, 2U);
}

bool writeIfdShort(IfdWriter* writer, uint16_t tag, uint16_t value) {
    uint8_t encoded[2];
    encodeLittleEndian16(value, encoded);
    return writeIfdEntry(writer, tag, kTiffTypeShort, 1U, encoded,
                         sizeof(encoded), 2U);
}

bool writeIfdLong(IfdWriter* writer, uint16_t tag, uint32_t value) {
    uint8_t encoded[4];
    encodeLittleEndian32(value, encoded);
    return writeIfdEntry(writer, tag, kTiffTypeLong, 1U, encoded,
                         sizeof(encoded), 4U);
}

bool writeIfdRational(IfdWriter* writer, uint16_t tag, uint32_t numerator,
                      uint32_t denominator) {
    if (denominator == 0) {
        return false;
    }
    uint8_t encoded[8];
    encodeLittleEndian32(numerator, encoded);
    encodeLittleEndian32(denominator, encoded + 4U);
    return writeIfdEntry(writer, tag, kTiffTypeRational, 1U, encoded,
                         sizeof(encoded), 4U);
}

bool writeIfdSignedRational(IfdWriter* writer, uint16_t tag,
                            int32_t numerator, int32_t denominator) {
    if (denominator == 0) {
        return false;
    }
    uint8_t encoded[8];
    encodeLittleEndian32(static_cast<uint32_t>(numerator), encoded);
    encodeLittleEndian32(static_cast<uint32_t>(denominator), encoded + 4U);
    return writeIfdEntry(writer, tag, kTiffTypeSignedRational, 1U, encoded,
                         sizeof(encoded), 4U);
}

bool writeIfdUndefined4(IfdWriter* writer, uint16_t tag,
                        const std::array<uint8_t, 4>& value) {
    return writeIfdEntry(writer, tag, kTiffTypeUndefined, 4U, value.data(),
                         value.size(), 2U);
}

bool finishIfd(const IfdWriter& writer) {
    return writer.segment != nullptr && writer.nextEntry == writer.entryCount;
}

template <size_t Size>
void readSanitizedProperty(const char* name, const char* fallback,
                           std::array<char, Size>* output) {
    static_assert(Size > 1);
    char raw[PROP_VALUE_MAX] = {};
    const int propertyLength = __system_property_get(name, raw);
    const char* source = propertyLength > 0 ? raw : fallback;
    size_t destinationIndex = 0;
    for (size_t sourceIndex = 0;
         source[sourceIndex] != '\0' && destinationIndex + 1U < output->size();
         ++sourceIndex) {
        const uint8_t character = static_cast<uint8_t>(source[sourceIndex]);
        (*output)[destinationIndex++] =
                character >= 0x20U && character <= 0x7eU
                ? static_cast<char>(character)
                : '_';
    }
    (*output)[destinationIndex] = '\0';
}

struct ExifIdentity {
    std::array<char, PROP_VALUE_MAX> manufacturer{};
    std::array<char, PROP_VALUE_MAX> model{};
    std::array<char, 192> frontLens{};
    std::array<char, 192> rearLens{};
    std::array<char, 192> genericLens{};
};

ExifIdentity loadExifIdentity() {
    ExifIdentity identity;
    readSanitizedProperty("ro.product.manufacturer", "Android",
                          &identity.manufacturer);
    readSanitizedProperty("ro.product.model", "Android device",
                          &identity.model);
    std::snprintf(identity.frontLens.data(), identity.frontLens.size(),
                  "%s front 4.38 mm camera", identity.model.data());
    std::snprintf(identity.rearLens.data(), identity.rearLens.size(),
                  "%s rear 4.38 mm camera", identity.model.data());
    std::snprintf(identity.genericLens.data(), identity.genericLens.size(),
                  "%s 4.38 mm camera", identity.model.data());
    return identity;
}

const ExifIdentity& exifIdentity() {
    static const ExifIdentity identity = loadExifIdentity();
    return identity;
}

bool formatCaptureTimestamp(const FrameTiming& timing,
                            std::array<char, 20>* dateTime,
                            std::array<char, 10>* subseconds) {
    timespec realtime{};
    if (clock_gettime(CLOCK_REALTIME, &realtime) != 0) {
        return false;
    }
    __int128 captureNanoseconds =
            static_cast<__int128>(realtime.tv_sec) * 1'000'000'000LL +
            realtime.tv_nsec;
    timespec bootTime{};
    if (timing.timestampNs > 0 &&
        clock_gettime(CLOCK_BOOTTIME, &bootTime) == 0) {
        const __int128 currentBootNanoseconds =
                static_cast<__int128>(bootTime.tv_sec) * 1'000'000'000LL +
                bootTime.tv_nsec;
        const __int128 frameRealtimeNanoseconds =
                captureNanoseconds -
                (currentBootNanoseconds - timing.timestampNs);
        if (frameRealtimeNanoseconds >= 0) {
            captureNanoseconds = frameRealtimeNanoseconds;
        }
    }

    const __int128 secondsWide = captureNanoseconds / 1'000'000'000LL;
    const long nanoseconds = static_cast<long>(
            captureNanoseconds % 1'000'000'000LL);
    const time_t seconds = static_cast<time_t>(secondsWide);
    if (static_cast<__int128>(seconds) != secondsWide) {
        return false;
    }
    tm utc{};
    if (gmtime_r(&seconds, &utc) == nullptr ||
        std::strftime(dateTime->data(), dateTime->size(),
                      "%Y:%m:%d %H:%M:%S", &utc) != 19U ||
        std::snprintf(subseconds->data(), subseconds->size(), "%09ld",
                      nanoseconds) != 9) {
        return false;
    }
    return true;
}

uint32_t greatestCommonDivisor(uint32_t left, uint32_t right) {
    while (right != 0U) {
        const uint32_t remainder = left % right;
        left = right;
        right = remainder;
    }
    return left;
}

bool buildExifSegment(const RequestSettings& settings,
                      const FrameTiming& timing, int32_t sensorOrientation,
                      int32_t width, int32_t height, ExifSegment* segment) {
    if (segment == nullptr || width <= 0 || height <= 0 ||
        timing.exposureTimeNs <= 0 ||
        timing.exposureTimeNs > std::numeric_limits<uint32_t>::max() ||
        timing.sensitivity <= 0 ||
        timing.sensitivity > std::numeric_limits<uint16_t>::max()) {
        return false;
    }
    *segment = ExifSegment{};
    constexpr std::array<uint8_t, 18> header = {
            0xff, 0xe1, 0x00, 0x00, 'E',  'x',  'i',  'f',  0x00,
            0x00, 'I',  'I',  0x2a, 0x00, 0x08, 0x00, 0x00, 0x00,
    };
    if (!appendExifBytes(segment, header.data(), header.size())) {
        return false;
    }

    std::array<char, 20> dateTime{};
    std::array<char, 10> subseconds{};
    if (!formatCaptureTimestamp(timing, &dateTime, &subseconds)) {
        return false;
    }
    const ExifIdentity& identity = exifIdentity();

    IfdWriter primaryIfd;
    uint32_t primaryOffset;
    if (!beginIfd(segment, 5U, &primaryIfd, &primaryOffset) ||
        primaryOffset != 8U ||
        !writeIfdAscii(&primaryIfd, 0x010f, identity.manufacturer.data()) ||
        !writeIfdAscii(&primaryIfd, 0x0110, identity.model.data()) ||
        !writeIfdShort(&primaryIfd, 0x0112, 1U) ||
        !writeIfdAscii(&primaryIfd, 0x0132, dateTime.data())) {
        return false;
    }

    IfdWriter exifIfd;
    uint32_t exifIfdOffset;
    if (!beginIfd(segment, 15U, &exifIfd, &exifIfdOffset) ||
        !writeIfdLong(&primaryIfd, 0x8769, exifIfdOffset) ||
        !finishIfd(primaryIfd)) {
        return false;
    }

    uint32_t exposureNumerator =
            static_cast<uint32_t>(timing.exposureTimeNs);
    uint32_t exposureDenominator = 1'000'000'000U;
    const uint32_t exposureDivisor =
            greatestCommonDivisor(exposureNumerator, exposureDenominator);
    exposureNumerator /= exposureDivisor;
    exposureDenominator /= exposureDivisor;
    constexpr std::array<uint8_t, 4> exifVersion = {'0', '2', '3', '1'};
    constexpr char utcOffset[] = "+00:00";
    const uint16_t exposureMode =
            settings.controlMode != 0 && settings.aeMode == 1 ? 0U : 1U;
    const uint16_t whiteBalance =
            settings.controlMode != 0 && settings.awbMode == 1 ? 0U : 1U;
    const char* lensModel = sensorOrientation == 270
            ? identity.frontLens.data()
            : (sensorOrientation == 90 ? identity.rearLens.data()
                                       : identity.genericLens.data());
    if (!writeIfdRational(&exifIfd, 0x829a, exposureNumerator,
                          exposureDenominator) ||
        !writeIfdShort(&exifIfd, 0x8827,
                       static_cast<uint16_t>(timing.sensitivity)) ||
        !writeIfdUndefined4(&exifIfd, 0x9000, exifVersion) ||
        !writeIfdAscii(&exifIfd, 0x9003, dateTime.data()) ||
        !writeIfdAscii(&exifIfd, 0x9011, utcOffset) ||
        !writeIfdSignedRational(&exifIfd, 0x9204,
                                settings.aeExposureCompensation, 1) ||
        !writeIfdRational(&exifIfd, 0x920a, 438U, 100U) ||
        !writeIfdAscii(&exifIfd, 0x9291, subseconds.data()) ||
        !writeIfdShort(&exifIfd, 0xa001, 1U) ||
        !writeIfdLong(&exifIfd, 0xa002, static_cast<uint32_t>(width)) ||
        !writeIfdLong(&exifIfd, 0xa003, static_cast<uint32_t>(height)) ||
        !writeIfdShort(&exifIfd, 0xa402, exposureMode) ||
        !writeIfdShort(&exifIfd, 0xa403, whiteBalance) ||
        !writeIfdAscii(&exifIfd, 0xa433, identity.manufacturer.data()) ||
        !writeIfdAscii(&exifIfd, 0xa434, lensModel) ||
        !finishIfd(exifIfd)) {
        return false;
    }

    if (segment->size < 4U ||
        segment->size - 2U > std::numeric_limits<uint16_t>::max()) {
        return false;
    }
    const uint16_t app1Length = static_cast<uint16_t>(segment->size - 2U);
    segment->bytes[2] = static_cast<uint8_t>(app1Length >> 8U);
    segment->bytes[3] = static_cast<uint8_t>(app1Length);
    return true;
}

}  // namespace

CameraRenderer::CameraRenderer(int32_t sensorOrientation)
    : sensorOrientation_(normalizeRotation(sensorOrientation)),
      sensorOrientationValid_(isRightAngle(sensorOrientation)) {
    uint64_t randomSeed = 0;
    size_t filled = 0;
    auto* destination = reinterpret_cast<uint8_t*>(&randomSeed);
    while (filled < sizeof(randomSeed)) {
        const ssize_t count =
                getrandom(destination + filled, sizeof(randomSeed) - filled, 0);
        if (count > 0) {
            filled += static_cast<size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    if (filled != sizeof(randomSeed)) {
        randomSeed = mix64(static_cast<uint64_t>(
                                     reinterpret_cast<uintptr_t>(this)) ^
                           static_cast<uint32_t>(sensorOrientation));
    }
    seed_ = mix64(randomSeed);
}

bool CameraRenderer::isRightAngle(int32_t degrees) {
    return degrees % 90 == 0;
}

int32_t CameraRenderer::normalizeRotation(int32_t degrees) {
    int32_t normalized = degrees % 360;
    if (normalized < 0) {
        normalized += 360;
    }
    return normalized;
}

bool CameraRenderer::sameIdentity(const ScratchIdentity& left,
                                  const ScratchIdentity& right) {
    return left.source == right.source &&
            left.sourceBytes == right.sourceBytes &&
            left.sourceWidth == right.sourceWidth &&
            left.sourceHeight == right.sourceHeight &&
            left.sourceStride == right.sourceStride &&
            left.sourceRotation == right.sourceRotation &&
            left.outputRotation == right.outputRotation &&
            left.width == right.width && left.height == right.height &&
            left.frameNumber == right.frameNumber &&
            left.timestampNs == right.timestampNs &&
            left.fallbackKey == right.fallbackKey &&
            left.fallbackPhase == right.fallbackPhase &&
            left.mode == right.mode &&
            left.sourceAvailable == right.sourceAvailable;
}

bool CameraRenderer::appendJpeg(void* context, const void* data, size_t size) {
    auto* output = static_cast<JpegWriteContext*>(context);
    if (output == nullptr || (data == nullptr && size != 0) ||
        !rangeFits(output->size, size, output->capacity)) {
        return false;
    }
    if (size != 0) {
        std::memcpy(output->destination + output->size, data, size);
        output->size += size;
    }
    return true;
}

CameraRenderer::SceneState CameraRenderer::makeSceneState(
        const RequestSettings& settings, const FrameTiming& timing,
        int64_t frameNumber) {
    uint64_t key = mix64(static_cast<uint64_t>(frameNumber));
    key ^= mix64(static_cast<uint64_t>(timing.timestampNs));
    key ^= mix64(static_cast<uint64_t>(timing.frameDurationNs));
    key ^= mix64(static_cast<uint64_t>(timing.exposureTimeNs));
    key ^= mix64(static_cast<uint32_t>(timing.sensitivity));
    key ^= mix64(static_cast<uint32_t>(settings.aeExposureCompensation));
    key = mix64(key);

    const uint64_t cadence = timing.frameDurationNs > 0
            ? static_cast<uint64_t>(timing.timestampNs / timing.frameDurationNs)
            : static_cast<uint64_t>(frameNumber);
    const uint64_t phase =
            static_cast<uint64_t>(frameNumber) * 977U + cadence * 257U;
    const uint32_t centerX =
            16384U + triangle16(phase) * 32768U / 32767U;
    const uint32_t centerY =
            16384U + triangle16(phase * 3U + 19087U) * 32768U / 32767U;
    const int exposureLift = static_cast<int>(std::clamp<int64_t>(
            timing.exposureTimeNs / 2'000'000LL, 0, 8));
    const int sensitivityLift =
            std::clamp(timing.sensitivity / 100 - 1, 0, 4);
    const int compensationLift =
            std::clamp(settings.aeExposureCompensation, -2, 2);
    return SceneState{key, phase, centerX, centerY,
                      exposureLift + sensitivityLift + compensationLift};
}

CameraRenderer::NaturalState CameraRenderer::makeNaturalState(
        const FrameTiming& timing, int64_t frameNumber) const {
    const uint64_t timestamp = timing.timestampNs > 0
            ? static_cast<uint64_t>(timing.timestampNs)
            : 0U;
    const uint64_t milliseconds = timestamp / UINT64_C(1000000);
    const uint64_t frameTick = frameNumber >= 0
            ? static_cast<uint64_t>(frameNumber)
            : timestamp / static_cast<uint64_t>(kNominalFrameDurationNs);
    const uint64_t phaseA = milliseconds + (seed_ & UINT64_C(0xffff));
    const uint64_t phaseB =
            milliseconds + ((seed_ >> 16U) & UINT64_C(0xffff));
    const uint64_t phaseC =
            milliseconds + ((seed_ >> 32U) & UINT64_C(0xffff));

    NaturalState state{};
    state.noiseEpoch = frameTick / 4U;
    state.noiseBlend = static_cast<uint16_t>((frameTick % 4U) * 64U);
    state.motionX = smoothTriangle(phaseA, 5101U, 24576);
    state.motionY = smoothTriangle(phaseB, 7297U, 24576);
    state.exposureGain = 4096 + smoothTriangle(phaseC, 7919U, 20);
    state.redGain = 4096 + smoothTriangle(phaseA, 9349U, 9);
    state.blueGain = 4096 + smoothTriangle(phaseB, 10613U, 9);
    return state;
}

CameraRenderer::Rgb CameraRenderer::scenePixel(const SceneState& state,
                                                uint32_t normalizedX,
                                                uint32_t normalizedY) {
    const int dx = static_cast<int>(normalizedX) - 32768;
    const int dy = static_cast<int>(normalizedY) - 32768;
    const uint64_t radial = static_cast<uint64_t>(static_cast<int64_t>(dx) * dx) +
                            static_cast<uint64_t>(static_cast<int64_t>(dy) * dy);
    constexpr uint64_t kMaximumRadial = UINT64_C(2) * 32768U * 32768U;
    const int vignette = static_cast<int>(radial * 12U / kMaximumRadial);

    const int64_t glowDx = static_cast<int64_t>(normalizedX) - state.centerX;
    const int64_t glowDy = static_cast<int64_t>(normalizedY) - state.centerY;
    const uint64_t glowDistance = static_cast<uint64_t>(glowDx * glowDx) +
                                  static_cast<uint64_t>(glowDy * glowDy);
    constexpr uint64_t kGlowRadiusSquared = UINT64_C(14500) * 14500U;
    const int glow = glowDistance < kGlowRadiusSquared
            ? static_cast<int>((kGlowRadiusSquared - glowDistance) * 14U /
                               kGlowRadiusSquared)
            : 0;

    const uint32_t wavePhase =
            ((normalizedX >> 3U) + (normalizedY >> 4U) +
             static_cast<uint32_t>(state.phase >> 2U)) &
            2047U;
    const uint32_t waveTriangle =
            wavePhase <= 1023U ? wavePhase : 2047U - wavePhase;
    const int wave = static_cast<int>(waveTriangle / 128U);

    const uint64_t spatial =
            mix64(static_cast<uint64_t>(normalizedX >> 6U) *
                          UINT64_C(0xd6e8feb86659fd93) ^
                  static_cast<uint64_t>(normalizedY >> 6U) *
                          UINT64_C(0xa5a3564e27f8862f));
    const int fixedPattern = static_cast<int>(spatial % 5U) - 2;
    const int temporalNoise =
            static_cast<int>(mix64(state.key ^ spatial) & 7U) - 3;

    const int base = 8 + static_cast<int>(normalizedX * 9U >> 16U) +
                     static_cast<int>(normalizedY * 7U >> 16U) - vignette + glow +
                     wave + fixedPattern + temporalNoise + state.baseLift;

    const int redBias =
            static_cast<int>(((normalizedX * 5U + normalizedY * 3U +
                               static_cast<uint32_t>(state.phase) * 7U) >>
                              11U) &
                             7U) -
            3;
    const int blueBias =
            static_cast<int>(((normalizedX * 2U + (65535U - normalizedY) * 7U +
                               static_cast<uint32_t>(state.phase) * 3U) >>
                              12U) &
                             7U) -
            3;

    return Rgb{clampByte(base + redBias), clampByte(base),
               clampByte(base + blueBias)};
}

CameraRenderer::Rgb CameraRenderer::sampleSource(const SourceFrame& source,
                                                 int64_t sourceX,
                                                 int64_t sourceY) {
    const int32_t x0 = static_cast<int32_t>(sourceX >> 16U);
    const int32_t y0 = static_cast<int32_t>(sourceY >> 16U);
    const int32_t x1 = std::min(x0 + 1, source.width - 1);
    const int32_t y1 = std::min(y0 + 1, source.height - 1);
    const uint32_t fractionX = static_cast<uint32_t>(sourceX) & 0xffffU;
    const uint32_t fractionY = static_cast<uint32_t>(sourceY) & 0xffffU;
    const uint8_t* row0 =
            source.rgba + static_cast<size_t>(y0) * source.rowStride;
    const uint8_t* row1 =
            source.rgba + static_cast<size_t>(y1) * source.rowStride;
    const uint8_t* pixel00 = row0 + static_cast<size_t>(x0) * 4U;
    const uint8_t* pixel10 = row0 + static_cast<size_t>(x1) * 4U;
    const uint8_t* pixel01 = row1 + static_cast<size_t>(x0) * 4U;
    const uint8_t* pixel11 = row1 + static_cast<size_t>(x1) * 4U;

    auto interpolate = [&](size_t channel) {
        const uint32_t top =
                (static_cast<uint32_t>(pixel00[channel]) *
                         (65536U - fractionX) +
                 static_cast<uint32_t>(pixel10[channel]) * fractionX +
                 32768U) >>
                16U;
        const uint32_t bottom =
                (static_cast<uint32_t>(pixel01[channel]) *
                         (65536U - fractionX) +
                 static_cast<uint32_t>(pixel11[channel]) * fractionX +
                 32768U) >>
                16U;
        return static_cast<uint8_t>(
                (top * (65536U - fractionY) + bottom * fractionY + 32768U) >>
                16U);
    };
    return Rgb{interpolate(0), interpolate(1), interpolate(2)};
}

CameraRenderer::Rgb CameraRenderer::naturalizePixel(
        const Rgb& pixel, const NaturalState& state, uint64_t seed,
        uint32_t normalizedX, uint32_t normalizedY) {
    const uint64_t spatial =
            mix64(seed ^ (static_cast<uint64_t>(normalizedX) << 32U) ^
                  normalizedY);
    const uint64_t first =
            mix64(spatial ^ mix64(state.noiseEpoch *
                                  UINT64_C(0xd6e8feb86659fd93)));
    const uint64_t second =
            mix64(spatial ^ mix64((state.noiseEpoch + 1U) *
                                  UINT64_C(0xd6e8feb86659fd93)));
    const int32_t luma =
            interpolatedNoise(first, second, state.noiseBlend, 0U, 2);
    const int32_t redChroma =
            interpolatedNoise(first, second, state.noiseBlend, 9U, 1);
    const int32_t blueChroma =
            interpolatedNoise(first, second, state.noiseBlend, 18U, 1);

    auto applyGain = [&](uint8_t value, int32_t colorGain) {
        const int64_t scaled = static_cast<int64_t>(value) *
                state.exposureGain * colorGain;
        return static_cast<int32_t>((scaled + (INT64_C(1) << 23U)) >> 24U);
    };
    return Rgb{clampByte(applyGain(pixel.red, state.redGain) + luma +
                         redChroma),
               clampByte(applyGain(pixel.green, 4096) + luma),
               clampByte(applyGain(pixel.blue, state.blueGain) + luma +
                         blueChroma)};
}

bool CameraRenderer::resizeScratch(int32_t width, int32_t height,
                                   std::string* error) {
    size_t pixelCount;
    size_t byteCount;
    if (width <= 0 || height <= 0 ||
        !checkedMultiply(static_cast<size_t>(width), static_cast<size_t>(height),
                         &pixelCount) ||
        !checkedMultiply(pixelCount, 4U, &byteCount) ||
        byteCount > rgbaScratch_.max_size() ||
        static_cast<size_t>(width) > normalizedXScratch_.max_size() ||
        static_cast<size_t>(width) > coordinateXScratch_.max_size() ||
        static_cast<size_t>(height) > coordinateYScratch_.max_size()) {
        return fail(error, "renderer dimensions overflow scratch storage");
    }
    try {
        rgbaScratch_.resize(byteCount);
        normalizedXScratch_.resize(static_cast<size_t>(width));
        coordinateXScratch_.resize(static_cast<size_t>(width));
        coordinateYScratch_.resize(static_cast<size_t>(height));
    } catch (const std::bad_alloc&) {
        return fail(error, "renderer could not allocate scratch storage");
    }
    return true;
}

bool CameraRenderer::renderFallbackScratch(const SceneState& state,
                                           int32_t outputRotation,
                                           int32_t width, int32_t height,
                                           std::string* error) {
    if (!resizeScratch(width, height, error)) {
        return false;
    }
    for (int32_t x = 0; x < width; ++x) {
        normalizedXScratch_[static_cast<size_t>(x)] =
                normalizedCoordinate(x, width);
    }

    const size_t rowBytes = static_cast<size_t>(width) * 4U;
    for (int32_t y = 0; y < height; ++y) {
        const size_t rowOffset = static_cast<size_t>(y) * rowBytes;
        if (!rangeFits(rowOffset, rowBytes, rgbaScratch_.size())) {
            return fail(error, "renderer fallback row exceeds scratch storage");
        }
        uint8_t* row = rgbaScratch_.data() + rowOffset;
        const uint32_t outputY = normalizedCoordinate(y, height);
        for (int32_t x = 0; x < width; ++x) {
            const uint32_t outputX =
                    normalizedXScratch_[static_cast<size_t>(x)];
            uint32_t displayX;
            uint32_t displayY;
            switch (outputRotation) {
                case 90:
                    displayX = outputY;
                    displayY = 65535U - outputX;
                    break;
                case 180:
                    displayX = 65535U - outputX;
                    displayY = 65535U - outputY;
                    break;
                case 270:
                    displayX = 65535U - outputY;
                    displayY = outputX;
                    break;
                default:
                    displayX = outputX;
                    displayY = outputY;
                    break;
            }
            const Rgb pixel = scenePixel(state, displayX, displayY);
            const size_t offset = static_cast<size_t>(x) * 4U;
            row[offset] = pixel.red;
            row[offset + 1U] = pixel.green;
            row[offset + 2U] = pixel.blue;
            row[offset + 3U] = 255;
        }
    }
    return true;
}

bool CameraRenderer::renderSourceScratch(const SourceFrame& source,
                                         const NaturalState* naturalState,
                                         int32_t outputRotation, int32_t width,
                                         int32_t height, std::string* error) {
    if (!resizeScratch(width, height, error)) {
        return false;
    }

    const int32_t sourceRotation = normalizeRotation(source.rotationDegrees);
    const int32_t totalRotation =
            normalizeRotation(sourceRotation + outputRotation);
    const bool swapsAxes = totalRotation == 90 || totalRotation == 270;
    const int32_t orientedWidth = swapsAxes ? source.height : source.width;
    const int32_t orientedHeight = swapsAxes ? source.width : source.height;

    int32_t motionX = 0;
    int32_t motionY = 0;
    if (naturalState != nullptr) {
        rotateVector(outputRotation, naturalState->motionX,
                     naturalState->motionY, &motionX, &motionY);
    }
    for (int32_t x = 0; x < width; ++x) {
        coordinateXScratch_[static_cast<size_t>(x)] = mappedCoordinate(
                x, width, orientedWidth, width, orientedWidth, motionX);
        normalizedXScratch_[static_cast<size_t>(x)] =
                normalizedCoordinate(x, width);
    }
    for (int32_t y = 0; y < height; ++y) {
        coordinateYScratch_[static_cast<size_t>(y)] = mappedCoordinate(
                y, height, orientedHeight, height, orientedHeight, motionY);
    }

    const int64_t maximumRawX =
            static_cast<int64_t>(source.width - 1) * 65536;
    const int64_t maximumRawY =
            static_cast<int64_t>(source.height - 1) * 65536;
    const size_t rowBytes = static_cast<size_t>(width) * 4U;
    for (int32_t y = 0; y < height; ++y) {
        const size_t rowOffset = static_cast<size_t>(y) * rowBytes;
        if (!rangeFits(rowOffset, rowBytes, rgbaScratch_.size())) {
            return fail(error, "renderer source row exceeds scratch storage");
        }
        uint8_t* row = rgbaScratch_.data() + rowOffset;
        const int64_t orientedY =
                coordinateYScratch_[static_cast<size_t>(y)];
        const uint32_t normalizedY = normalizedCoordinate(y, height);
        for (int32_t x = 0; x < width; ++x) {
            const int64_t orientedX =
                    coordinateXScratch_[static_cast<size_t>(x)];
            int64_t rawX;
            int64_t rawY;
            switch (totalRotation) {
                case 90:
                    rawX = orientedY;
                    rawY = maximumRawY - orientedX;
                    break;
                case 180:
                    rawX = maximumRawX - orientedX;
                    rawY = maximumRawY - orientedY;
                    break;
                case 270:
                    rawX = maximumRawX - orientedY;
                    rawY = orientedX;
                    break;
                default:
                    rawX = orientedX;
                    rawY = orientedY;
                    break;
            }
            Rgb pixel = sampleSource(source, rawX, rawY);
            if (naturalState != nullptr) {
                pixel = naturalizePixel(
                        pixel, *naturalState, seed_,
                        normalizedXScratch_[static_cast<size_t>(x)],
                        normalizedY);
            }
            const size_t offset = static_cast<size_t>(x) * 4U;
            row[offset] = pixel.red;
            row[offset + 1U] = pixel.green;
            row[offset + 2U] = pixel.blue;
            row[offset + 3U] = 255;
        }
    }
    return true;
}

bool CameraRenderer::renderScratch(const RequestSettings& settings,
                                   const FrameTiming& timing,
                                   int64_t frameNumber,
                                   const SourceFrame& source, SourceMode mode,
                                   int32_t outputRotation, int32_t width,
                                   int32_t height, std::string* error) {
    if (mode != SourceMode::Naturalized && mode != SourceMode::Faithful) {
        return fail(error, "renderer source mode is invalid");
    }

    const bool sourceAvailable = source.rgba != nullptr;
    if (!sourceAvailable &&
        (source.rgbaBytes != 0 || source.width != 0 || source.height != 0 ||
         source.rowStride != 0 || source.rotationDegrees != 0)) {
        return fail(error, "unavailable source frame has an invalid layout");
    }
    if (sourceAvailable) {
        size_t sourceRowBytes;
        size_t requiredSourceBytes;
        if (source.width <= 0 || source.height <= 0 || source.rowStride <= 0 ||
            !isRightAngle(source.rotationDegrees) ||
            !checkedMultiply(static_cast<size_t>(source.width), 4U,
                             &sourceRowBytes) ||
            sourceRowBytes > static_cast<size_t>(source.rowStride) ||
            !checkedMultiply(static_cast<size_t>(source.rowStride),
                             static_cast<size_t>(source.height),
                             &requiredSourceBytes) ||
            requiredSourceBytes > source.rgbaBytes) {
            return fail(error, "source frame layout is invalid");
        }
    }

    size_t pixelCount;
    size_t byteCount;
    if (width <= 0 || height <= 0 ||
        !checkedMultiply(static_cast<size_t>(width), static_cast<size_t>(height),
                         &pixelCount) ||
        !checkedMultiply(pixelCount, 4U, &byteCount)) {
        return fail(error, "renderer dimensions overflow scratch storage");
    }

    const SceneState fallbackState =
            makeSceneState(settings, timing, frameNumber);
    ScratchIdentity identity{};
    identity.source = source.rgba;
    identity.sourceBytes = source.rgbaBytes;
    identity.sourceWidth = source.width;
    identity.sourceHeight = source.height;
    identity.sourceStride = source.rowStride;
    identity.sourceRotation = source.rotationDegrees;
    identity.outputRotation = outputRotation;
    identity.width = width;
    identity.height = height;
    identity.frameNumber = frameNumber;
    identity.timestampNs = timing.timestampNs;
    identity.fallbackKey = fallbackState.key;
    identity.fallbackPhase = fallbackState.phase;
    identity.mode = mode;
    identity.sourceAvailable = sourceAvailable;
    if (scratchValid_ && sameIdentity(renderedIdentity_, identity) &&
        rgbaScratch_.size() == byteCount) {
        return true;
    }
    scratchValid_ = false;

    bool rendered;
    if (sourceAvailable) {
        NaturalState naturalState{};
        const NaturalState* naturalStatePointer = nullptr;
        if (mode == SourceMode::Naturalized) {
            naturalState = makeNaturalState(timing, frameNumber);
            naturalStatePointer = &naturalState;
        }
        rendered = renderSourceScratch(source, naturalStatePointer,
                                       outputRotation, width, height, error);
    } else {
        rendered = renderFallbackScratch(fallbackState, outputRotation, width,
                                         height, error);
    }
    if (!rendered) {
        return false;
    }
    renderedIdentity_ = identity;
    scratchValid_ = true;
    return true;
}

bool CameraRenderer::writeRgba(int32_t width, int32_t height,
                               CachedBuffer& buffer, std::string* error) const {
    const int32_t stridePixels = buffer.lumaStride();
    size_t rowBytes;
    size_t strideBytes;
    size_t lastRowOffset;
    if (stridePixels < width || stridePixels <= 0 ||
        !checkedMultiply(static_cast<size_t>(width), 4U, &rowBytes) ||
        !checkedMultiply(static_cast<size_t>(stridePixels), 4U, &strideBytes) ||
        !checkedMultiply(static_cast<size_t>(height - 1), strideBytes,
                         &lastRowOffset) ||
        !rangeFits(lastRowOffset, rowBytes, buffer.capacity())) {
        return fail(error, "RGBA layout exceeds mapped buffer");
    }
    if (buffer.data() == nullptr) {
        return fail(error, "RGBA buffer is not mapped");
    }

    for (int32_t y = 0; y < height; ++y) {
        size_t sourceOffset;
        size_t destinationOffset;
        if (!checkedMultiply(static_cast<size_t>(y), rowBytes, &sourceOffset) ||
            !checkedMultiply(static_cast<size_t>(y), strideBytes,
                             &destinationOffset) ||
            !rangeFits(sourceOffset, rowBytes, rgbaScratch_.size()) ||
            !rangeFits(destinationOffset, rowBytes, buffer.capacity())) {
            return fail(error, "RGBA row exceeds mapped buffer");
        }
        std::memcpy(buffer.data() + destinationOffset,
                    rgbaScratch_.data() + sourceOffset, rowBytes);
    }
    return true;
}

bool CameraRenderer::writeYuv(int32_t width, int32_t height,
                              CachedBuffer& buffer, std::string* error) const {
    const int32_t yStrideValue = buffer.lumaStride();
    const int32_t cStrideValue = buffer.chromaStride();
    const size_t chromaRowBytes =
            (static_cast<size_t>(width) + 1U) / 2U * 2U;
    if (yStrideValue < width || cStrideValue <= 0 ||
        static_cast<size_t>(cStrideValue) < chromaRowBytes) {
        return fail(error, "YUV strides are smaller than the image planes");
    }

    const size_t yStride = static_cast<size_t>(yStrideValue);
    const size_t cStride = static_cast<size_t>(cStrideValue);
    const size_t alignedHeight = (static_cast<size_t>(height) + 1U) & ~size_t{1};
    const size_t chromaRows = (static_cast<size_t>(height) + 1U) / 2U;
    size_t yPlaneBytes;
    size_t lastYRowOffset;
    size_t lastChromaRowOffset;
    if (!checkedMultiply(yStride, alignedHeight, &yPlaneBytes) ||
        !checkedMultiply(static_cast<size_t>(height - 1), yStride,
                         &lastYRowOffset) ||
        !rangeFits(lastYRowOffset, static_cast<size_t>(width),
                   buffer.capacity()) ||
        !checkedMultiply(chromaRows - 1U, cStride, &lastChromaRowOffset) ||
        !checkedAdd(yPlaneBytes, lastChromaRowOffset, &lastChromaRowOffset) ||
        !rangeFits(lastChromaRowOffset, chromaRowBytes, buffer.capacity())) {
        return fail(error, "YUV planes exceed mapped buffer");
    }
    if (buffer.data() == nullptr) {
        return fail(error, "YUV buffer is not mapped");
    }

    size_t scratchRowBytes;
    if (!checkedMultiply(static_cast<size_t>(width), 4U, &scratchRowBytes)) {
        return fail(error, "YUV source row size overflow");
    }
    for (int32_t y = 0; y < height; ++y) {
        size_t destinationOffset;
        size_t sourceOffset;
        if (!checkedMultiply(static_cast<size_t>(y), yStride,
                             &destinationOffset) ||
            !checkedMultiply(static_cast<size_t>(y), scratchRowBytes,
                             &sourceOffset) ||
            !rangeFits(destinationOffset, static_cast<size_t>(width),
                       buffer.capacity()) ||
            !rangeFits(sourceOffset, scratchRowBytes, rgbaScratch_.size())) {
            return fail(error, "YUV luma row exceeds mapped buffer");
        }
        uint8_t* destination = buffer.data() + destinationOffset;
        const uint8_t* source = rgbaScratch_.data() + sourceOffset;
        for (int32_t x = 0; x < width; ++x) {
            uint8_t luma;
            uint8_t ignoredU;
            uint8_t ignoredV;
            const size_t pixelOffset = static_cast<size_t>(x) * 4U;
            rgbToYuv(source[pixelOffset], source[pixelOffset + 1U],
                     source[pixelOffset + 2U], &luma, &ignoredU, &ignoredV);
            destination[x] = luma;
        }
    }

    for (size_t chromaY = 0; chromaY < chromaRows; ++chromaY) {
        size_t rowOffset;
        size_t destinationOffset;
        if (!checkedMultiply(chromaY, cStride, &rowOffset) ||
            !checkedAdd(yPlaneBytes, rowOffset, &destinationOffset) ||
            !rangeFits(destinationOffset, chromaRowBytes, buffer.capacity())) {
            return fail(error, "YUV chroma row exceeds mapped buffer");
        }
        uint8_t* destination = buffer.data() + destinationOffset;
        for (size_t chromaX = 0; chromaX < chromaRowBytes / 2U; ++chromaX) {
            const int32_t x0 = static_cast<int32_t>(chromaX * 2U);
            const int32_t x1 = std::min(x0 + 1, width - 1);
            const int32_t y0 = static_cast<int32_t>(chromaY * 2U);
            const int32_t y1 = std::min(y0 + 1, height - 1);
            const size_t offsets[4] = {
                    (static_cast<size_t>(y0) * static_cast<size_t>(width) +
                     static_cast<size_t>(x0)) *
                            4U,
                    (static_cast<size_t>(y0) * static_cast<size_t>(width) +
                     static_cast<size_t>(x1)) *
                            4U,
                    (static_cast<size_t>(y1) * static_cast<size_t>(width) +
                     static_cast<size_t>(x0)) *
                            4U,
                    (static_cast<size_t>(y1) * static_cast<size_t>(width) +
                     static_cast<size_t>(x1)) *
                            4U,
            };
            int red = 0;
            int green = 0;
            int blue = 0;
            for (size_t index : offsets) {
                if (!rangeFits(index, 4U, rgbaScratch_.size())) {
                    return fail(error, "YUV chroma sample exceeds scratch storage");
                }
                red += rgbaScratch_[index];
                green += rgbaScratch_[index + 1U];
                blue += rgbaScratch_[index + 2U];
            }
            uint8_t ignoredY;
            uint8_t u;
            uint8_t v;
            rgbToYuv(static_cast<uint8_t>((red + 2) / 4),
                     static_cast<uint8_t>((green + 2) / 4),
                     static_cast<uint8_t>((blue + 2) / 4), &ignoredY, &u, &v);
            destination[chromaX * 2U] = u;
            destination[chromaX * 2U + 1U] = v;
        }
    }
    return true;
}

bool CameraRenderer::writeJpeg(const RequestSettings& settings,
                               const FrameTiming& timing, int32_t width,
                               int32_t height, CachedBuffer& buffer,
                               std::string* error) {
    if (buffer.blobCapacity() < sizeof(JpegBlobFooter) ||
        buffer.blobCapacity() > buffer.capacity() || buffer.data() == nullptr) {
        return fail(error, "JPEG buffer has no payload and footer capacity");
    }
    size_t rowBytes;
    if (!checkedMultiply(static_cast<size_t>(width), 4U, &rowBytes) ||
        rowBytes > std::numeric_limits<uint32_t>::max()) {
        return fail(error, "JPEG source stride is not representable");
    }
    size_t sourceBytes;
    if (!checkedMultiply(rowBytes, static_cast<size_t>(height), &sourceBytes) ||
        sourceBytes > rgbaScratch_.size()) {
        return fail(error, "JPEG source exceeds scratch storage");
    }

    const size_t footerOffset = buffer.blobCapacity() - sizeof(JpegBlobFooter);
    const JpegBlobFooter invalidFooter{};
    std::memcpy(buffer.data() + footerOffset, &invalidFooter,
                sizeof(invalidFooter));

    AndroidBitmapInfo info{};
    info.width = static_cast<uint32_t>(width);
    info.height = static_cast<uint32_t>(height);
    info.stride = static_cast<uint32_t>(rowBytes);
    info.format = ANDROID_BITMAP_FORMAT_RGBA_8888;
    info.flags = ANDROID_BITMAP_FLAGS_ALPHA_OPAQUE;

    ExifSegment exif;
    if (!buildExifSegment(settings, timing, sensorOrientation_, width, height,
                          &exif)) {
        return fail(error, "failed to generate JPEG EXIF metadata");
    }
    size_t minimumPayloadCapacity;
    if (!checkedAdd(exif.size, 4U, &minimumPayloadCapacity) ||
        minimumPayloadCapacity > footerOffset) {
        return fail(error, "JPEG buffer cannot hold EXIF metadata");
    }
    JpegWriteContext output{
            buffer.data(), footerOffset - exif.size, 0};
    const int result = AndroidBitmap_compress(
            &info, ADATASPACE_SRGB, rgbaScratch_.data(),
            ANDROID_BITMAP_COMPRESS_FORMAT_JPEG,
            std::min<int32_t>(settings.jpegQuality, 100), &output,
            &CameraRenderer::appendJpeg);
    if (result != ANDROID_BITMAP_RESULT_SUCCESS) {
        return fail(error, "Android JPEG compression failed");
    }
    if (output.size < 4U || output.size > std::numeric_limits<uint32_t>::max() ||
        output.destination[0] != 0xff || output.destination[1] != 0xd8 ||
        output.destination[output.size - 2U] != 0xff ||
        output.destination[output.size - 1U] != 0xd9) {
        return fail(error, "Android JPEG compressor returned an invalid payload");
    }

    size_t jpegSize;
    if (!checkedAdd(output.size, exif.size, &jpegSize) ||
        jpegSize > footerOffset ||
        jpegSize > std::numeric_limits<uint32_t>::max()) {
        return fail(error, "JPEG and EXIF payload exceed buffer capacity");
    }
    std::memmove(output.destination + 2U + exif.size,
                 output.destination + 2U, output.size - 2U);
    std::memcpy(output.destination + 2U, exif.bytes.data(), exif.size);
    const JpegBlobFooter footer{kCameraJpegBlobId, 0,
                                static_cast<uint32_t>(jpegSize)};
    std::memcpy(buffer.data() + footerOffset, &footer, sizeof(footer));
    return true;
}

bool CameraRenderer::writeFrame(const RequestSettings& settings,
                                const FrameTiming& timing, int64_t frameNumber,
                                const StreamDescriptor& stream,
                                CachedBuffer& buffer,
                                const SourceFrame& source, SourceMode mode,
                                std::string* error) {
    if (error != nullptr) {
        error->clear();
    }
    if (!sensorOrientationValid_) {
        return fail(error, "sensor orientation is not a right angle");
    }
    if (stream.width <= 0 || stream.height <= 0 ||
        buffer.width() != stream.width || buffer.height() != stream.height) {
        return fail(error, "stream and mapped buffer dimensions differ");
    }
    if (stream.overrideFormat != buffer.format()) {
        return fail(error, "stream and mapped buffer formats differ");
    }
    if (stream.overrideFormat != kRgba8888Format &&
        stream.overrideFormat != kYuv420Format &&
        stream.overrideFormat != kBlobFormat) {
        return fail(error, "renderer does not support the stream format");
    }
    if (buffer.data() == nullptr || buffer.capacity() == 0) {
        return fail(error, "stream buffer is not mapped");
    }

    int32_t jpegRotation = 0;
    if (stream.overrideFormat == kBlobFormat) {
        if (!isRightAngle(settings.jpegOrientation)) {
            return fail(error, "JPEG orientation is not a right angle");
        }
        if (settings.jpegQuality < 1 || settings.jpegQuality > 100) {
            return fail(error, "JPEG quality is out of range");
        }
        jpegRotation = normalizeRotation(settings.jpegOrientation);
    }
    const bool jpegSwapsAxes = stream.overrideFormat == kBlobFormat &&
            (jpegRotation == 90 || jpegRotation == 270);
    const int32_t outputWidth =
            jpegSwapsAxes ? stream.height : stream.width;
    const int32_t outputHeight =
            jpegSwapsAxes ? stream.width : stream.height;
    const int32_t outputRotation =
            normalizeRotation(jpegRotation - sensorOrientation_);
    if (!renderScratch(settings, timing, frameNumber, source, mode,
                       outputRotation, outputWidth, outputHeight, error)) {
        return false;
    }

    switch (stream.overrideFormat) {
        case kRgba8888Format:
            return writeRgba(stream.width, stream.height, buffer, error);
        case kYuv420Format:
            return writeYuv(stream.width, stream.height, buffer, error);
        case kBlobFormat:
            return writeJpeg(settings, timing, outputWidth, outputHeight, buffer,
                             error);
        default:
            return fail(error, "renderer format dispatch failed");
    }
}

}  // namespace camera_provider
