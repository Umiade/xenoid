#include "camera_source.h"

#include <android/bitmap.h>
#include <android/data_space.h>
#include <android/hardware_buffer.h>
#include <android/imagedecoder.h>
#include <media/NdkImage.h>
#include <media/NdkImageReader.h>
#include <media/NdkMediaCodec.h>
#include <media/NdkMediaExtractor.h>
#include <media/NdkMediaFormat.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

namespace camera_provider {
namespace {

constexpr char kSourceDirectory[] = "/data/misc/camera/source";
constexpr char kConfigurationName[] = "current.conf";
constexpr size_t kMaximumConfigurationBytes = 4096;
constexpr off64_t kMaximumPhotoBytes = 64LL * 1024LL * 1024LL;
constexpr off64_t kMaximumVideoBytes = 2LL * 1024LL * 1024LL * 1024LL;
constexpr int32_t kMaximumDimension = 8192;
constexpr size_t kMaximumPixels = 64U * 1024U * 1024U;
constexpr int64_t kMaximumDurationUs = 24LL * 60LL * 60LL * 1000000LL;
constexpr int64_t kDiscontinuityUs = 2LL * 1000000LL;
constexpr int64_t kCodecPollUs = 5000;
constexpr size_t kMaximumCodecPumpSteps = 512;
constexpr size_t kMaximumOutputsPerRequest = 4096;
constexpr auto kDecodeDeadline = std::chrono::milliseconds(2000);
constexpr auto kImageDeadline = std::chrono::milliseconds(250);
constexpr int32_t kColorStandardBt709 = 1;
constexpr int32_t kColorStandardBt601Pal = 2;
constexpr int32_t kColorStandardBt601Ntsc = 4;
constexpr int32_t kColorRangeFull = 1;
constexpr int32_t kColorRangeLimited = 2;
constexpr int32_t kColorTransferSrgb = 2;
constexpr int32_t kColorTransferSdrVideo = 3;

enum class VideoColorStandard {
    Bt601,
    Bt709,
};

bool fail(std::string* error, const char* message);

bool requestStopped(
        const std::atomic<bool>* cancelled,
        const std::chrono::steady_clock::time_point& deadline,
        std::string* error) {
    if (cancelled != nullptr &&
        cancelled->load(std::memory_order_acquire)) {
        return fail(error, "source request cancelled");
    }
    if (std::chrono::steady_clock::now() >= deadline) {
        return fail(error, "source request deadline exceeded");
    }
    return false;
}

bool readColorDescription(
        AMediaFormat* format, VideoColorStandard* standard, bool* fullRange,
        std::string* error) {
    int32_t value = 0;
    if (AMediaFormat_getInt32(
                format, AMEDIAFORMAT_KEY_COLOR_STANDARD, &value)) {
        if (value == 0) {
            // Unspecified inherits the prior/default description.
        } else if (value == kColorStandardBt709) {
            *standard = VideoColorStandard::Bt709;
        } else if (value == kColorStandardBt601Pal ||
                   value == kColorStandardBt601Ntsc) {
            *standard = VideoColorStandard::Bt601;
        } else {
            return fail(error, "video color standard is unsupported");
        }
    }
    if (AMediaFormat_getInt32(
                format, AMEDIAFORMAT_KEY_COLOR_RANGE, &value)) {
        if (value == 0) {
            // Unspecified inherits the prior/default description.
        } else if (value == kColorRangeFull) {
            *fullRange = true;
        } else if (value == kColorRangeLimited) {
            *fullRange = false;
        } else {
            return fail(error, "video color range is unsupported");
        }
    }
    if (AMediaFormat_getInt32(
                format, AMEDIAFORMAT_KEY_COLOR_TRANSFER, &value) &&
        value != 0 && value != kColorTransferSrgb &&
        value != kColorTransferSdrVideo) {
        return fail(error, "video color transfer is unsupported");
    }
    return true;
}

constexpr int kMaximumSnapshotAttempts = 3;
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

uint8_t clampByte(int value) {
    return static_cast<uint8_t>(std::clamp(value, 0, 255));
}

class UniqueFd final {
  public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) : fd_(fd) {}
    ~UniqueFd() { reset(); }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& other) noexcept : fd_(other.release()) {}
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    int get() const { return fd_; }
    explicit operator bool() const { return fd_ >= 0; }

    int release() {
        const int fd = fd_;
        fd_ = -1;
        return fd;
    }

    void reset(int fd = -1) {
        if (fd_ >= 0) {
            close(fd_);
        }
        fd_ = fd;
    }

  private:
    int fd_ = -1;
};

struct MediaFormatDeleter {
    void operator()(AMediaFormat* format) const {
        if (format != nullptr) {
            AMediaFormat_delete(format);
        }
    }
};
using UniqueMediaFormat = std::unique_ptr<AMediaFormat, MediaFormatDeleter>;

struct ImageDecoderDeleter {
    void operator()(AImageDecoder* decoder) const {
        if (decoder != nullptr) {
            AImageDecoder_delete(decoder);
        }
    }
};
using UniqueImageDecoder = std::unique_ptr<AImageDecoder, ImageDecoderDeleter>;

struct ImageDeleter {
    void operator()(AImage* image) const {
        if (image != nullptr) {
            AImage_delete(image);
        }
    }
};
using UniqueImage = std::unique_ptr<AImage, ImageDeleter>;

bool hasExactMode(const struct stat& status, mode_t mode) {
    return (status.st_mode & 07777) == mode;
}

bool isRootOwned(const struct stat& status) {
    return status.st_uid == 0 && status.st_gid == 0;
}

bool validateSourceDirectory(int fd, std::string* error) {
    struct stat status {};
    if (fstat(fd, &status) != 0 || !S_ISDIR(status.st_mode) ||
        !isRootOwned(status) || !hasExactMode(status, 0700)) {
        return fail(error, "source directory validation failed");
    }
    return true;
}

bool validateRegularFile(int fd, off64_t minimumSize, off64_t maximumSize,
                         off64_t* size, std::string* error) {
    struct stat status {};
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        !isRootOwned(status) || !hasExactMode(status, 0600) ||
        status.st_size < minimumSize || status.st_size > maximumSize) {
        return fail(error, "source file validation failed");
    }
    *size = status.st_size;
    return true;
}

bool clearNonBlocking(int fd, std::string* error) {
    const int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) != 0) {
        return fail(error, "source descriptor setup failed");
    }
    return true;
}

bool readExactFile(int fd, size_t size, std::string* contents,
                   std::string* error) {
    try {
        contents->resize(size);
    } catch (const std::bad_alloc&) {
        return fail(error, "configuration allocation failed");
    }

    size_t offset = 0;
    while (offset < size) {
        const ssize_t count = read(fd, contents->data() + offset, size - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return fail(error, "configuration read failed");
        }
        offset += static_cast<size_t>(count);
    }

    char extra;
    ssize_t count;
    do {
        count = read(fd, &extra, 1);
    } while (count < 0 && errno == EINTR);
    if (count != 0) {
        return fail(error, "configuration changed during read");
    }
    return true;
}

bool parseUnsigned(std::string_view text, uint64_t* value) {
    if (text.empty() || text.size() > 20 ||
        (text.size() > 1 && text.front() == '0')) {
        return false;
    }
    uint64_t parsed = 0;
    for (const char character : text) {
        if (character < '0' || character > '9') {
            return false;
        }
        const uint64_t digit = static_cast<uint64_t>(character - '0');
        if (parsed > (std::numeric_limits<uint64_t>::max() - digit) / 10U) {
            return false;
        }
        parsed = parsed * 10U + digit;
    }
    *value = parsed;
    return true;
}

struct ParsedConfiguration {
    uint64_t generation = 0;
    SourceMode mode = SourceMode::Naturalized;
    std::string_view generationText;
    std::string_view photoName;
    std::string_view videoName;
};

bool parseConfiguration(const std::string& contents,
                        ParsedConfiguration* configuration,
                        std::string* error) {
    if (contents.empty() || contents.back() != '\n' ||
        contents.find('\0') != std::string::npos) {
        return fail(error, "invalid source configuration");
    }

    std::array<std::string_view, 5> lines;
    const std::string_view view(contents);
    size_t start = 0;
    for (size_t index = 0; index < lines.size(); ++index) {
        const size_t end = view.find('\n', start);
        if (end == std::string_view::npos) {
            return fail(error, "invalid source configuration");
        }
        lines[index] = view.substr(start, end - start);
        start = end + 1;
    }
    if (start != view.size() || lines[0] != "version=1" ||
        lines[1].substr(0, 11) != "generation=" ||
        lines[2].substr(0, 5) != "mode=" ||
        lines[3].substr(0, 6) != "photo=" ||
        lines[4].substr(0, 6) != "video=") {
        return fail(error, "invalid source configuration");
    }

    configuration->generationText = lines[1].substr(11);
    if (!parseUnsigned(configuration->generationText,
                       &configuration->generation)) {
        return fail(error, "invalid source configuration");
    }

    const std::string_view mode = lines[2].substr(5);
    if (mode == "naturalized") {
        configuration->mode = SourceMode::Naturalized;
    } else if (mode == "faithful") {
        configuration->mode = SourceMode::Faithful;
    } else {
        return fail(error, "invalid source configuration");
    }

    configuration->photoName = lines[3].substr(6);
    configuration->videoName = lines[4].substr(6);

    std::string expectedPhoto;
    std::string expectedVideo;
    try {
        expectedPhoto = "photo-";
        expectedPhoto.append(configuration->generationText);
        expectedPhoto.append(".png");
        expectedVideo = "video-";
        expectedVideo.append(configuration->generationText);
        expectedVideo.append(".bin");
    } catch (const std::bad_alloc&) {
        return fail(error, "configuration allocation failed");
    }

    if ((!configuration->photoName.empty() &&
         configuration->photoName != expectedPhoto) ||
        (!configuration->videoName.empty() &&
         configuration->videoName != expectedVideo)) {
        return fail(error, "invalid source configuration");
    }
    return true;
}

bool openAsset(int directoryFd, std::string_view name, off64_t maximumSize,
               UniqueFd* output, off64_t* size, bool* missing,
               std::string* error) {
    std::string path;
    try {
        path.assign(name);
    } catch (const std::bad_alloc&) {
        return fail(error, "source descriptor allocation failed");
    }

    UniqueFd fd(openat(directoryFd, path.c_str(),
                       O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (!fd) {
        *missing = errno == ENOENT;
        return fail(error, "source asset open failed");
    }
    if (!validateRegularFile(fd.get(), 1, maximumSize, size, error) ||
        !clearNonBlocking(fd.get(), error)) {
        return false;
    }
    *output = std::move(fd);
    return true;
}

bool dimensionsAreBounded(int32_t width, int32_t height, size_t* rgbaBytes) {
    if (width <= 0 || height <= 0 || width > kMaximumDimension ||
        height > kMaximumDimension) {
        return false;
    }
    size_t pixels;
    return checkedMultiply(static_cast<size_t>(width),
                           static_cast<size_t>(height), &pixels) &&
           pixels <= kMaximumPixels && checkedMultiply(pixels, 4U, rgbaBytes) &&
           *rgbaBytes <= std::vector<uint8_t>().max_size();
}

int32_t normalizedRotation(int32_t rotation) {
    int32_t normalized = rotation % 360;
    if (normalized < 0) {
        normalized += 360;
    }
    if (normalized != 0 && normalized != 90 && normalized != 180 &&
        normalized != 270) {
        return -1;
    }
    return normalized;
}

bool planeFits(int32_t width, int32_t height, int32_t rowStride,
               int32_t pixelStride, int length) {
    if (width <= 0 || height <= 0 || rowStride <= 0 || pixelStride <= 0 ||
        length <= 0) {
        return false;
    }
    size_t rowOffset;
    size_t columnOffset;
    if (!checkedMultiply(static_cast<size_t>(height - 1),
                         static_cast<size_t>(rowStride), &rowOffset) ||
        !checkedMultiply(static_cast<size_t>(width - 1),
                         static_cast<size_t>(pixelStride), &columnOffset) ||
        rowOffset > std::numeric_limits<size_t>::max() - columnOffset) {
        return false;
    }
    return rowOffset + columnOffset < static_cast<size_t>(length);
}

}  // namespace

class CameraSource::Impl final {
  public:
    Impl() = default;
    ~Impl() { resetVideo(); }
    bool retryableSnapshotRace() const { return retryableSnapshotRace_; }

    bool load(std::string* error) {
        UniqueFd directory(open(kSourceDirectory,
                                O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW |
                                        O_NONBLOCK));
        if (!directory) {
            if (errno == ENOENT) {
                return true;
            }
            return fail(error, "source directory open failed");
        }
        if (!validateSourceDirectory(directory.get(), error) ||
            !clearNonBlocking(directory.get(), error)) {
            return false;
        }

        UniqueFd configurationFd(openat(
                directory.get(), kConfigurationName,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
        if (!configurationFd) {
            if (errno == ENOENT) {
                return true;
            }
            return fail(error, "source configuration open failed");
        }

        off64_t configurationSize = 0;
        if (!validateRegularFile(configurationFd.get(), 1,
                                 static_cast<off64_t>(kMaximumConfigurationBytes),
                                 &configurationSize, error) ||
            !clearNonBlocking(configurationFd.get(), error)) {
            return false;
        }

        std::string contents;
        if (!readExactFile(configurationFd.get(),
                           static_cast<size_t>(configurationSize), &contents,
                           error)) {
            return false;
        }

        ParsedConfiguration configuration;
        if (!parseConfiguration(contents, &configuration, error)) {
            return false;
        }

        generation_ = configuration.generation;
        mode_ = configuration.mode;

        if (!configuration.photoName.empty()) {
            off64_t photoSize = 0;
            bool missing = false;
            if (!openAsset(directory.get(), configuration.photoName,
                           kMaximumPhotoBytes, &photoFd_, &photoSize, &missing,
                           error)) {
                retryableSnapshotRace_ = missing;
                return false;
            }
            if (!decodePhoto(error)) {
                return false;
            }
        }

        if (!configuration.videoName.empty()) {
            off64_t videoSize = 0;
            bool missing = false;
            if (!openAsset(directory.get(), configuration.videoName,
                           kMaximumVideoBytes, &videoFd_, &videoSize, &missing,
                           error)) {
                retryableSnapshotRace_ = missing;
                return false;
            }
            if (!initializeVideo(videoSize, error)) {
                return false;
            }
            const auto deadline =
                    std::chrono::steady_clock::now() + kDecodeDeadline;
            if (!decodeVideoAt(0, false, nullptr, deadline, error)) {
                return false;
            }
        }
        return true;
    }

    bool getFrame(
            bool videoRequest, int64_t monotonicTimestampNs,
            const std::atomic<bool>* cancelled,
            const std::chrono::steady_clock::time_point& deadline,
            SourceFrame* output, std::string* error) {
        if (output == nullptr) {
            return fail(error, "source frame output is null");
        }
        *output = SourceFrame{};
        if (requestStopped(cancelled, deadline, error)) {
            return false;
        }

        if (videoRequest) {
            if (videoAvailable_) {
                int64_t targetUs = 0;
                bool forceRestart = false;
                if (!videoTarget(monotonicTimestampNs, &targetUs, &forceRestart,
                                 error)) {
                    return false;
                }
                if (!decodeVideoAt(targetUs, forceRestart, cancelled, deadline,
                                   error)) {
                    decoderNeedsRestart_ = true;
                    return false;
                }
                setVideoFrame(output);
                return true;
            }
            if (!photoRgba_.empty()) {
                setPhotoFrame(output);
            }
            return true;
        }

        if (!photoRgba_.empty()) {
            setPhotoFrame(output);
            return true;
        }
        if (videoAvailable_) {
            if (!decodeVideoAt(0, false, cancelled, deadline, error)) {
                decoderNeedsRestart_ = true;
                return false;
            }
            setVideoFrame(output);
        }
        return true;
    }

    SourceMode mode() const { return mode_; }
    uint64_t generation() const { return generation_; }
    void release() { releaseResources(); }

  private:
    enum class PumpResult {
        Output,
        EndOfStream,
        TimedOut,
        Error,
    };

    struct CodecOutput {
        size_t index = 0;
        AMediaCodecBufferInfo info{};
        bool endsStream = false;
    };

    bool decodePhoto(std::string* error) {
        AImageDecoder* rawDecoder = nullptr;
        if (AImageDecoder_createFromFd(photoFd_.get(), &rawDecoder) !=
                    ANDROID_IMAGE_DECODER_SUCCESS ||
            rawDecoder == nullptr) {
            return fail(error, "photo decode setup failed");
        }
        UniqueImageDecoder decoder(rawDecoder);

        const AImageDecoderHeaderInfo* header =
                AImageDecoder_getHeaderInfo(decoder.get());
        if (header == nullptr) {
            return fail(error, "photo header read failed");
        }
        const char* mime = AImageDecoderHeaderInfo_getMimeType(header);
        if (mime == nullptr || std::strcmp(mime, "image/png") != 0) {
            return fail(error, "photo content is not normalized");
        }

        const int32_t width = AImageDecoderHeaderInfo_getWidth(header);
        const int32_t height = AImageDecoderHeaderInfo_getHeight(header);
        size_t byteCount;
        if (!dimensionsAreBounded(width, height, &byteCount) ||
            width > std::numeric_limits<int32_t>::max() / 4) {
            return fail(error, "photo dimensions are invalid");
        }

        if (AImageDecoder_setAndroidBitmapFormat(
                    decoder.get(), ANDROID_BITMAP_FORMAT_RGBA_8888) !=
                    ANDROID_IMAGE_DECODER_SUCCESS ||
            AImageDecoder_setUnpremultipliedRequired(decoder.get(), true) !=
                    ANDROID_IMAGE_DECODER_SUCCESS ||
            AImageDecoder_setDataSpace(decoder.get(), ADATASPACE_SRGB) !=
                    ANDROID_IMAGE_DECODER_SUCCESS) {
            return fail(error, "photo output setup failed");
        }

        const size_t stride = AImageDecoder_getMinimumStride(decoder.get());
        if (stride != static_cast<size_t>(width) * 4U ||
            stride > static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
            return fail(error, "photo stride is invalid");
        }

        try {
            photoRgba_.resize(byteCount);
        } catch (const std::bad_alloc&) {
            return fail(error, "photo allocation failed");
        }
        if (AImageDecoder_decodeImage(decoder.get(), photoRgba_.data(), stride,
                                      photoRgba_.size()) !=
            ANDROID_IMAGE_DECODER_SUCCESS) {
            photoRgba_.clear();
            return fail(error, "photo decode failed");
        }

        photoWidth_ = width;
        photoHeight_ = height;
        photoStride_ = static_cast<int32_t>(stride);
        return true;
    }

    bool initializeVideo(off64_t videoSize, std::string* error) {
        extractor_ = AMediaExtractor_new();
        if (extractor_ == nullptr ||
            AMediaExtractor_setDataSourceFd(extractor_, videoFd_.get(), 0,
                                            videoSize) != AMEDIA_OK) {
            return fail(error, "video container setup failed");
        }

        UniqueMediaFormat fileFormat(AMediaExtractor_getFileFormat(extractor_));
        int64_t fileDuration = 0;
        int32_t fileRotation = 0;
        const bool hasFileDuration = fileFormat != nullptr &&
                AMediaFormat_getInt64(fileFormat.get(), AMEDIAFORMAT_KEY_DURATION,
                                      &fileDuration);
        const bool hasFileRotation = fileFormat != nullptr &&
                AMediaFormat_getInt32(fileFormat.get(), AMEDIAFORMAT_KEY_ROTATION,
                                      &fileRotation);
        VideoColorStandard fileColorStandard = VideoColorStandard::Bt601;
        bool fileFullRange = false;
        if (fileFormat != nullptr &&
            !readColorDescription(fileFormat.get(), &fileColorStandard,
                                  &fileFullRange, error)) {
            return false;
        }

        const size_t trackCount = AMediaExtractor_getTrackCount(extractor_);
        if (trackCount == 0 || trackCount > 128) {
            return fail(error, "video track table is invalid");
        }

        UniqueMediaFormat selectedFormat;
        const char* selectedMime = nullptr;
        for (size_t index = 0; index < trackCount; ++index) {
            UniqueMediaFormat format(
                    AMediaExtractor_getTrackFormat(extractor_, index));
            const char* mime = nullptr;
            if (format == nullptr ||
                !AMediaFormat_getString(format.get(), AMEDIAFORMAT_KEY_MIME,
                                        &mime) ||
                mime == nullptr ||
                (std::strcmp(mime, "video/avc") != 0 &&
                 std::strcmp(mime, "video/hevc") != 0)) {
                continue;
            }

            int32_t width = 0;
            int32_t height = 0;
            int64_t duration = 0;
            int32_t rotation = 0;
            VideoColorStandard colorStandard = fileColorStandard;
            bool fullRange = fileFullRange;
            if (!readColorDescription(format.get(), &colorStandard, &fullRange,
                                      error)) {
                return false;
            }
            if (!AMediaFormat_getInt32(format.get(), AMEDIAFORMAT_KEY_WIDTH,
                                       &width) ||
                !AMediaFormat_getInt32(format.get(), AMEDIAFORMAT_KEY_HEIGHT,
                                       &height)) {
                continue;
            }
            if (!AMediaFormat_getInt64(format.get(), AMEDIAFORMAT_KEY_DURATION,
                                       &duration)) {
                if (!hasFileDuration) {
                    continue;
                }
                duration = fileDuration;
            }
            if (!AMediaFormat_getInt32(format.get(), AMEDIAFORMAT_KEY_ROTATION,
                                       &rotation) && hasFileRotation) {
                rotation = fileRotation;
            }

            size_t byteCount;
            const int32_t normalized = normalizedRotation(rotation);
            if (!dimensionsAreBounded(width, height, &byteCount) ||
                duration <= 0 || duration > kMaximumDurationUs ||
                normalized < 0) {
                continue;
            }

            if (AMediaExtractor_selectTrack(extractor_, index) != AMEDIA_OK) {
                return fail(error, "video track selection failed");
            }
            videoTrackIndex_ = index;
            videoWidth_ = width;
            videoHeight_ = height;
            videoDurationUs_ = duration;
            videoRotation_ = normalized;
            videoColorStandard_ = colorStandard;
            videoFullRange_ = fullRange;
            selectedMime = mime;
            selectedFormat = std::move(format);
            break;
        }

        if (selectedFormat == nullptr || selectedMime == nullptr) {
            return fail(error, "video track is unavailable");
        }

        if (AImageReader_newWithUsage(
                    videoWidth_, videoHeight_, AIMAGE_FORMAT_YUV_420_888,
                    AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN, 3, &reader_) !=
                    AMEDIA_OK ||
            reader_ == nullptr) {
            return fail(error, "video image reader setup failed");
        }
        ANativeWindow* window = nullptr;
        if (AImageReader_getWindow(reader_, &window) != AMEDIA_OK ||
            window == nullptr) {
            return fail(error, "video output surface setup failed");
        }

        codec_ = AMediaCodec_createDecoderByType(selectedMime);
        if (codec_ == nullptr) {
            return fail(error, "video decoder is unavailable");
        }

        // Keep container orientation as source metadata. The renderer applies it
        // before its sensor transform, so the decoder surface must stay unrotated.
        AMediaFormat_setInt32(selectedFormat.get(), AMEDIAFORMAT_KEY_ROTATION, 0);
        if (AMediaCodec_configure(codec_, selectedFormat.get(), window, nullptr,
                                  0) != AMEDIA_OK ||
            AMediaCodec_start(codec_) != AMEDIA_OK) {
            return fail(error, "video decoder setup failed");
        }
        codecStarted_ = true;
        videoAvailable_ = true;
        return true;
    }

    bool videoTarget(int64_t timestampNs, int64_t* targetUs,
                     bool* forceRestart, std::string* error) {
        if (timestampNs < 0 || videoDurationUs_ <= 0) {
            return fail(error, "video timestamp is invalid");
        }
        *forceRestart = false;
        if (!recordEpochSet_) {
            recordEpochSet_ = true;
            recordEpochNs_ = timestampNs;
            recordLoop_ = 0;
            *targetUs = 0;
            return true;
        }
        if (timestampNs < recordEpochNs_) {
            recordEpochNs_ = timestampNs;
            recordLoop_ = 0;
            *targetUs = 0;
            *forceRestart = true;
            return true;
        }

        const int64_t elapsedUs = (timestampNs - recordEpochNs_) / 1000;
        const uint64_t loop = static_cast<uint64_t>(elapsedUs / videoDurationUs_);
        *targetUs = elapsedUs % videoDurationUs_;
        *forceRestart = loop != recordLoop_;
        recordLoop_ = loop;
        return true;
    }

    bool queueInput(bool* queued, std::string* error) {
        *queued = false;
        if (inputEos_) {
            return true;
        }
        const ssize_t index = AMediaCodec_dequeueInputBuffer(codec_, 0);
        if (index == AMEDIACODEC_INFO_TRY_AGAIN_LATER) {
            return true;
        }
        if (index < 0) {
            return fail(error, "video decoder input failed");
        }

        size_t capacity = 0;
        uint8_t* buffer = AMediaCodec_getInputBuffer(
                codec_, static_cast<size_t>(index), &capacity);
        if (buffer == nullptr) {
            return fail(error, "video decoder input is unavailable");
        }

        if (extractorEof_) {
            if (AMediaCodec_queueInputBuffer(
                        codec_, static_cast<size_t>(index), 0, 0,
                        static_cast<uint64_t>(videoDurationUs_),
                        AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM) != AMEDIA_OK) {
                return fail(error, "video decoder end marker failed");
            }
            inputEos_ = true;
            *queued = true;
            return true;
        }

        const ssize_t sampleSize = AMediaExtractor_getSampleSize(extractor_);
        const int64_t sampleTimeUs = AMediaExtractor_getSampleTime(extractor_);
        if (sampleSize < 0 || sampleTimeUs < 0) {
            extractorEof_ = true;
            if (AMediaCodec_queueInputBuffer(
                        codec_, static_cast<size_t>(index), 0, 0,
                        static_cast<uint64_t>(videoDurationUs_),
                        AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM) != AMEDIA_OK) {
                return fail(error, "video decoder end marker failed");
            }
            inputEos_ = true;
            *queued = true;
            return true;
        }
        if (static_cast<size_t>(sampleSize) > capacity ||
            (AMediaExtractor_getSampleFlags(extractor_) &
             AMEDIAEXTRACTOR_SAMPLE_FLAG_ENCRYPTED) != 0) {
            return fail(error, "video sample is invalid");
        }
        const int track = AMediaExtractor_getSampleTrackIndex(extractor_);
        if (track < 0 || static_cast<size_t>(track) != videoTrackIndex_) {
            return fail(error, "video sample track is invalid");
        }

        const ssize_t readSize = AMediaExtractor_readSampleData(
                extractor_, buffer, static_cast<size_t>(sampleSize));
        if (readSize != sampleSize ||
            AMediaCodec_queueInputBuffer(
                    codec_, static_cast<size_t>(index), 0,
                    static_cast<size_t>(sampleSize),
                    static_cast<uint64_t>(sampleTimeUs), 0) != AMEDIA_OK) {
            return fail(error, "video sample submission failed");
        }
        if (!AMediaExtractor_advance(extractor_)) {
            extractorEof_ = true;
        }
        *queued = true;
        return true;
    }

    PumpResult nextOutput(
            const std::chrono::steady_clock::time_point& deadline,
            const std::atomic<bool>* cancelled, CodecOutput* output,
            std::string* error) {
        for (size_t step = 0; step < kMaximumCodecPumpSteps; ++step) {
            if (requestStopped(cancelled, deadline, error)) {
                return PumpResult::Error;
            }

            bool queued = false;
            if (!queueInput(&queued, error)) {
                return PumpResult::Error;
            }

            const auto remaining = std::chrono::duration_cast<
                    std::chrono::microseconds>(deadline -
                                               std::chrono::steady_clock::now());
            const int64_t timeoutUs = queued
                    ? 0
                    : std::max<int64_t>(
                              0, std::min<int64_t>(kCodecPollUs,
                                                   remaining.count()));
            AMediaCodecBufferInfo info{};
            const ssize_t index =
                    AMediaCodec_dequeueOutputBuffer(codec_, &info, timeoutUs);
            if (requestStopped(cancelled, deadline, error)) {
                if (index >= 0) {
                    AMediaCodec_releaseOutputBuffer(
                            codec_, static_cast<size_t>(index), false);
                }
                return PumpResult::Error;
            }
            if (index == AMEDIACODEC_INFO_TRY_AGAIN_LATER ||
                index == AMEDIACODEC_INFO_OUTPUT_BUFFERS_CHANGED) {
                continue;
            }
            if (index == AMEDIACODEC_INFO_OUTPUT_FORMAT_CHANGED) {
                UniqueMediaFormat outputFormat(
                        AMediaCodec_getOutputFormat(codec_));
                if (outputFormat == nullptr ||
                    !readColorDescription(outputFormat.get(),
                                          &videoColorStandard_,
                                          &videoFullRange_, error)) {
                    return PumpResult::Error;
                }
                continue;
            }
            if (index < 0) {
                if (error != nullptr) {
                    *error = "video decoder output failed: " +
                            std::to_string(index);
                }
                return PumpResult::Error;
            }

            const bool endsStream =
                    (info.flags & AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM) != 0;
            if ((info.flags & AMEDIACODEC_BUFFER_FLAG_CODEC_CONFIG) != 0 ||
                (endsStream && info.size <= 0)) {
                if (AMediaCodec_releaseOutputBuffer(
                            codec_, static_cast<size_t>(index), false) !=
                    AMEDIA_OK) {
                    fail(error, "video decoder output release failed");
                    return PumpResult::Error;
                }
                if (endsStream) {
                    outputEos_ = true;
                    return PumpResult::EndOfStream;
                }
                continue;
            }
            if (info.presentationTimeUs < 0) {
                AMediaCodec_releaseOutputBuffer(
                        codec_, static_cast<size_t>(index), false);
                fail(error, "video frame timestamp is invalid");
                return PumpResult::Error;
            }

            output->index = static_cast<size_t>(index);
            output->info = info;
            output->endsStream = endsStream;
            return PumpResult::Output;
        }
        return PumpResult::TimedOut;
    }

    void releasePending() {
        if (pendingOutput_ && codec_ != nullptr) {
            AMediaCodec_releaseOutputBuffer(codec_, pending_.index, false);
        }
        pendingOutput_ = false;
        pending_ = CodecOutput{};
    }

    void drainReader() {
        if (reader_ == nullptr) {
            return;
        }
        for (int count = 0; count < 3; ++count) {
            AImage* image = nullptr;
            if (AImageReader_acquireNextImage(reader_, &image) != AMEDIA_OK) {
                break;
            }
            AImage_delete(image);
        }
    }

    bool restartDecoder(
            int64_t targetUs, const std::atomic<bool>* cancelled,
            const std::chrono::steady_clock::time_point& deadline,
            std::string* error) {
        if (requestStopped(cancelled, deadline, error)) {
            return false;
        }
        releasePending();
        drainReader();
        if (targetUs < 0 || targetUs >= videoDurationUs_ || codec_ == nullptr ||
            extractor_ == nullptr ||
            AMediaCodec_flush(codec_) != AMEDIA_OK ||
            AMediaExtractor_seekTo(extractor_, targetUs,
                                   AMEDIAEXTRACTOR_SEEK_PREVIOUS_SYNC) !=
                    AMEDIA_OK) {
            return fail(error, "video decoder seek failed");
        }
        // A rendered output may reach the reader while the codec is flushing.
        drainReader();
        extractorEof_ = false;
        inputEos_ = false;
        outputEos_ = false;
        videoFrameAvailable_ = false;
        decoderTargetSet_ = false;
        decoderNeedsRestart_ = false;
        return !requestStopped(cancelled, deadline, error);
    }

    bool acquireRenderedImage(
            const std::chrono::steady_clock::time_point& deadline,
            const std::atomic<bool>* cancelled, UniqueImage* image,
            std::string* error) {
        for (;;) {
            if (requestStopped(cancelled, deadline, error)) {
                return false;
            }
            AImage* rawImage = nullptr;
            const media_status_t status =
                    AImageReader_acquireNextImage(reader_, &rawImage);
            if (status == AMEDIA_OK && rawImage != nullptr) {
                image->reset(rawImage);
                return true;
            }
            if (status != AMEDIA_IMGREADER_NO_BUFFER_AVAILABLE) {
                return fail(error, "video image acquisition failed");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    bool convertImage(
            AImage* image, const std::atomic<bool>* cancelled,
            const std::chrono::steady_clock::time_point& deadline,
            std::string* error) {
        int32_t width = 0;
        int32_t height = 0;
        int32_t format = 0;
        int32_t planeCount = 0;
        if (AImage_getWidth(image, &width) != AMEDIA_OK ||
            AImage_getHeight(image, &height) != AMEDIA_OK ||
            AImage_getFormat(image, &format) != AMEDIA_OK ||
            AImage_getNumberOfPlanes(image, &planeCount) != AMEDIA_OK ||
            width != videoWidth_ || height != videoHeight_ ||
            format != AIMAGE_FORMAT_YUV_420_888 || planeCount != 3) {
            return fail(error, "video image layout is invalid");
        }

        std::array<uint8_t*, 3> data{};
        std::array<int, 3> lengths{};
        std::array<int32_t, 3> rowStrides{};
        std::array<int32_t, 3> pixelStrides{};
        for (int plane = 0; plane < 3; ++plane) {
            if (AImage_getPlaneData(image, plane, &data[plane],
                                    &lengths[plane]) != AMEDIA_OK ||
                AImage_getPlaneRowStride(image, plane, &rowStrides[plane]) !=
                        AMEDIA_OK ||
                AImage_getPlanePixelStride(image, plane, &pixelStrides[plane]) !=
                        AMEDIA_OK ||
                data[plane] == nullptr) {
                return fail(error, "video image planes are invalid");
            }
        }

        const int32_t chromaWidth = (width + 1) / 2;
        const int32_t chromaHeight = (height + 1) / 2;
        if (!planeFits(width, height, rowStrides[0], pixelStrides[0],
                       lengths[0]) ||
            !planeFits(chromaWidth, chromaHeight, rowStrides[1],
                       pixelStrides[1], lengths[1]) ||
            !planeFits(chromaWidth, chromaHeight, rowStrides[2],
                       pixelStrides[2], lengths[2])) {
            return fail(error, "video image plane bounds are invalid");
        }

        size_t byteCount;
        if (!dimensionsAreBounded(width, height, &byteCount)) {
            return fail(error, "video image dimensions are invalid");
        }
        try {
            if (videoRgba_.size() != byteCount) {
                videoRgba_.resize(byteCount);
            }
        } catch (const std::bad_alloc&) {
            return fail(error, "video frame allocation failed");
        }

        const bool bt709 = videoColorStandard_ == VideoColorStandard::Bt709;
        const int lumaOffset = videoFullRange_ ? 0 : 16;
        const int lumaCoefficient = videoFullRange_ ? 256 : 298;
        const int redV = videoFullRange_ ? (bt709 ? 403 : 359)
                                         : (bt709 ? 459 : 409);
        const int greenU = videoFullRange_ ? (bt709 ? 48 : 88)
                                           : (bt709 ? 55 : 100);
        const int greenV = videoFullRange_ ? (bt709 ? 120 : 183)
                                           : (bt709 ? 136 : 208);
        const int blueU = videoFullRange_ ? (bt709 ? 475 : 454)
                                          : (bt709 ? 541 : 516);

        const size_t outputStride = static_cast<size_t>(width) * 4U;
        for (int32_t y = 0; y < height; ++y) {
            if (requestStopped(cancelled, deadline, error)) {
                return false;
            }
            const size_t yRow = static_cast<size_t>(y) * rowStrides[0];
            const size_t uRow = static_cast<size_t>(y / 2) * rowStrides[1];
            const size_t vRow = static_cast<size_t>(y / 2) * rowStrides[2];
            uint8_t* destination =
                    videoRgba_.data() + static_cast<size_t>(y) * outputStride;
            for (int32_t x = 0; x < width; ++x) {
                const int luma = data[0][yRow +
                                         static_cast<size_t>(x) *
                                                 pixelStrides[0]];
                const int u = data[1][uRow +
                                      static_cast<size_t>(x / 2) *
                                              pixelStrides[1]];
                const int v = data[2][vRow +
                                      static_cast<size_t>(x / 2) *
                                              pixelStrides[2]];
                const int c = std::max(0, luma - lumaOffset);
                const int d = u - 128;
                const int e = v - 128;
                destination[0] = clampByte(
                        (lumaCoefficient * c + redV * e + 128) >> 8);
                destination[1] = clampByte(
                        (lumaCoefficient * c - greenU * d - greenV * e + 128) >>
                        8);
                destination[2] = clampByte(
                        (lumaCoefficient * c + blueU * d + 128) >> 8);
                destination[3] = 255;
                destination += 4;
            }
        }
        return true;
    }

    bool renderOutput(
            const CodecOutput& output,
            const std::chrono::steady_clock::time_point& decodeDeadline,
            const std::atomic<bool>* cancelled, std::string* error) {
        if (requestStopped(cancelled, decodeDeadline, error)) {
            AMediaCodec_releaseOutputBuffer(codec_, output.index, false);
            return false;
        }
        if (AMediaCodec_releaseOutputBuffer(codec_, output.index, true) !=
            AMEDIA_OK) {
            return fail(error, "video frame render failed");
        }

        const auto imageDeadline = std::min(
                decodeDeadline, std::chrono::steady_clock::now() + kImageDeadline);
        UniqueImage image;
        if (!acquireRenderedImage(imageDeadline, cancelled, &image, error) ||
            !convertImage(image.get(), cancelled, decodeDeadline, error)) {
            return false;
        }
        videoFramePresentationUs_ = output.info.presentationTimeUs;
        videoFrameAvailable_ = true;
        if (output.endsStream) {
            outputEos_ = true;
        }
        return true;
    }

    bool decodeVideoAt(
            int64_t requestedTargetUs, bool forceRestart,
            const std::atomic<bool>* cancelled,
            const std::chrono::steady_clock::time_point& requestDeadline,
            std::string* error) {
        if (!videoAvailable_ || requestedTargetUs < 0 ||
            requestedTargetUs >= videoDurationUs_) {
            return fail(error, "video target is invalid");
        }
        const auto deadline = std::min(
                requestDeadline,
                std::chrono::steady_clock::now() + kDecodeDeadline);
        if (requestStopped(cancelled, deadline, error)) {
            return false;
        }

        bool discontinuity = forceRestart || decoderNeedsRestart_;
        if (decoderTargetSet_) {
            if (requestedTargetUs < decoderTargetUs_ ||
                requestedTargetUs - decoderTargetUs_ > kDiscontinuityUs) {
                discontinuity = true;
            }
        }
        if (discontinuity &&
            !restartDecoder(requestedTargetUs, cancelled, deadline, error)) {
            return false;
        }

        int64_t targetUs = requestedTargetUs;
        if (outputEos_) {
            if (!restartDecoder(0, cancelled, deadline, error)) {
                return false;
            }
            targetUs = 0;
        }

        CodecOutput candidate;
        bool hasCandidate = false;
        size_t outputCount = 0;

        if (pendingOutput_) {
            if (pending_.info.presentationTimeUs <= targetUs ||
                !videoFrameAvailable_) {
                candidate = pending_;
                hasCandidate = true;
                pendingOutput_ = false;
                pending_ = CodecOutput{};
            } else {
                if (requestStopped(cancelled, deadline, error)) {
                    return false;
                }
                decoderTargetUs_ = targetUs;
                decoderTargetSet_ = true;
                return true;
            }
        }

        while (outputCount++ < kMaximumOutputsPerRequest) {
            CodecOutput next;
            const PumpResult result =
                    nextOutput(deadline, cancelled, &next, error);
            if (result == PumpResult::Error) {
                if (hasCandidate) {
                    AMediaCodec_releaseOutputBuffer(codec_, candidate.index,
                                                    false);
                }
                return false;
            }
            if (result == PumpResult::TimedOut ||
                result == PumpResult::EndOfStream) {
                break;
            }

            if (!hasCandidate && !videoFrameAvailable_) {
                candidate = next;
                hasCandidate = true;
                continue;
            }
            if (next.info.presentationTimeUs <= targetUs) {
                if (hasCandidate &&
                    AMediaCodec_releaseOutputBuffer(codec_, candidate.index,
                                                    false) != AMEDIA_OK) {
                    AMediaCodec_releaseOutputBuffer(codec_, next.index, false);
                    return fail(error, "video frame discard failed");
                }
                candidate = next;
                hasCandidate = true;
                continue;
            }

            pending_ = next;
            pendingOutput_ = true;
            break;
        }

        if (outputCount > kMaximumOutputsPerRequest) {
            if (hasCandidate) {
                AMediaCodec_releaseOutputBuffer(codec_, candidate.index, false);
            }
            return fail(error, "video decode bound exceeded");
        }

        if (hasCandidate &&
            !renderOutput(candidate, deadline, cancelled, error)) {
            return false;
        }
        if (requestStopped(cancelled, deadline, error)) {
            return false;
        }
        if (!videoFrameAvailable_) {
            return fail(error, "video produced no frame");
        }

        decoderTargetUs_ = targetUs;
        decoderTargetSet_ = true;
        return true;
    }

    void setPhotoFrame(SourceFrame* output) const {
        output->rgba = photoRgba_.data();
        output->rgbaBytes = photoRgba_.size();
        output->width = photoWidth_;
        output->height = photoHeight_;
        output->rowStride = photoStride_;
        output->rotationDegrees = 0;
    }

    void setVideoFrame(SourceFrame* output) const {
        output->rgba = videoRgba_.data();
        output->rgbaBytes = videoRgba_.size();
        output->width = videoWidth_;
        output->height = videoHeight_;
        output->rowStride = videoWidth_ * 4;
        output->rotationDegrees = videoRotation_;
    }

    void releaseResources() {
        resetVideo();
        photoFd_.reset();
        std::vector<uint8_t>().swap(photoRgba_);
        photoWidth_ = 0;
        photoHeight_ = 0;
        photoStride_ = 0;
        retryableSnapshotRace_ = false;
    }

    void resetVideo() {
        releasePending();
        if (codec_ != nullptr) {
            if (codecStarted_) {
                AMediaCodec_stop(codec_);
            }
            AMediaCodec_delete(codec_);
            codec_ = nullptr;
        }
        if (reader_ != nullptr) {
            AImageReader_delete(reader_);
            reader_ = nullptr;
        }
        if (extractor_ != nullptr) {
            AMediaExtractor_delete(extractor_);
            extractor_ = nullptr;
        }
        videoFd_.reset();
        std::vector<uint8_t>().swap(videoRgba_);
        codecStarted_ = false;
        videoAvailable_ = false;
        videoTrackIndex_ = 0;
        videoWidth_ = 0;
        videoHeight_ = 0;
        videoRotation_ = 0;
        videoDurationUs_ = 0;
        videoColorStandard_ = VideoColorStandard::Bt601;
        videoFullRange_ = false;
        videoFrameAvailable_ = false;
        videoFramePresentationUs_ = 0;
        extractorEof_ = false;
        inputEos_ = false;
        outputEos_ = false;
        pendingOutput_ = false;
        pending_ = CodecOutput{};
        decoderTargetSet_ = false;
        decoderTargetUs_ = 0;
        decoderNeedsRestart_ = false;
        recordEpochSet_ = false;
        recordEpochNs_ = 0;
        recordLoop_ = 0;
    }

    SourceMode mode_ = SourceMode::Naturalized;
    uint64_t generation_ = 0;

    UniqueFd photoFd_;
    std::vector<uint8_t> photoRgba_;
    int32_t photoWidth_ = 0;
    int32_t photoHeight_ = 0;
    int32_t photoStride_ = 0;
    bool retryableSnapshotRace_ = false;

    UniqueFd videoFd_;
    AMediaExtractor* extractor_ = nullptr;
    AMediaCodec* codec_ = nullptr;
    AImageReader* reader_ = nullptr;
    bool codecStarted_ = false;
    bool videoAvailable_ = false;
    size_t videoTrackIndex_ = 0;
    int32_t videoWidth_ = 0;
    int32_t videoHeight_ = 0;
    int32_t videoRotation_ = 0;
    int64_t videoDurationUs_ = 0;
    VideoColorStandard videoColorStandard_ = VideoColorStandard::Bt601;
    bool videoFullRange_ = false;

    std::vector<uint8_t> videoRgba_;
    bool videoFrameAvailable_ = false;
    int64_t videoFramePresentationUs_ = 0;

    bool extractorEof_ = false;
    bool inputEos_ = false;
    bool outputEos_ = false;
    bool pendingOutput_ = false;
    CodecOutput pending_;

    bool decoderTargetSet_ = false;
    int64_t decoderTargetUs_ = 0;
    bool decoderNeedsRestart_ = false;
    bool recordEpochSet_ = false;
    int64_t recordEpochNs_ = 0;
    uint64_t recordLoop_ = 0;
};

CameraSource::CameraSource() : impl_(std::make_unique<Impl>()) {}

CameraSource::~CameraSource() = default;

bool CameraSource::openSnapshot(std::string* error) {
    if (error != nullptr) {
        error->clear();
    }
    try {
        for (int attempt = 0; attempt < kMaximumSnapshotAttempts; ++attempt) {
            auto snapshot = std::make_unique<Impl>();
            if (snapshot->load(error)) {
                impl_.swap(snapshot);
                if (error != nullptr) {
                    error->clear();
                }
                return true;
            }
            if (!snapshot->retryableSnapshotRace()) {
                return false;
            }
            std::this_thread::yield();
        }
        return fail(error, "source generation is unavailable");
    } catch (const std::bad_alloc&) {
        return fail(error, "source snapshot allocation failed");
    }
}

bool CameraSource::frame(
        bool videoRequest, int64_t monotonicTimestampNs,
        const std::atomic<bool>* cancelled,
        const std::chrono::steady_clock::time_point& deadline,
        SourceFrame* output, std::string* error) {
    if (error != nullptr) {
        error->clear();
    }
    return impl_->getFrame(videoRequest, monotonicTimestampNs, cancelled,
                           deadline, output, error);
}

void CameraSource::release() {
    impl_->release();
}

SourceMode CameraSource::mode() const {
    return impl_->mode();
}

uint64_t CameraSource::generation() const {
    return impl_->generation();
}

}  // namespace camera_provider
