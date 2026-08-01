#include <jni.h>

#include <camera/NdkCameraManager.h>
#include <camera/NdkCameraMetadata.h>
#include <media/NdkImage.h>
#include <media/NdkImageReader.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <sstream>
#include <utility>
#include <string>

namespace {

struct CaptureState {
    std::mutex mutex;
    std::condition_variable changed;
    bool imageReady = false;
    bool resultReady = false;
    bool sequenceDone = false;
    bool failed = false;
    int imageBytes = 0;
    int sampleBytes = 0;
    uint64_t fingerprint = 0;
    std::array<uint8_t, 16 * 12 * 3> sample{};
    int64_t imageTimestamp = -1;
    int64_t resultTimestamp = -1;
};

struct CameraResult {
    std::string id;
    int imageBytes = 0;
    uint64_t fingerprint = 0;
    std::array<uint8_t, 16 * 12 * 3> sample{};
};

void fail(CaptureState* state) {
    if (state == nullptr) return;
    std::lock_guard<std::mutex> lock(state->mutex);
    state->failed = true;
    state->changed.notify_all();
}

uint8_t clampByte(int value) {
    return static_cast<uint8_t>(std::max(0, std::min(255, value)));
}

bool planeValue(uint8_t* data, int length, int rowStride, int pixelStride,
                int x, int y, uint8_t* value) {
    if (data == nullptr || value == nullptr || length <= 0 ||
        rowStride <= 0 || pixelStride <= 0 || x < 0 || y < 0) {
        return false;
    }
    const int64_t offset = static_cast<int64_t>(y) * rowStride +
            static_cast<int64_t>(x) * pixelStride;
    if (offset < 0 || offset >= length) return false;
    *value = data[offset];
    return true;
}

void imageAvailable(void* context, AImageReader* reader) {
    auto* state = static_cast<CaptureState*>(context);
    AImage* image = nullptr;
    if (state == nullptr ||
        AImageReader_acquireNextImage(reader, &image) != AMEDIA_OK || image == nullptr) {
        fail(state);
        return;
    }

    int64_t timestamp = -1;
    int planeCount = 0;
    int width = 0;
    int height = 0;
    int32_t format = 0;
    AImageCropRect crop{};
    bool valid = AImage_getTimestamp(image, &timestamp) == AMEDIA_OK &&
            AImage_getNumberOfPlanes(image, &planeCount) == AMEDIA_OK &&
            AImage_getWidth(image, &width) == AMEDIA_OK &&
            AImage_getHeight(image, &height) == AMEDIA_OK &&
            AImage_getFormat(image, &format) == AMEDIA_OK &&
            format == AIMAGE_FORMAT_YUV_420_888 && planeCount == 3 &&
            width > 0 && height > 0;
    if (valid && AImage_getCropRect(image, &crop) != AMEDIA_OK) {
        crop.left = 0;
        crop.top = 0;
        crop.right = width;
        crop.bottom = height;
    }
    valid = valid && crop.left >= 0 && crop.top >= 0 &&
            crop.right > crop.left && crop.bottom > crop.top &&
            crop.right <= width && crop.bottom <= height;

    uint8_t* planeData[3] = {};
    int planeLength[3] = {};
    int rowStride[3] = {};
    int pixelStride[3] = {};
    int bytes = 0;
    for (int plane = 0; valid && plane < 3; ++plane) {
        valid = AImage_getPlaneData(
                        image, plane, &planeData[plane], &planeLength[plane]) == AMEDIA_OK &&
                AImage_getPlaneRowStride(image, plane, &rowStride[plane]) == AMEDIA_OK &&
                AImage_getPlanePixelStride(image, plane, &pixelStride[plane]) == AMEDIA_OK &&
                planeData[plane] != nullptr && planeLength[plane] > 0 &&
                rowStride[plane] > 0 && pixelStride[plane] > 0;
        if (valid) bytes += planeLength[plane];
    }

    std::array<uint8_t, 16 * 12 * 3> sample{};
    uint64_t fingerprint = 0xcbf29ce484222325ULL;
    for (int sampleY = 0; valid && sampleY < 12; ++sampleY) {
        const int sourceY = std::min(crop.bottom - 1,
                crop.top + ((2 * sampleY + 1) * (crop.bottom - crop.top)) / 24);
        for (int sampleX = 0; valid && sampleX < 16; ++sampleX) {
            const int sourceX = std::min(crop.right - 1,
                    crop.left + ((2 * sampleX + 1) * (crop.right - crop.left)) / 32);
            uint8_t y = 0;
            uint8_t u = 0;
            uint8_t v = 0;
            valid = planeValue(planeData[0], planeLength[0], rowStride[0],
                            pixelStride[0], sourceX, sourceY, &y) &&
                    planeValue(planeData[1], planeLength[1], rowStride[1],
                            pixelStride[1], sourceX / 2, sourceY / 2, &u) &&
                    planeValue(planeData[2], planeLength[2], rowStride[2],
                            pixelStride[2], sourceX / 2, sourceY / 2, &v);
            if (!valid) break;
            const int c = std::max(0, static_cast<int>(y) - 16);
            const int d = static_cast<int>(u) - 128;
            const int e = static_cast<int>(v) - 128;
            const int base = (sampleY * 16 + sampleX) * 3;
            sample[base] = clampByte((298 * c + 409 * e + 128) >> 8);
            sample[base + 1] =
                    clampByte((298 * c - 100 * d - 208 * e + 128) >> 8);
            sample[base + 2] = clampByte((298 * c + 516 * d + 128) >> 8);
            for (int channel = 0; channel < 3; ++channel) {
                fingerprint ^= sample[base + channel];
                fingerprint *= 0x100000001b3ULL;
            }
        }
    }
    AImage_delete(image);

    std::lock_guard<std::mutex> lock(state->mutex);
    state->imageReady = valid;
    state->imageBytes = valid ? bytes : 0;
    state->sampleBytes = valid ? static_cast<int>(sample.size()) : 0;
    state->fingerprint = valid ? fingerprint : 0;
    if (valid) state->sample = sample;
    state->imageTimestamp = valid ? timestamp : -1;
    if (!valid) state->failed = true;
    state->changed.notify_all();
}

void deviceDisconnected(void* context, ACameraDevice*) {
    fail(static_cast<CaptureState*>(context));
}
void deviceError(void* context, ACameraDevice*, int) {
    fail(static_cast<CaptureState*>(context));
}
void sessionClosed(void*, ACameraCaptureSession*) {}
void sessionReady(void*, ACameraCaptureSession*) {}
void sessionActive(void*, ACameraCaptureSession*) {}
void captureStarted(void*, ACameraCaptureSession*, const ACaptureRequest*, int64_t) {}
void captureProgressed(void*, ACameraCaptureSession*, ACaptureRequest*, const ACameraMetadata*) {}

void captureCompleted(void* context, ACameraCaptureSession*, ACaptureRequest*,
                      const ACameraMetadata* metadata) {
    auto* state = static_cast<CaptureState*>(context);
    if (state == nullptr) return;
    ACameraMetadata_const_entry entry{};
    const bool valid = metadata != nullptr &&
            ACameraMetadata_getConstEntry(metadata, ACAMERA_SENSOR_TIMESTAMP, &entry) ==
                    ACAMERA_OK &&
            entry.count == 1 && entry.data.i64 != nullptr;
    std::lock_guard<std::mutex> lock(state->mutex);
    state->resultReady = valid;
    state->resultTimestamp = valid ? entry.data.i64[0] : -1;
    if (!valid) state->failed = true;
    state->changed.notify_all();
}

void captureFailed(void* context, ACameraCaptureSession*, ACaptureRequest*,
                   ACameraCaptureFailure*) {
    fail(static_cast<CaptureState*>(context));
}
void sequenceCompleted(void* context, ACameraCaptureSession*, int, int64_t) {
    auto* state = static_cast<CaptureState*>(context);
    if (state == nullptr) return;
    std::lock_guard<std::mutex> lock(state->mutex);
    state->sequenceDone = true;
    state->changed.notify_all();
}
void sequenceAborted(void* context, ACameraCaptureSession*, int) {
    fail(static_cast<CaptureState*>(context));
}
void bufferLost(void* context, ACameraCaptureSession*, ACaptureRequest*,
                ACameraWindowType*, int64_t) {
    fail(static_cast<CaptureState*>(context));
}

bool captureOne(ACameraManager* manager, const char* id, CameraResult* result) {
    if (manager == nullptr || id == nullptr || result == nullptr) return false;
    CaptureState state;
    AImageReader* reader = nullptr;
    ANativeWindow* window = nullptr;
    ACameraDevice* device = nullptr;
    ACaptureSessionOutputContainer* container = nullptr;
    ACaptureSessionOutput* output = nullptr;
    ACameraCaptureSession* session = nullptr;
    ACameraOutputTarget* target = nullptr;
    ACaptureRequest* request = nullptr;
    bool success = false;

    if (AImageReader_new(320, 240, AIMAGE_FORMAT_YUV_420_888, 4, &reader) != AMEDIA_OK ||
        reader == nullptr) goto cleanup;
    {
        AImageReader_ImageListener listener{};
        listener.context = &state;
        listener.onImageAvailable = imageAvailable;
        if (AImageReader_setImageListener(reader, &listener) != AMEDIA_OK) goto cleanup;
    }
    if (AImageReader_getWindow(reader, &window) != AMEDIA_OK || window == nullptr) goto cleanup;
    {
        ACameraDevice_StateCallbacks callbacks{};
        callbacks.context = &state;
        callbacks.onDisconnected = deviceDisconnected;
        callbacks.onError = deviceError;
        if (ACameraManager_openCamera(manager, id, &callbacks, &device) != ACAMERA_OK ||
            device == nullptr) goto cleanup;
    }
    if (ACaptureSessionOutputContainer_create(&container) != ACAMERA_OK ||
        container == nullptr) goto cleanup;
    if (ACaptureSessionOutput_create(window, &output) != ACAMERA_OK || output == nullptr) {
        goto cleanup;
    }
    if (ACaptureSessionOutputContainer_add(container, output) != ACAMERA_OK) goto cleanup;
    {
        ACameraCaptureSession_stateCallbacks callbacks{};
        callbacks.context = nullptr;
        callbacks.onClosed = sessionClosed;
        callbacks.onReady = sessionReady;
        callbacks.onActive = sessionActive;
        if (ACameraDevice_createCaptureSession(device, container, &callbacks, &session) !=
                    ACAMERA_OK ||
            session == nullptr) goto cleanup;
    }
    if (ACameraDevice_createCaptureRequest(device, TEMPLATE_STILL_CAPTURE, &request) !=
                ACAMERA_OK ||
        request == nullptr) goto cleanup;
    if (ACameraOutputTarget_create(window, &target) != ACAMERA_OK || target == nullptr) {
        goto cleanup;
    }
    if (ACaptureRequest_addTarget(request, target) != ACAMERA_OK) goto cleanup;
    {
        ACameraCaptureSession_captureCallbacks callbacks{};
        callbacks.context = &state;
        callbacks.onCaptureStarted = captureStarted;
        callbacks.onCaptureProgressed = captureProgressed;
        callbacks.onCaptureCompleted = captureCompleted;
        callbacks.onCaptureFailed = captureFailed;
        callbacks.onCaptureSequenceCompleted = sequenceCompleted;
        callbacks.onCaptureSequenceAborted = sequenceAborted;
        callbacks.onCaptureBufferLost = bufferLost;
        ACaptureRequest* requests[] = {request};
        int sequence = -1;
        if (ACameraCaptureSession_capture(session, &callbacks, 1, requests, &sequence) !=
                ACAMERA_OK) goto cleanup;
    }
    {
        std::unique_lock<std::mutex> lock(state.mutex);
        const bool terminal = state.changed.wait_for(lock, std::chrono::seconds(15), [&state] {
            return state.failed || (state.imageReady && state.resultReady && state.sequenceDone);
        });
        if (!terminal || state.failed || state.imageBytes <= 0 ||
            state.sampleBytes != static_cast<int>(state.sample.size()) ||
            state.imageTimestamp <= 0 || state.imageTimestamp != state.resultTimestamp) {
            goto cleanup;
        }
        result->id = id;
        result->imageBytes = state.imageBytes;
        result->fingerprint = state.fingerprint;
        result->sample = state.sample;
        success = true;
    }

cleanup:
    if (session != nullptr) ACameraCaptureSession_close(session);
    if (request != nullptr) ACaptureRequest_free(request);
    if (target != nullptr) ACameraOutputTarget_free(target);
    if (container != nullptr && output != nullptr) {
        ACaptureSessionOutputContainer_remove(container, output);
    }
    if (output != nullptr) ACaptureSessionOutput_free(output);
    if (container != nullptr) ACaptureSessionOutputContainer_free(container);
    if (device != nullptr) ACameraDevice_close(device);
    if (reader != nullptr) {
        AImageReader_setImageListener(reader, nullptr);
        AImageReader_delete(reader);
    }
    return success;
}

bool cameraListHasBoth(ACameraManager* manager) {
    ACameraIdList* list = nullptr;
    if (ACameraManager_getCameraIdList(manager, &list) != ACAMERA_OK || list == nullptr) {
        return false;
    }
    bool zero = false;
    bool one = false;
    for (int index = 0; index < list->numCameras; ++index) {
        const std::string id = list->cameraIds[index] == nullptr ? "" : list->cameraIds[index];
        zero |= id == "0";
        one |= id == "1";
    }
    const bool exact = list->numCameras == 2 && zero && one;
    ACameraManager_deleteCameraIdList(list);
    return exact;
}

std::string runCaptureProbe() {
    ACameraManager* manager = ACameraManager_create();
    if (manager == nullptr || !cameraListHasBoth(manager)) {
        if (manager != nullptr) ACameraManager_delete(manager);
        return "{\"schema\":\"org.example.camera-runtime-probe/v1\",\"probe\":\"ndk-camera\",\"ok\":false,\"error\":\"camera list mismatch\"}";
    }
    CameraResult results[2];
    const char* ids[] = {"0", "1"};
    bool ok = captureOne(manager, ids[0], &results[0]) &&
              captureOne(manager, ids[1], &results[1]);
    std::ostringstream output;
    output << "{\"schema\":\"org.example.camera-runtime-probe/v1\","
           << "\"probe\":\"ndk-camera\",\"ok\":" << (ok ? "true" : "false");
    if (ok) {
        output << ",\"cameras\":[";
        for (int index = 0; index < 2; ++index) {
            if (index != 0) output << ',';
            output << "{\"id\":\"" << results[index].id
                   << "\",\"imageNonempty\":"
                   << (results[index].imageBytes > 0 ? "true" : "false")
                   << ",\"timestampsMatched\":true,\"sample\":[";
            for (size_t channel = 0; channel < results[index].sample.size(); ++channel) {
                if (channel != 0) output << ',';
                output << static_cast<unsigned int>(results[index].sample[channel]);
            }
            output << "],\"fingerprint\":\"" << results[index].fingerprint
                   << "\",\"ok\":true}";
        }
        output << ']';
    } else {
        output << ",\"error\":\"capture failed\"";
    }
    output << '}';
    ACameraManager_delete(manager);
    return output.str();
}

std::string runIsolationProbe() {
    ACameraManager* manager = ACameraManager_create();
    if (manager == nullptr) return "{\"ok\":false}";
    bool denied[2] = {false, false};
    const char* ids[] = {"0", "1"};
    for (int index = 0; index < 2; ++index) {
        ACameraDevice* device = nullptr;
        ACameraDevice_StateCallbacks callbacks{};
        callbacks.context = nullptr;
        callbacks.onDisconnected = deviceDisconnected;
        callbacks.onError = deviceError;
        camera_status_t status = ACameraManager_openCamera(manager, ids[index],
                &callbacks, &device);
        denied[index] = status != ACAMERA_OK || device == nullptr;
        if (device != nullptr) ACameraDevice_close(device);
    }
    ACameraManager_delete(manager);
    std::ostringstream output;
    output << "{\"ids\":[\"0\",\"1\"],\"accessDenied\":["
           << (denied[0] ? "true" : "false") << ','
           << (denied[1] ? "true" : "false") << "]}";
    return output.str();
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_org_example_cameraruntimeprobe_NdkProbeActivity_runNativeProbe(JNIEnv* env, jclass) {
    const std::string result = runCaptureProbe();
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_org_example_cameraruntimeprobe_IsolationProbeService_runNativeIsolationProbe(
        JNIEnv* env, jclass) {
    const std::string result = runIsolationProbe();
    return env->NewStringUTF(result.c_str());
}
