/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Ported from android-13.0.0_r1
 * hardware/libhardware/modules/gralloc/mapper.cpp.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "gr.h"
#include "gralloc_priv.h"

namespace {

constexpr int kAcquireFenceTimeoutMs = 300;

class OwnedFd {
  public:
    explicit OwnedFd(int fd) : fd_(fd) {}
    ~OwnedFd() {
        if (fd_ >= 0) {
            close(fd_);
        }
    }

    OwnedFd(const OwnedFd&) = delete;
    OwnedFd& operator=(const OwnedFd&) = delete;

    int get() const { return fd_; }

  private:
    int fd_;
};

int waitForAcquireFence(int fenceFd) {
    if (fenceFd < 0) {
        return 0;
    }

    int duplicate;
    do {
        duplicate = fcntl(fenceFd, F_DUPFD_CLOEXEC, 0);
    } while (duplicate < 0 && errno == EINTR);
    if (duplicate < 0) {
        return -errno;
    }
    const OwnedFd waitFence(duplicate);

    pollfd descriptor = {
            .fd = waitFence.get(),
            .events = POLLIN,
            .revents = 0,
    };
    int result;
    do {
        result = poll(&descriptor, 1, kAcquireFenceTimeoutMs);
    } while (result < 0 && errno == EINTR);

    if (result == 0) {
        return -ETIMEDOUT;
    }
    if (result < 0) {
        return -errno;
    }
    if ((descriptor.revents & POLLNVAL) != 0) {
        return -EBADF;
    }
    if ((descriptor.revents & POLLERR) != 0) {
        return -EINVAL;
    }
    return 0;
}

}  // namespace

static int gralloc_map(gralloc_module_t const*, buffer_handle_t buffer,
                       void** outAddress) {
    if (outAddress == nullptr || private_handle_t::validate(buffer) < 0) {
        return -EINVAL;
    }

    private_handle_t* handle = const_cast<private_handle_t*>(
            reinterpret_cast<const private_handle_t*>(buffer));
    if ((handle->flags & private_handle_t::PRIV_FLAGS_FRAMEBUFFER) == 0) {
        void* mapped = mmap(nullptr, static_cast<size_t>(handle->size),
                            PROT_READ | PROT_WRITE, MAP_SHARED, handle->fd, 0);
        if (mapped == MAP_FAILED) {
            const int error = errno;
            ALOGE("Could not mmap buffer: %s", strerror(error));
            return -error;
        }
        handle->base = reinterpret_cast<uintptr_t>(mapped) + handle->offset;
    }

    *outAddress = reinterpret_cast<void*>(static_cast<uintptr_t>(handle->base));
    return 0;
}

static int gralloc_unmap(gralloc_module_t const*, buffer_handle_t buffer) {
    if (private_handle_t::validate(buffer) < 0) {
        return -EINVAL;
    }

    private_handle_t* handle = const_cast<private_handle_t*>(
            reinterpret_cast<const private_handle_t*>(buffer));
    int result = 0;
    if ((handle->flags & private_handle_t::PRIV_FLAGS_FRAMEBUFFER) == 0 &&
        handle->base != 0) {
        void* mapped = reinterpret_cast<void*>(
                static_cast<uintptr_t>(handle->base) - handle->offset);
        if (munmap(mapped, static_cast<size_t>(handle->size)) < 0) {
            result = -errno;
            ALOGE("Could not unmap buffer: %s", strerror(errno));
        }
    }
    handle->base = 0;
    return result;
}

int gralloc_register_buffer(gralloc_module_t const* module, buffer_handle_t buffer) {
    if (module == nullptr || private_handle_t::validate(buffer) < 0) {
        return -EINVAL;
    }

    private_handle_t* handle = const_cast<private_handle_t*>(
            reinterpret_cast<const private_handle_t*>(buffer));
    ALOGD_IF(handle->pid == getpid(),
             "Registering a buffer in the process that created it");

    void* address = nullptr;
    return gralloc_map(module, buffer, &address);
}

int gralloc_unregister_buffer(gralloc_module_t const* module,
                              buffer_handle_t buffer) {
    if (module == nullptr || private_handle_t::validate(buffer) < 0) {
        return -EINVAL;
    }

    private_handle_t* handle = const_cast<private_handle_t*>(
            reinterpret_cast<const private_handle_t*>(buffer));
    return handle->base != 0 ? gralloc_unmap(module, buffer) : 0;
}

int mapBuffer(gralloc_module_t const* module, private_handle_t* handle) {
    if (module == nullptr || private_handle_t::validate(handle) < 0) {
        return -EINVAL;
    }
    void* address = nullptr;
    return gralloc_map(module, handle, &address);
}

int terminateBuffer(gralloc_module_t const* module, private_handle_t* handle) {
    if (module == nullptr || private_handle_t::validate(handle) < 0) {
        return -EINVAL;
    }
    return handle->base != 0 ? gralloc_unmap(module, handle) : 0;
}

int gralloc_lock(gralloc_module_t const*, buffer_handle_t buffer, int, int, int,
                 int, int, void** outAddress) {
    if (outAddress == nullptr || private_handle_t::validate(buffer) < 0) {
        return -EINVAL;
    }
    if (private_handle_t::isCamera(buffer)) {
        const camera_handle_t* camera =
                reinterpret_cast<const camera_handle_t*>(buffer);
        if (camera->format == HAL_PIXEL_FORMAT_YCBCR_420_888) {
            return -EINVAL;
        }
    }

    const private_handle_t* handle =
            reinterpret_cast<const private_handle_t*>(buffer);
    if (handle->base == 0) {
        return -EINVAL;
    }
    *outAddress = reinterpret_cast<void*>(static_cast<uintptr_t>(handle->base));
    return 0;
}

int gralloc_lock_async(gralloc_module_t const* module, buffer_handle_t buffer,
                       int usage, int left, int top, int width, int height,
                       void** outAddress, int fenceFd) {
    const int waitError = waitForAcquireFence(fenceFd);
    if (waitError != 0) {
        return waitError;
    }
    return gralloc_lock(module, buffer, usage, left, top, width, height,
                        outAddress);
}

int gralloc_lock_ycbcr(gralloc_module_t const*, buffer_handle_t buffer, int,
                       int left, int top, int width, int height,
                       struct android_ycbcr* outYcbcr) {
    const int validation = private_handle_t::validate(buffer);
    if (outYcbcr == nullptr || validation < 0 ||
        !private_handle_t::isCamera(buffer)) {
        ALOGE("lock_ycbcr rejected handle: output=%p validation=%d camera=%d",
              outYcbcr, validation, private_handle_t::isCamera(buffer));
        return -EINVAL;
    }

    const camera_handle_t* handle =
            reinterpret_cast<const camera_handle_t*>(buffer);
    const bool wholeBuffer = left == 0 && top == 0 && width == 0 && height == 0;
    if ((handle->format != HAL_PIXEL_FORMAT_YCBCR_420_888 &&
         handle->format != HAL_PIXEL_FORMAT_YV12) ||
        handle->base == 0 || left < 0 || top < 0 ||
        (!wholeBuffer &&
         (width <= 0 || height <= 0 || left > handle->width - width ||
          top > handle->height - height))) {
        ALOGE("lock_ycbcr rejected geometry: format=%d base=%llu rect=%d,%d %dx%d "
              "buffer=%dx%d luma=%d chroma=%d",
              handle->format, static_cast<unsigned long long>(handle->base),
              left, top, width, height, handle->width, handle->height,
              handle->lumaStride, handle->chromaStride);
        return -EINVAL;
    }

    uint8_t* const y =
            reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(handle->base));
    const size_t alignedHeight = alignTo(static_cast<size_t>(handle->height), 2U);
    uint8_t* const firstChroma =
            y + static_cast<size_t>(handle->lumaStride) * alignedHeight;

    memset(outYcbcr, 0, sizeof(*outYcbcr));
    outYcbcr->y = y;
    if (handle->format == HAL_PIXEL_FORMAT_YV12) {
        outYcbcr->cr = firstChroma;
        outYcbcr->cb =
                firstChroma + static_cast<size_t>(handle->chromaStride) *
                                      (alignedHeight / 2U);
        outYcbcr->chroma_step = 1;
    } else {
        outYcbcr->cb = firstChroma;
        outYcbcr->cr = firstChroma + 1;
        outYcbcr->chroma_step = 2;
    }
    outYcbcr->ystride = static_cast<size_t>(handle->lumaStride);
    outYcbcr->cstride = static_cast<size_t>(handle->chromaStride);
    return 0;
}

int gralloc_lock_async_ycbcr(gralloc_module_t const* module,
                             buffer_handle_t buffer, int usage, int left,
                             int top, int width, int height,
                             struct android_ycbcr* outYcbcr, int fenceFd) {
    const int waitError = waitForAcquireFence(fenceFd);
    if (waitError != 0) {
        return waitError;
    }
    return gralloc_lock_ycbcr(module, buffer, usage, left, top, width, height,
                              outYcbcr);
}

int gralloc_unlock(gralloc_module_t const*, buffer_handle_t buffer) {
    return private_handle_t::validate(buffer) < 0 ? -EINVAL : 0;
}

int gralloc_unlock_async(gralloc_module_t const* module, buffer_handle_t buffer,
                         int* fenceFd) {
    if (fenceFd == nullptr) {
        return -EINVAL;
    }
    *fenceFd = -1;
    return gralloc_unlock(module, buffer);
}

int32_t gralloc_get_transport_size(gralloc_module_t const*, buffer_handle_t buffer,
                                   uint32_t* outNumFds, uint32_t* outNumInts) {
    if (outNumFds == nullptr || outNumInts == nullptr ||
        private_handle_t::validate(buffer) < 0) {
        return -EINVAL;
    }
    *outNumFds = static_cast<uint32_t>(buffer->numFds);
    *outNumInts = static_cast<uint32_t>(buffer->numInts);
    return 0;
}

static bool checkedBufferBytes(uint32_t height, uint32_t stride,
                               uint32_t bytesPerPixel, uint64_t* outBytes) {
    const uint64_t alignedHeight = (static_cast<uint64_t>(height) + 1U) & ~UINT64_C(1);
    const uint64_t pixels = alignedHeight * stride;
    if (bytesPerPixel != 0 && pixels > (UINT64_MAX - 4U) / bytesPerPixel) {
        return false;
    }
    *outBytes = pixels * bytesPerPixel + 4U;
    return true;
}

int32_t gralloc_validate_buffer_size(gralloc_module_t const*, buffer_handle_t buffer,
                                     uint32_t width, uint32_t height, int32_t format,
                                     int, uint32_t stride) {
    if (width == 0 || height == 0 || private_handle_t::validate(buffer) < 0) {
        return -EINVAL;
    }

    const private_handle_t* legacy =
            reinterpret_cast<const private_handle_t*>(buffer);
    if (private_handle_t::isCamera(buffer)) {
        const camera_handle_t* camera =
                reinterpret_cast<const camera_handle_t*>(buffer);
        if (format != camera->format || width != static_cast<uint32_t>(camera->width) ||
            height != static_cast<uint32_t>(camera->height)) {
            return -EINVAL;
        }
        if (format == HAL_PIXEL_FORMAT_YCBCR_420_888 ||
            format == HAL_PIXEL_FORMAT_YV12) {
            return stride == static_cast<uint32_t>(camera->lumaStride) ? 0 : -EINVAL;
        }
        return stride == width ? 0 : -EINVAL;
    }

    if (stride < width) {
        return -EINVAL;
    }
    uint32_t bytesPerPixel;
    switch (format) {
        case HAL_PIXEL_FORMAT_RGBA_FP16:
            bytesPerPixel = 8;
            break;
        case HAL_PIXEL_FORMAT_RGBA_8888:
        case HAL_PIXEL_FORMAT_RGBX_8888:
        case HAL_PIXEL_FORMAT_BGRA_8888:
        case HAL_PIXEL_FORMAT_RGBA_1010102:
            bytesPerPixel = 4;
            break;
        case HAL_PIXEL_FORMAT_RGB_888:
            bytesPerPixel = 3;
            break;
        case HAL_PIXEL_FORMAT_RGB_565:
        case HAL_PIXEL_FORMAT_RAW16:
            bytesPerPixel = 2;
            break;
        case HAL_PIXEL_FORMAT_R_8:
            bytesPerPixel = 1;
            break;
        default:
            return -EINVAL;
    }

    uint64_t minimumSize;
    if (!checkedBufferBytes(height, stride, bytesPerPixel, &minimumSize) ||
        minimumSize > static_cast<uint32_t>(legacy->size)) {
        return -EINVAL;
    }
    return 0;
}
