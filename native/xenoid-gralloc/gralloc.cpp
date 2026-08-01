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
 * hardware/libhardware/modules/gralloc/gralloc.cpp. Camera-only BLOB and
 * flexible-YUV allocation extends that implementation without changing its
 * legacy handle or framebuffer behavior.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <new>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "gr.h"
#include "gralloc_priv.h"

extern "C" int ashmem_create_region(const char* name, size_t size);

struct gralloc_context_t {
    alloc_device_t device;
};

static int gralloc_device_open(const hw_module_t* module, const char* name,
                               hw_device_t** device);
int fb_device_open(const hw_module_t* module, const char* name, hw_device_t** device);

static struct hw_module_methods_t gralloc_module_methods = {
        .open = gralloc_device_open,
};

extern "C" {
__attribute__((visibility("default"))) struct private_module_t HAL_MODULE_INFO_SYM = {
        .base = {
                .common = {
                        .tag = HARDWARE_MODULE_TAG,
                        .module_api_version = GRALLOC_MODULE_API_VERSION_0_2,
                        .hal_api_version = 0,
                        .id = GRALLOC_HARDWARE_MODULE_ID,
                        .name = "Graphics Memory Allocator Module",
                        .author = "The Android Open Source Project",
                        .methods = &gralloc_module_methods,
                },
                .registerBuffer = gralloc_register_buffer,
                .unregisterBuffer = gralloc_unregister_buffer,
                .lock = gralloc_lock,
                .unlock = gralloc_unlock,
                .lock_ycbcr = gralloc_lock_ycbcr,
                .getTransportSize = gralloc_get_transport_size,
                .validateBufferSize = gralloc_validate_buffer_size,
        },
        .framebuffer = nullptr,
        .flags = 0,
        .numBuffers = 0,
        .bufferMask = 0,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .currentBuffer = nullptr,
};
}

static bool checkedMultiply(size_t left, size_t right, size_t* result) {
    if (left != 0 && right > SIZE_MAX / left) {
        return false;
    }
    *result = left * right;
    return true;
}

static bool checkedAdd(size_t left, size_t right, size_t* result) {
    if (right > SIZE_MAX - left) {
        return false;
    }
    *result = left + right;
    return true;
}

static int allocateSharedMemory(size_t requestedSize) {
    if (requestedSize == 0 || requestedSize > INT_MAX) {
        return -EINVAL;
    }
    const int fd = ashmem_create_region("gralloc-buffer", requestedSize);
    if (fd < 0) {
        const int error = errno != 0 ? errno : ENOMEM;
        ALOGE("couldn't create shared memory: %s", strerror(error));
        return -error;
    }
    return fd;
}

static int gralloc_alloc_buffer(alloc_device_t* dev, size_t size,
                                buffer_handle_t* outHandle) {
    size = roundUpToPageSize(size);
    const int fd = allocateSharedMemory(size);
    if (fd < 0) {
        return fd;
    }

    private_handle_t* handle =
            new (std::nothrow) private_handle_t(fd, static_cast<int>(size), 0);
    if (handle == nullptr) {
        close(fd);
        return -ENOMEM;
    }

    gralloc_module_t* module =
            reinterpret_cast<gralloc_module_t*>(dev->common.module);
    const int error = mapBuffer(module, handle);
    if (error != 0) {
        close(fd);
        delete handle;
        return error;
    }

    *outHandle = handle;
    return 0;
}

static int gralloc_alloc_camera_buffer(alloc_device_t* dev, size_t size, int format,
                                       int width, int height, int lumaStride,
                                       int chromaStride, buffer_handle_t* outHandle) {
    size = roundUpToPageSize(size);
    const int fd = allocateSharedMemory(size);
    if (fd < 0) {
        return fd;
    }

    camera_handle_t* handle = new (std::nothrow) camera_handle_t(
            fd, static_cast<int>(size), format, width, height, lumaStride, chromaStride);
    if (handle == nullptr) {
        close(fd);
        return -ENOMEM;
    }

    gralloc_module_t* module =
            reinterpret_cast<gralloc_module_t*>(dev->common.module);
    private_handle_t* prefix = reinterpret_cast<private_handle_t*>(handle);
    const int error = mapBuffer(module, prefix);
    if (error != 0) {
        close(fd);
        delete handle;
        return error;
    }

    *outHandle = handle;
    return 0;
}

static int gralloc_alloc_framebuffer_locked(alloc_device_t* dev, size_t size,
                                             int format, int usage,
                                             buffer_handle_t* outHandle) {
    private_module_t* module =
            reinterpret_cast<private_module_t*>(dev->common.module);

    if (module->framebuffer == nullptr) {
        const int error = mapFrameBufferLocked(module, format);
        if (error < 0) {
            return error;
        }
    }

    const uint32_t bufferMask = module->bufferMask;
    const uint32_t numBuffers = module->numBuffers;
    const size_t bufferSize = module->finfo.line_length * module->info.yres;
    if (numBuffers == 1) {
        const int newUsage = (usage & ~GRALLOC_USAGE_HW_FB) | GRALLOC_USAGE_HW_2D;
        (void)newUsage;
        return gralloc_alloc_buffer(dev, bufferSize, outHandle);
    }

    if (numBuffers == 0 || numBuffers >= 32 ||
        bufferMask >= ((UINT32_C(1) << numBuffers) - 1U) || size > INT_MAX) {
        return -ENOMEM;
    }

    intptr_t address = static_cast<intptr_t>(module->framebuffer->base);
    private_handle_t* handle = new (std::nothrow) private_handle_t(
            dup(module->framebuffer->fd), static_cast<int>(size),
            private_handle_t::PRIV_FLAGS_FRAMEBUFFER);
    if (handle == nullptr || handle->fd < 0) {
        if (handle != nullptr) {
            delete handle;
        }
        return -ENOMEM;
    }

    for (uint32_t index = 0; index < numBuffers; ++index) {
        if ((bufferMask & (UINT32_C(1) << index)) == 0) {
            module->bufferMask |= UINT32_C(1) << index;
            break;
        }
        address += bufferSize;
    }

    handle->base = address;
    handle->offset = address - static_cast<intptr_t>(module->framebuffer->base);
    *outHandle = handle;
    return 0;
}

static int gralloc_alloc_framebuffer(alloc_device_t* dev, size_t size, int format,
                                      int usage, buffer_handle_t* outHandle) {
    private_module_t* module =
            reinterpret_cast<private_module_t*>(dev->common.module);
    pthread_mutex_lock(&module->lock);
    const int error =
            gralloc_alloc_framebuffer_locked(dev, size, format, usage, outHandle);
    pthread_mutex_unlock(&module->lock);
    return error;
}

static int gralloc_alloc(alloc_device_t* dev, int width, int height, int format,
                         int usage, buffer_handle_t* outHandle, int* outStride) {
    if (dev == nullptr || outHandle == nullptr || outStride == nullptr || width <= 0 ||
        height <= 0) {
        return -EINVAL;
    }
    *outHandle = nullptr;
    *outStride = 0;

    if (format == HAL_PIXEL_FORMAT_BLOB) {
        if ((usage & GRALLOC_USAGE_HW_FB) != 0) {
            return -EINVAL;
        }
        size_t payloadSize;
        size_t size;
        if (!checkedMultiply(static_cast<size_t>(width), static_cast<size_t>(height),
                             &payloadSize) ||
            !checkedAdd(payloadSize, sizeof(camera3_jpeg_blob_t), &size)) {
            return -EINVAL;
        }
        const int error = gralloc_alloc_camera_buffer(
                dev, size, format, width, height, width, 0, outHandle);
        if (error == 0) {
            *outStride = width;
        }
        return error;
    }

    if (format == HAL_PIXEL_FORMAT_YCBCR_420_888 ||
        format == HAL_PIXEL_FORMAT_YV12) {
        if ((usage & GRALLOC_USAGE_HW_FB) != 0) {
            return -EINVAL;
        }
        const size_t lumaStride = alignTo(static_cast<size_t>(width), 16U);
        const size_t alignedHeight = alignTo(static_cast<size_t>(height), 2U);
        const size_t chromaStride =
                format == HAL_PIXEL_FORMAT_YV12
                        ? alignTo((lumaStride + 1U) / 2U, 16U)
                        : lumaStride;
        size_t ySize;
        size_t cPlaneSize;
        size_t chromaSize;
        size_t size;
        if (lumaStride > INT_MAX || chromaStride > INT_MAX ||
            !checkedMultiply(lumaStride, alignedHeight, &ySize) ||
            !checkedMultiply(chromaStride, alignedHeight / 2U, &cPlaneSize) ||
            (format == HAL_PIXEL_FORMAT_YV12 &&
             !checkedMultiply(cPlaneSize, 2U, &chromaSize))) {
            return -EINVAL;
        }
        if (format != HAL_PIXEL_FORMAT_YV12) {
            chromaSize = cPlaneSize;
        }
        if (!checkedAdd(ySize, chromaSize, &size)) {
            return -EINVAL;
        }
        const int error = gralloc_alloc_camera_buffer(
                dev, size, format, width, height, static_cast<int>(lumaStride),
                static_cast<int>(chromaStride), outHandle);
        if (error == 0) {
            *outStride = static_cast<int>(lumaStride);
        }
        return error;
    }

    int bytesPerPixel;
    switch (format) {
        case HAL_PIXEL_FORMAT_RGBA_FP16:
            bytesPerPixel = 8;
            break;
        case HAL_PIXEL_FORMAT_RGBA_8888:
        case HAL_PIXEL_FORMAT_RGBX_8888:
        case HAL_PIXEL_FORMAT_BGRA_8888:
            bytesPerPixel = 4;
            break;
        case HAL_PIXEL_FORMAT_RGB_888:
            bytesPerPixel = 3;
            break;
        case HAL_PIXEL_FORMAT_RGB_565:
        case HAL_PIXEL_FORMAT_RAW16:
            bytesPerPixel = 2;
            break;
        default:
            return -EINVAL;
    }

    const size_t stride = alignTo(static_cast<size_t>(width), 2U);
    const size_t alignedHeight = alignTo(static_cast<size_t>(height), 2U);
    size_t pixels;
    size_t bytes;
    size_t size;
    if (stride > INT_MAX || !checkedMultiply(alignedHeight, stride, &pixels) ||
        !checkedMultiply(pixels, static_cast<size_t>(bytesPerPixel), &bytes) ||
        !checkedAdd(bytes, 4U, &size)) {
        return -EINVAL;
    }

    int error;
    if ((usage & GRALLOC_USAGE_HW_FB) != 0) {
        error = gralloc_alloc_framebuffer(dev, size, format, usage, outHandle);
    } else {
        error = gralloc_alloc_buffer(dev, size, outHandle);
    }
    if (error < 0) {
        return error;
    }

    *outStride = static_cast<int>(stride);
    return 0;
}

static int gralloc_free(alloc_device_t* dev, buffer_handle_t buffer) {
    if (dev == nullptr || private_handle_t::validate(buffer) < 0) {
        return -EINVAL;
    }

    private_handle_t* handle = const_cast<private_handle_t*>(
            reinterpret_cast<const private_handle_t*>(buffer));
    if ((handle->flags & private_handle_t::PRIV_FLAGS_FRAMEBUFFER) != 0) {
        private_module_t* module =
                reinterpret_cast<private_module_t*>(dev->common.module);
        const size_t bufferSize = module->finfo.line_length * module->info.yres;
        if (bufferSize != 0 && handle->base >= module->framebuffer->base) {
            const size_t index = (handle->base - module->framebuffer->base) / bufferSize;
            if (index < module->numBuffers) {
                module->bufferMask &= ~(UINT32_C(1) << index);
            }
        }
    } else {
        gralloc_module_t* module =
                reinterpret_cast<gralloc_module_t*>(dev->common.module);
        terminateBuffer(module, handle);
    }

    close(handle->fd);
    if (private_handle_t::isCamera(buffer)) {
        delete reinterpret_cast<camera_handle_t*>(handle);
    } else {
        delete handle;
    }
    return 0;
}

static int gralloc_close(struct hw_device_t* device) {
    free(reinterpret_cast<gralloc_context_t*>(device));
    return 0;
}

static int gralloc_device_open(const hw_module_t* module, const char* name,
                               hw_device_t** device) {
    if (module == nullptr || name == nullptr || device == nullptr) {
        return -EINVAL;
    }

    if (strcmp(name, GRALLOC_HARDWARE_GPU0) != 0) {
        return fb_device_open(module, name, device);
    }

    gralloc_context_t* context =
            static_cast<gralloc_context_t*>(calloc(1, sizeof(*context)));
    if (context == nullptr) {
        return -ENOMEM;
    }

    context->device.common.tag = HARDWARE_DEVICE_TAG;
    context->device.common.version = 0;
    context->device.common.module = const_cast<hw_module_t*>(module);
    context->device.common.close = gralloc_close;
    context->device.alloc = gralloc_alloc;
    context->device.free = gralloc_free;

    *device = &context->device.common;
    return 0;
}
