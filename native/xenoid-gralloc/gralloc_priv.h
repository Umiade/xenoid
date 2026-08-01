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

#ifndef REDROID_GRALLOC_PRIV_H_
#define REDROID_GRALLOC_PRIV_H_

/*
 * Ported from android-13.0.0_r1
 * hardware/libhardware/modules/gralloc/gralloc_priv.h.
 */

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>

#include <linux/fb.h>

#include "android_compat.h"

struct private_handle_t;
struct camera_handle_t;

struct private_module_t {
    gralloc_module_t base;

    private_handle_t* framebuffer;
    uint32_t flags;
    uint32_t numBuffers;
    uint32_t bufferMask;
    pthread_mutex_t lock;
    buffer_handle_t currentBuffer;
    int pmem_master;
    void* pmem_master_base;

    struct fb_var_screeninfo info;
    struct fb_fix_screeninfo finfo;
    float xdpi;
    float ydpi;
    float fps;
};

/*
 * This is the Android 13 AOSP legacy wire layout. The explicit reserved int
 * names the trailing padding that is already counted by upstream sNumInts().
 * Consequently RGB, framebuffer, and RAW16 handles remain one fd plus exactly
 * eight ints, at the same offsets as the stock allocator.
 */
struct private_handle_t : public native_handle_t {
    enum {
        PRIV_FLAGS_FRAMEBUFFER = 0x00000001,
        sNumFds = 1,
        sNumInts = 8,
        sMagic = 0x03141592,
    };

    int fd;
    int magic;
    int flags;
    int size;
    int offset;
    uint64_t base __attribute__((aligned(8)));
    int pid;
    int reserved;

    private_handle_t(int bufferFd, int bufferSize, int bufferFlags)
        : fd(bufferFd),
          magic(sMagic),
          flags(bufferFlags),
          size(bufferSize),
          offset(0),
          base(0),
          pid(getpid()),
          reserved(0) {
        version = sizeof(native_handle_t);
        numFds = sNumFds;
        numInts = sNumInts;
    }

    ~private_handle_t() { magic = 0; }

    static int validate(const native_handle_t* handle);
    static bool isCamera(const native_handle_t* handle) {
        return handle != nullptr && handle->numFds == sNumFds &&
               handle->numInts == cameraNumInts;
    }

    static constexpr int cameraNumInts = sNumInts + 5;
};

/*
 * Only camera-only formats use this extended shape. Its prefix is identical
 * to private_handle_t, including the legacy reserved transport int. The five
 * appended ints are format, width, height, luma stride, and chroma stride.
 */
struct camera_handle_t : public native_handle_t {
    int fd;
    int magic;
    int flags;
    int size;
    int offset;
    uint64_t base __attribute__((aligned(8)));
    int pid;
    int reserved;
    int format;
    int width;
    int height;
    int lumaStride;
    int chromaStride;

    camera_handle_t(int bufferFd, int bufferSize, int pixelFormat, int bufferWidth,
                    int bufferHeight, int yStride, int cStride)
        : fd(bufferFd),
          magic(private_handle_t::sMagic),
          flags(0),
          size(bufferSize),
          offset(0),
          base(0),
          pid(getpid()),
          reserved(0),
          format(pixelFormat),
          width(bufferWidth),
          height(bufferHeight),
          lumaStride(yStride),
          chromaStride(cStride) {
        version = sizeof(native_handle_t);
        numFds = private_handle_t::sNumFds;
        numInts = private_handle_t::cameraNumInts;
    }

    ~camera_handle_t() { magic = 0; }
};

static_assert(sizeof(private_handle_t) == 48,
              "legacy private handle must remain 48 bytes on Android LP64");
static_assert(sizeof(camera_handle_t) == 72,
              "extended camera handle object layout changed");

inline int private_handle_t::validate(const native_handle_t* handle) {
    if (handle == nullptr || handle->version != sizeof(native_handle_t) ||
        handle->numFds != sNumFds ||
        (handle->numInts != sNumInts && handle->numInts != cameraNumInts)) {
        return -EINVAL;
    }

    const private_handle_t* legacy =
            reinterpret_cast<const private_handle_t*>(handle);
    if (legacy->magic != sMagic) {
        return -EINVAL;
    }
    if (handle->numInts == sNumInts) {
        return 0;
    }

    const camera_handle_t* camera =
            reinterpret_cast<const camera_handle_t*>(handle);
    if (camera->flags != 0 || camera->offset != 0 || camera->size <= 0 ||
        camera->width <= 0 || camera->height <= 0) {
        return -EINVAL;
    }

    const uint64_t width = static_cast<uint32_t>(camera->width);
    const uint64_t height = static_cast<uint32_t>(camera->height);
    uint64_t minimumSize = 0;
    if (camera->format == HAL_PIXEL_FORMAT_BLOB) {
        if (camera->lumaStride != camera->width || camera->chromaStride != 0) {
            return -EINVAL;
        }
        minimumSize = width * height + sizeof(camera3_jpeg_blob_t);
    } else if (camera->format == HAL_PIXEL_FORMAT_YCBCR_420_888 ||
               camera->format == HAL_PIXEL_FORMAT_YV12) {
        const uint64_t expectedStride = (width + 15U) & ~UINT64_C(15);
        const uint64_t expectedChromaStride =
                camera->format == HAL_PIXEL_FORMAT_YV12
                        ? ((expectedStride + 1U) / 2U + 15U) & ~UINT64_C(15)
                        : expectedStride;
        const uint64_t alignedHeight = (height + 1U) & ~UINT64_C(1);
        if (camera->lumaStride != static_cast<int>(expectedStride) ||
            camera->chromaStride != static_cast<int>(expectedChromaStride)) {
            return -EINVAL;
        }
        const uint64_t chromaPlanes =
                camera->format == HAL_PIXEL_FORMAT_YV12 ? 2U : 1U;
        minimumSize = expectedStride * alignedHeight +
                      expectedChromaStride * (alignedHeight / 2U) * chromaPlanes;
    } else {
        return -EINVAL;
    }

    return minimumSize <= static_cast<uint32_t>(camera->size) ? 0 : -EINVAL;
}

#endif  // REDROID_GRALLOC_PRIV_H_
