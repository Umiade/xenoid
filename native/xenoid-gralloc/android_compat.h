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

#ifndef REDROID_GRALLOC_ANDROID_COMPAT_H_
#define REDROID_GRALLOC_ANDROID_COMPAT_H_

/*
 * Android 13 legacy HAL ABI definitions, kept self-contained because the
 * public NDK does not ship libhardware's legacy gralloc headers. Derived from
 * android-13.0.0_r1:
 *   hardware/libhardware/include/hardware/{hardware,gralloc,fb,camera3}.h
 *   system/core/libcutils/include/cutils/native_handle.h
 *   system/core/libsystem/include/system/{graphics,graphics-base}.h
 */

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct native_handle {
    int version;
    int numFds;
    int numInts;
    int data[0];
} native_handle_t;

typedef const native_handle_t* buffer_handle_t;

#define MAKE_TAG_CONSTANT(A, B, C, D) \
    (((A) << 24) | ((B) << 16) | ((C) << 8) | (D))
#define HARDWARE_MODULE_TAG MAKE_TAG_CONSTANT('H', 'W', 'M', 'T')
#define HARDWARE_DEVICE_TAG MAKE_TAG_CONSTANT('H', 'W', 'D', 'T')
#define HARDWARE_MAKE_API_VERSION(maj, min) ((((maj) & 0xff) << 8) | ((min) & 0xff))
#define HARDWARE_MODULE_API_VERSION(maj, min) HARDWARE_MAKE_API_VERSION(maj, min)
#define HARDWARE_DEVICE_API_VERSION(maj, min) HARDWARE_MAKE_API_VERSION(maj, min)
#define HARDWARE_HAL_API_VERSION HARDWARE_MAKE_API_VERSION(1, 0)

struct hw_module_t;
struct hw_device_t;

typedef struct hw_module_methods_t {
    int (*open)(const struct hw_module_t* module, const char* id,
                struct hw_device_t** device);
} hw_module_methods_t;

typedef struct hw_module_t {
    uint32_t tag;
    uint16_t module_api_version;
    uint16_t hal_api_version;
    const char* id;
    const char* name;
    const char* author;
    struct hw_module_methods_t* methods;
    void* dso;
#if defined(__LP64__)
    uint64_t reserved[32 - 7];
#else
    uint32_t reserved[32 - 7];
#endif
} hw_module_t;

typedef struct hw_device_t {
    uint32_t tag;
    uint32_t version;
    struct hw_module_t* module;
#if defined(__LP64__)
    uint64_t reserved[12];
#else
    uint32_t reserved[12];
#endif
    int (*close)(struct hw_device_t* device);
} hw_device_t;

#define HAL_MODULE_INFO_SYM HMI
#define HAL_MODULE_INFO_SYM_AS_STR "HMI"

/* Values from android-13.0.0_r1 system/graphics-base.h. */
enum {
    HAL_PIXEL_FORMAT_RGBA_8888 = 1,
    HAL_PIXEL_FORMAT_RGBX_8888 = 2,
    HAL_PIXEL_FORMAT_RGB_888 = 3,
    HAL_PIXEL_FORMAT_RGB_565 = 4,
    HAL_PIXEL_FORMAT_BGRA_8888 = 5,
    HAL_PIXEL_FORMAT_RGBA_FP16 = 0x16,
    HAL_PIXEL_FORMAT_RAW16 = 0x20,
    HAL_PIXEL_FORMAT_BLOB = 0x21,
    HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED = 0x22,
    HAL_PIXEL_FORMAT_YCBCR_420_888 = 0x23,
    HAL_PIXEL_FORMAT_RGBA_1010102 = 0x2B,
    HAL_PIXEL_FORMAT_R_8 = 0x38,
    HAL_PIXEL_FORMAT_YV12 = 0x32315659,
};
#define HAL_PIXEL_FORMAT_YCbCr_420_888 HAL_PIXEL_FORMAT_YCBCR_420_888

struct android_ycbcr {
    void* y;
    void* cb;
    void* cr;
    size_t ystride;
    size_t cstride;
    size_t chroma_step;
    uint32_t reserved[8];
};

typedef struct camera3_jpeg_blob {
    uint16_t jpeg_blob_id;
    uint32_t jpeg_size;
} camera3_jpeg_blob_t;

#if defined(__cplusplus)
static_assert(sizeof(camera3_jpeg_blob_t) == 8,
              "Android 13 camera3 JPEG footer ABI changed");
#endif

#define GRALLOC_MODULE_API_VERSION_0_1 HARDWARE_MODULE_API_VERSION(0, 1)
#define GRALLOC_MODULE_API_VERSION_0_2 HARDWARE_MODULE_API_VERSION(0, 2)
#define GRALLOC_MODULE_API_VERSION_0_3 HARDWARE_MODULE_API_VERSION(0, 3)
#define GRALLOC_DEVICE_API_VERSION_0_1 HARDWARE_DEVICE_API_VERSION(0, 1)

#define GRALLOC_HARDWARE_MODULE_ID "gralloc"
#define GRALLOC_HARDWARE_GPU0 "gpu0"
#define GRALLOC_HARDWARE_FB0 "fb0"

enum {
    GRALLOC_USAGE_SW_READ_NEVER = 0x00000000U,
    GRALLOC_USAGE_SW_READ_RARELY = 0x00000002U,
    GRALLOC_USAGE_SW_READ_OFTEN = 0x00000003U,
    GRALLOC_USAGE_SW_READ_MASK = 0x0000000FU,
    GRALLOC_USAGE_SW_WRITE_NEVER = 0x00000000U,
    GRALLOC_USAGE_SW_WRITE_RARELY = 0x00000020U,
    GRALLOC_USAGE_SW_WRITE_OFTEN = 0x00000030U,
    GRALLOC_USAGE_SW_WRITE_MASK = 0x000000F0U,
    GRALLOC_USAGE_HW_TEXTURE = 0x00000100U,
    GRALLOC_USAGE_HW_RENDER = 0x00000200U,
    GRALLOC_USAGE_HW_2D = 0x00000400U,
    GRALLOC_USAGE_HW_COMPOSER = 0x00000800U,
    GRALLOC_USAGE_HW_FB = 0x00001000U,
    GRALLOC_USAGE_EXTERNAL_DISP = 0x00002000U,
    GRALLOC_USAGE_PROTECTED = 0x00004000U,
    GRALLOC_USAGE_CURSOR = 0x00008000U,
    GRALLOC_USAGE_HW_VIDEO_ENCODER = 0x00010000U,
    GRALLOC_USAGE_HW_CAMERA_WRITE = 0x00020000U,
    GRALLOC_USAGE_HW_CAMERA_READ = 0x00040000U,
    GRALLOC_USAGE_HW_CAMERA_ZSL = 0x00060000U,
    GRALLOC_USAGE_HW_CAMERA_MASK = 0x00060000U,
    GRALLOC_USAGE_HW_MASK = 0x00071F00U,
    GRALLOC_USAGE_RENDERSCRIPT = 0x00100000U,
    GRALLOC_USAGE_FOREIGN_BUFFERS = 0x00200000U,
    GRALLOC_USAGE_HW_IMAGE_ENCODER = 0x08000000U,
    GRALLOC_USAGE_PRIVATE_0 = 0x10000000U,
    GRALLOC_USAGE_PRIVATE_1 = 0x20000000U,
    GRALLOC_USAGE_PRIVATE_2 = 0x40000000U,
    GRALLOC_USAGE_PRIVATE_3 = 0x80000000U,
    GRALLOC_USAGE_PRIVATE_MASK = 0xF0000000U,
};

typedef struct gralloc_module_t {
    struct hw_module_t common;
    int (*registerBuffer)(struct gralloc_module_t const* module, buffer_handle_t handle);
    int (*unregisterBuffer)(struct gralloc_module_t const* module, buffer_handle_t handle);
    int (*lock)(struct gralloc_module_t const* module, buffer_handle_t handle, int usage,
                int l, int t, int w, int h, void** vaddr);
    int (*unlock)(struct gralloc_module_t const* module, buffer_handle_t handle);
    int (*perform)(struct gralloc_module_t const* module, int operation, ...);
    int (*lock_ycbcr)(struct gralloc_module_t const* module, buffer_handle_t handle, int usage,
                      int l, int t, int w, int h, struct android_ycbcr* ycbcr);
    int (*lockAsync)(struct gralloc_module_t const* module, buffer_handle_t handle, int usage,
                     int l, int t, int w, int h, void** vaddr, int fenceFd);
    int (*unlockAsync)(struct gralloc_module_t const* module, buffer_handle_t handle,
                       int* fenceFd);
    int (*lockAsync_ycbcr)(struct gralloc_module_t const* module, buffer_handle_t handle,
                           int usage, int l, int t, int w, int h,
                           struct android_ycbcr* ycbcr, int fenceFd);
    int32_t (*getTransportSize)(struct gralloc_module_t const* module,
                                buffer_handle_t handle, uint32_t* outNumFds,
                                uint32_t* outNumInts);
    int32_t (*validateBufferSize)(struct gralloc_module_t const* module,
                                  buffer_handle_t handle, uint32_t w, uint32_t h,
                                  int32_t format, int usage, uint32_t stride);
    void* reserved_proc[1];
} gralloc_module_t;

typedef struct alloc_device_t {
    struct hw_device_t common;
    int (*alloc)(struct alloc_device_t* dev, int w, int h, int format, int usage,
                 buffer_handle_t* handle, int* stride);
    int (*free)(struct alloc_device_t* dev, buffer_handle_t handle);
    void (*dump)(struct alloc_device_t* dev, char* buff, int buff_len);
    void* reserved_proc[7];
} alloc_device_t;

typedef struct framebuffer_device_t {
    struct hw_device_t common;
    const uint32_t flags;
    const uint32_t width;
    const uint32_t height;
    const int stride;
    const int format;
    const float xdpi;
    const float ydpi;
    const float fps;
    const int minSwapInterval;
    const int maxSwapInterval;
    const int numFramebuffers;
    int reserved[7];
    int (*setSwapInterval)(struct framebuffer_device_t* window, int interval);
    int (*setUpdateRect)(struct framebuffer_device_t* window, int left, int top,
                         int width, int height);
    int (*post)(struct framebuffer_device_t* dev, buffer_handle_t buffer);
    int (*compositionComplete)(struct framebuffer_device_t* dev);
    void (*dump)(struct framebuffer_device_t* dev, char* buff, int buff_len);
    int (*enableScreen)(struct framebuffer_device_t* dev, int enable);
    void* reserved_proc[6];
} framebuffer_device_t;

#if defined(__cplusplus)
}

static_assert(sizeof(native_handle_t) == 3 * sizeof(int),
              "Android native_handle_t ABI changed");
#if defined(__LP64__)
static_assert(sizeof(hw_module_t) == 248, "Android 13 LP64 hw_module_t ABI changed");
static_assert(sizeof(hw_device_t) == 120, "Android 13 LP64 hw_device_t ABI changed");
static_assert(sizeof(gralloc_module_t) == 344,
              "Android 13 LP64 gralloc_module_t ABI changed");
static_assert(sizeof(alloc_device_t) == 200,
              "Android 13 LP64 alloc_device_t ABI changed");
static_assert(sizeof(framebuffer_device_t) == 288,
              "Android 13 LP64 framebuffer_device_t ABI changed");
#endif
#endif

#endif  // REDROID_GRALLOC_ANDROID_COMPAT_H_
