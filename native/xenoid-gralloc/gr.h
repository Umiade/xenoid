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

#ifndef REDROID_GRALLOC_GR_H_
#define REDROID_GRALLOC_GR_H_

/*
 * Ported from android-13.0.0_r1
 * hardware/libhardware/modules/gralloc/gr.h.
 */

#include <android/log.h>
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/user.h>
#include <unistd.h>

#include "android_compat.h"

#define GRALLOC_LOG_TAG "gralloc"
#define ALOGE(...) \
    __android_log_print(ANDROID_LOG_ERROR, GRALLOC_LOG_TAG, __VA_ARGS__)
#define ALOGW(...) \
    __android_log_print(ANDROID_LOG_WARN, GRALLOC_LOG_TAG, __VA_ARGS__)
#define ALOGI(...) \
    __android_log_print(ANDROID_LOG_INFO, GRALLOC_LOG_TAG, __VA_ARGS__)
#define ALOGD_IF(condition, ...) \
    do { \
        if (condition) { \
            __android_log_print(ANDROID_LOG_DEBUG, GRALLOC_LOG_TAG, __VA_ARGS__); \
        } \
    } while (0)
#define ALOGE_IF(condition, ...) \
    do { \
        if (condition) { \
            __android_log_print(ANDROID_LOG_ERROR, GRALLOC_LOG_TAG, __VA_ARGS__); \
        } \
    } while (0)

struct private_module_t;
struct private_handle_t;

inline size_t roundUpToPageSize(size_t value) {
    static const size_t pageSize = static_cast<size_t>(getpagesize());
    return (value + (pageSize - 1U)) & ~(pageSize - 1U);
}

inline size_t alignTo(size_t value, size_t alignment) {
    return ((value + alignment - 1U) / alignment) * alignment;
}

int mapFrameBufferLocked(struct private_module_t* module, int format);
int terminateBuffer(gralloc_module_t const* module, private_handle_t* handle);
int mapBuffer(gralloc_module_t const* module, private_handle_t* handle);

int gralloc_register_buffer(gralloc_module_t const* module, buffer_handle_t handle);
int gralloc_unregister_buffer(gralloc_module_t const* module, buffer_handle_t handle);
int gralloc_lock(gralloc_module_t const* module, buffer_handle_t handle, int usage,
                 int l, int t, int w, int h, void** vaddr);
int gralloc_unlock(gralloc_module_t const* module, buffer_handle_t handle);
int gralloc_lock_ycbcr(gralloc_module_t const* module, buffer_handle_t handle,
                       int usage, int l, int t, int w, int h,
                       struct android_ycbcr* ycbcr);
int gralloc_lock_async(gralloc_module_t const* module, buffer_handle_t handle,
                       int usage, int l, int t, int w, int h, void** vaddr,
                       int fenceFd);
int gralloc_unlock_async(gralloc_module_t const* module, buffer_handle_t handle,
                         int* fenceFd);
int gralloc_lock_async_ycbcr(gralloc_module_t const* module,
                             buffer_handle_t handle, int usage, int l, int t,
                             int w, int h, struct android_ycbcr* ycbcr,
                             int fenceFd);
int32_t gralloc_get_transport_size(gralloc_module_t const* module,
                                   buffer_handle_t handle, uint32_t* outNumFds,
                                   uint32_t* outNumInts);
int32_t gralloc_validate_buffer_size(gralloc_module_t const* module,
                                     buffer_handle_t handle, uint32_t width,
                                     uint32_t height, int32_t format, int usage,
                                     uint32_t stride);

#endif  // REDROID_GRALLOC_GR_H_
