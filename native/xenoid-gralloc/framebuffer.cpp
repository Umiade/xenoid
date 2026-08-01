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
 * hardware/libhardware/modules/gralloc/framebuffer.cpp.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <new>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "gr.h"
#include "gralloc_priv.h"

#ifndef USE_PAN_DISPLAY
#define USE_PAN_DISPLAY 0
#endif

#ifndef NUM_BUFFERS
#define NUM_BUFFERS 2
#endif

enum {
    PAGE_FLIP = 0x00000001,
};

struct fb_context_t {
    framebuffer_device_t device;
};

static int fb_set_swap_interval(struct framebuffer_device_t* device, int interval) {
    if (device == nullptr || interval < device->minSwapInterval ||
        interval > device->maxSwapInterval) {
        return -EINVAL;
    }
    return 0;
}

static int fb_post(struct framebuffer_device_t* device, buffer_handle_t buffer) {
    if (device == nullptr || private_handle_t::validate(buffer) < 0) {
        return -EINVAL;
    }

    const private_handle_t* handle =
            reinterpret_cast<const private_handle_t*>(buffer);
    private_module_t* module =
            reinterpret_cast<private_module_t*>(device->common.module);
    if (module->framebuffer == nullptr) {
        return -EINVAL;
    }

    if ((handle->flags & private_handle_t::PRIV_FLAGS_FRAMEBUFFER) != 0) {
        const size_t offset = handle->base - module->framebuffer->base;
        module->info.activate = FB_ACTIVATE_VBL;
        module->info.yoffset = offset / module->finfo.line_length;
        if (ioctl(module->framebuffer->fd, FBIOPUT_VSCREENINFO, &module->info) == -1) {
            const int error = errno;
            ALOGE("FBIOPUT_VSCREENINFO failed: %s", strerror(error));
            module->base.unlock(&module->base, buffer);
            return -error;
        }
        module->currentBuffer = buffer;
        return 0;
    }

    void* framebufferAddress = nullptr;
    void* bufferAddress = nullptr;
    int error = module->base.lock(
            &module->base, module->framebuffer, GRALLOC_USAGE_SW_WRITE_RARELY,
            0, 0, module->info.xres, module->info.yres, &framebufferAddress);
    if (error != 0) {
        return error;
    }
    error = module->base.lock(
            &module->base, buffer, GRALLOC_USAGE_SW_READ_RARELY,
            0, 0, module->info.xres, module->info.yres, &bufferAddress);
    if (error == 0) {
        memcpy(framebufferAddress, bufferAddress,
               module->finfo.line_length * module->info.yres);
        module->base.unlock(&module->base, buffer);
    }
    module->base.unlock(&module->base, module->framebuffer);
    return error;
}

int mapFrameBufferLocked(struct private_module_t* module, int format) {
    if (module == nullptr) {
        return -EINVAL;
    }
    if (module->framebuffer != nullptr) {
        return 0;
    }

    static const char* const deviceTemplates[] = {
            "/dev/graphics/fb%u",
            "/dev/fb%u",
            nullptr,
    };

    int fd = -1;
    char name[64];
    for (size_t index = 0; deviceTemplates[index] != nullptr && fd < 0; ++index) {
        snprintf(name, sizeof(name), deviceTemplates[index], 0U);
        fd = open(name, O_RDWR, 0);
    }
    if (fd < 0) {
        return -errno;
    }

    struct fb_fix_screeninfo fixedInfo;
    if (ioctl(fd, FBIOGET_FSCREENINFO, &fixedInfo) == -1) {
        const int error = errno;
        close(fd);
        return -error;
    }

    struct fb_var_screeninfo variableInfo;
    if (ioctl(fd, FBIOGET_VSCREENINFO, &variableInfo) == -1) {
        const int error = errno;
        close(fd);
        return -error;
    }

    variableInfo.reserved[0] = 0;
    variableInfo.reserved[1] = 0;
    variableInfo.reserved[2] = 0;
    variableInfo.xoffset = 0;
    variableInfo.yoffset = 0;
    variableInfo.activate = FB_ACTIVATE_NOW;
    variableInfo.yres_virtual = variableInfo.yres * NUM_BUFFERS;

    switch (format) {
        case HAL_PIXEL_FORMAT_RGBA_8888:
            variableInfo.bits_per_pixel = 32;
            variableInfo.red.offset = 0;
            variableInfo.red.length = 8;
            variableInfo.green.offset = 8;
            variableInfo.green.length = 8;
            variableInfo.blue.offset = 16;
            variableInfo.blue.length = 8;
            break;
        default:
            ALOGW("unknown framebuffer format: %d", format);
            break;
    }

    uint32_t flags = PAGE_FLIP;
#if USE_PAN_DISPLAY
    if (ioctl(fd, FBIOPAN_DISPLAY, &variableInfo) == -1) {
        ALOGW("FBIOPAN_DISPLAY failed, page flipping not supported");
#else
    if (ioctl(fd, FBIOPUT_VSCREENINFO, &variableInfo) == -1) {
        ALOGW("FBIOPUT_VSCREENINFO failed, page flipping not supported");
#endif
        variableInfo.yres_virtual = variableInfo.yres;
        flags &= ~PAGE_FLIP;
    }

    if (variableInfo.yres_virtual < variableInfo.yres * 2U) {
        variableInfo.yres_virtual = variableInfo.yres;
        flags &= ~PAGE_FLIP;
        ALOGW("page flipping not supported (yres_virtual=%u, requested=%u)",
              variableInfo.yres_virtual, variableInfo.yres * 2U);
    }

    if (ioctl(fd, FBIOGET_VSCREENINFO, &variableInfo) == -1) {
        const int error = errno;
        close(fd);
        return -error;
    }

    const uint64_t refreshQuotient =
            static_cast<uint64_t>(variableInfo.upper_margin + variableInfo.lower_margin +
                                  variableInfo.yres) *
            (variableInfo.left_margin + variableInfo.right_margin + variableInfo.xres) *
            variableInfo.pixclock;
    int refreshRate = refreshQuotient > 0
            ? static_cast<int>(UINT64_C(1000000000000000) / refreshQuotient)
            : 0;
    if (refreshRate == 0) {
        refreshRate = 60 * 1000;
    }

    if (static_cast<int>(variableInfo.width) <= 0 ||
        static_cast<int>(variableInfo.height) <= 0) {
        variableInfo.width = static_cast<uint32_t>(
                (variableInfo.xres * 25.4f) / 160.0f + 0.5f);
        variableInfo.height = static_cast<uint32_t>(
                (variableInfo.yres * 25.4f) / 160.0f + 0.5f);
    }

    const float xdpi = (variableInfo.xres * 25.4f) / variableInfo.width;
    const float ydpi = (variableInfo.yres * 25.4f) / variableInfo.height;
    const float fps = refreshRate / 1000.0f;

    ALOGI("using framebuffer fd=%d, id=%s, %ux%u, virtual=%ux%u, bpp=%u",
          fd, fixedInfo.id, variableInfo.xres, variableInfo.yres,
          variableInfo.xres_virtual, variableInfo.yres_virtual,
          variableInfo.bits_per_pixel);
    ALOGI("framebuffer dimensions=%ux%u mm, dpi=%f,%f, refresh=%.2f Hz",
          variableInfo.width, variableInfo.height, xdpi, ydpi, fps);

    if (ioctl(fd, FBIOGET_FSCREENINFO, &fixedInfo) == -1) {
        const int error = errno;
        close(fd);
        return -error;
    }
    if (fixedInfo.smem_len == 0) {
        close(fd);
        return -EINVAL;
    }

    const size_t framebufferSize = roundUpToPageSize(
            static_cast<size_t>(fixedInfo.line_length) * variableInfo.yres_virtual);
    if (framebufferSize == 0 || framebufferSize > INT_MAX) {
        close(fd);
        return -EOVERFLOW;
    }

    const int handleFd = dup(fd);
    if (handleFd < 0) {
        const int error = errno;
        close(fd);
        return -error;
    }
    private_handle_t* framebuffer = new (std::nothrow) private_handle_t(
            handleFd, static_cast<int>(framebufferSize), 0);
    if (framebuffer == nullptr) {
        close(handleFd);
        close(fd);
        return -ENOMEM;
    }

    void* address = mmap(nullptr, framebufferSize, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, 0);
    const int mapError = errno;
    close(fd);
    if (address == MAP_FAILED) {
        ALOGE("Error mapping the framebuffer: %s", strerror(mapError));
        close(handleFd);
        delete framebuffer;
        return -mapError;
    }

    framebuffer->base = reinterpret_cast<intptr_t>(address);
    memset(address, 0, framebufferSize);

    module->flags = flags;
    module->info = variableInfo;
    module->finfo = fixedInfo;
    module->xdpi = xdpi;
    module->ydpi = ydpi;
    module->fps = fps;
    module->framebuffer = framebuffer;
    module->numBuffers = variableInfo.yres_virtual / variableInfo.yres;
    module->bufferMask = 0;
    return 0;
}

static int map_framebuffer(struct private_module_t* module) {
    pthread_mutex_lock(&module->lock);
    const int error = mapFrameBufferLocked(module, HAL_PIXEL_FORMAT_RGBA_8888);
    pthread_mutex_unlock(&module->lock);
    return error;
}

static int fb_close(struct hw_device_t* device) {
    free(reinterpret_cast<fb_context_t*>(device));
    return 0;
}

int fb_device_open(hw_module_t const* module, const char* name,
                   hw_device_t** device) {
    if (module == nullptr || name == nullptr || device == nullptr ||
        strcmp(name, GRALLOC_HARDWARE_FB0) != 0) {
        return -EINVAL;
    }

    fb_context_t* context = static_cast<fb_context_t*>(calloc(1, sizeof(*context)));
    if (context == nullptr) {
        return -ENOMEM;
    }

    context->device.common.tag = HARDWARE_DEVICE_TAG;
    context->device.common.version = 0;
    context->device.common.module = const_cast<hw_module_t*>(module);
    context->device.common.close = fb_close;
    context->device.setSwapInterval = fb_set_swap_interval;
    context->device.post = fb_post;
    context->device.setUpdateRect = nullptr;

    private_module_t* privateModule =
            reinterpret_cast<private_module_t*>(const_cast<hw_module_t*>(module));
    const int status = map_framebuffer(privateModule);
    if (status < 0) {
        free(context);
        return status;
    }

    const int bytesPerPixel = privateModule->info.bits_per_pixel >> 3;
    if (bytesPerPixel == 0) {
        free(context);
        return -EINVAL;
    }
    const int stride = privateModule->finfo.line_length / bytesPerPixel;
    const int format = privateModule->info.bits_per_pixel == 32
            ? (privateModule->info.red.offset != 0 ? HAL_PIXEL_FORMAT_BGRA_8888
                                                   : HAL_PIXEL_FORMAT_RGBX_8888)
            : HAL_PIXEL_FORMAT_RGB_565;

    const_cast<uint32_t&>(context->device.flags) = 0;
    const_cast<uint32_t&>(context->device.width) = privateModule->info.xres;
    const_cast<uint32_t&>(context->device.height) = privateModule->info.yres;
    const_cast<int&>(context->device.stride) = stride;
    const_cast<int&>(context->device.format) = format;
    const_cast<float&>(context->device.xdpi) = privateModule->xdpi;
    const_cast<float&>(context->device.ydpi) = privateModule->ydpi;
    const_cast<float&>(context->device.fps) = privateModule->fps;
    const_cast<int&>(context->device.minSwapInterval) = 1;
    const_cast<int&>(context->device.maxSwapInterval) = 1;

    *device = &context->device.common;
    return 0;
}
