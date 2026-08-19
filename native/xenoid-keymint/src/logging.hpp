#pragma once

// Log macros for the KeyMint HAL service sources. Kept deliberately tiny; the
// tag matches the upstream TEESimulator project these sources derive from.

#include <android/log.h>
#include <errno.h>
#include <string.h>

#ifndef LOG_TAG
#define LOG_TAG "TEESimulator"
#endif

#ifdef LOG_DISABLED
#define LOGD(...) 0
#define LOGV(...) 0
#define LOGI(...) 0
#define LOGW(...) 0
#define LOGE(...) 0
#else
#ifndef NDEBUG
#define LOGD(fmt, ...)                                                                             \
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG,                                                \
                        "%s:%d#%s"                                                                 \
                        ": " fmt,                                                                  \
                        __FILE_NAME__, __LINE__, __PRETTY_FUNCTION__ __VA_OPT__(, ) __VA_ARGS__)
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#else
#define LOGD(...) 0
#define LOGV(...) 0
#endif
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL, LOG_TAG, __VA_ARGS__)
#define PLOGE(fmt, args...) LOGE(fmt " failed with %d: %s", ##args, errno, strerror(errno))
#endif
