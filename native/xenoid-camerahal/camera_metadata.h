#pragma once

#include <aidl/android/hardware/camera/device/CameraMetadata.h>
#include <aidl/android/hardware/camera/device/RequestTemplate.h>

#include <string>

#include "camera_types.h"

namespace camera_provider {

using CameraMetadata = ::aidl::android::hardware::camera::device::CameraMetadata;
using RequestTemplate = ::aidl::android::hardware::camera::device::RequestTemplate;

bool buildStaticMetadata(const CameraProfile& profile, CameraMetadata* output,
                         std::string* error);
bool buildDefaultRequest(const CameraProfile& profile,
                         RequestTemplate requestTemplate, CameraMetadata* output,
                         std::string* error);
bool parseRequestSettings(const CameraProfile& profile,
                          const CameraMetadata& metadata,
                          const RequestSettings* previous,
                          RequestSettings* output, std::string* error);
bool buildResultMetadata(const CameraProfile& profile,
                         const RequestSettings& settings,
                         const FrameTiming& timing, CameraMetadata* output,
                         std::string* error);

}  // namespace camera_provider
