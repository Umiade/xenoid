/*
 * Copyright (C) 2022 The Android Open Source Project
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

package android.hardware.camera.device;

/**
 * RequestTemplate:
 *
 * Available template types for
 * ICameraDevice::constructDefaultRequestSettings()
 */
@VintfStability
@Backing(type="int")
enum RequestTemplate {
    /**
     * Standard camera preview operation with 3A on auto.
     */
    PREVIEW = 1,

    /**
     * Standard camera high-quality still capture with 3A and flash on auto.
     */
    STILL_CAPTURE = 2,

    /**
     * Standard video recording plus preview with 3A on auto, torch off.
     */
    VIDEO_RECORD = 3,

    /**
     * High-quality still capture while recording video. Applications typically
     * include preview, video record, and full-resolution YUV or JPEG streams in
     * request. Must not cause stuttering on video stream. 3A on auto.
     */
    VIDEO_SNAPSHOT = 4,

    /**
     * Zero-shutter-lag mode. Application typically request preview and
     * full-resolution data for each frame, and reprocess it to JPEG when a
     * still image is requested by user. Settings must provide highest-quality
     * full-resolution images without compromising preview frame rate. 3A on
     * auto.
     */
    ZERO_SHUTTER_LAG = 5,

    /**
     * A basic template for direct application control of capture
     * parameters. All automatic control is disabled (auto-exposure, auto-white
     * balance, auto-focus), and post-processing parameters are set to preview
     * quality. The manual capture parameters (exposure, sensitivity, etc.)
     * are set to reasonable defaults, but may be overridden by the
     * application depending on the intended use case.
     */
    MANUAL = 6,

    /**
     * First value for vendor-defined request templates
     */
    VENDOR_TEMPLATE_START = 0x40000000,
}
