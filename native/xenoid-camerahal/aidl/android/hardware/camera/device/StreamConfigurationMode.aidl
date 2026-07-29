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
 * StreamConfigurationMode:
 *
 * This defines the general operation mode for the HAL (for a given stream
 * configuration) where modes besides NORMAL have different semantics, and
 * usually limit the generality of the API in exchange for higher performance in
 * some particular area.
 */
@VintfStability
@Backing(type="int")
enum StreamConfigurationMode {
    /**
     * Normal stream configuration operation mode. This is the default camera
     * operation mode, where all semantics of HAL APIs and metadata controls
     * apply.
     */
    NORMAL_MODE = 0,

    /**
     * Special constrained high speed operation mode for devices that can not
     * support high speed output in NORMAL mode. All streams in this
     * configuration are operating at high speed mode and have different
     * characteristics and limitations to achieve high speed output. The NORMAL
     * mode can still be used for high speed output if the HAL can support high
     * speed output while satisfying all the semantics of HAL APIs and metadata
     * controls. It is recommended for the HAL to support high speed output in
     * NORMAL mode (by advertising the high speed FPS ranges in
     * android.control.aeAvailableTargetFpsRanges) if possible.
     *
     * This mode has below limitations/requirements:
     *
     *   1. The HAL must support up to 2 streams with sizes reported by
     *      android.control.availableHighSpeedVideoConfigurations.
     *   2. In this mode, the HAL is expected to output up to 120fps or
     *      higher. This mode must support the targeted FPS range and size
     *      configurations reported by
     *      android.control.availableHighSpeedVideoConfigurations.
     *   3. The HAL must support IMPLEMENTATION_DEFINED output
     *      stream format.
     *   4. To achieve efficient high speed streaming, the HAL may have to
     *      aggregate multiple frames together and send to camera device for
     *      processing where the request controls are same for all the frames in
     *      this batch (batch mode). The HAL must support max batch size and the
     *      max batch size requirements defined by
     *      android.control.availableHighSpeedVideoConfigurations.
     *   5. In this mode, the HAL must override aeMode, awbMode, and afMode to
     *      ON, ON, and CONTINUOUS_VIDEO, respectively. All post-processing
     *      block mode controls must be overridden to be FAST. Therefore, no
     *      manual control of capture and post-processing parameters is
     *      possible. All other controls operate the same as when
     *      android.control.mode == AUTO. This means that all other
     *      android.control.* fields must continue to work, such as
     *
     *      android.control.aeTargetFpsRange
     *      android.control.aeExposureCompensation
     *      android.control.aeLock
     *      android.control.awbLock
     *      android.control.effectMode
     *      android.control.aeRegions
     *      android.control.afRegions
     *      android.control.awbRegions
     *      android.control.afTrigger
     *      android.control.aePrecaptureTrigger
     *
     *      Outside of android.control.*, the following controls must work:
     *
     *      android.flash.mode (TORCH mode only, automatic flash for still
     *          capture must not work since aeMode is ON)
     *      android.lens.opticalStabilizationMode (if it is supported)
     *      android.scaler.cropRegion
     *      android.statistics.faceDetectMode (if it is supported)
     *   6. To reduce the amount of data passed across process boundaries at
     *      high frame rate, within one batch, camera framework only propagates
     *      the last shutter notify and the last capture results (including partial
     *      results and final result) to the app. The shutter notifies and capture
     *      results for the other requests in the batch are derived by
     *      the camera framework. As a result, the HAL can return empty metadata
     *      except for the last result in the batch.
     *
     * For more details about high speed stream requirements, see
     * android.control.availableHighSpeedVideoConfigurations and
     * CONSTRAINED_HIGH_SPEED_VIDEO capability defined in
     * android.request.availableCapabilities.
     *
     * This mode only needs to be supported by HALs that include
     * CONSTRAINED_HIGH_SPEED_VIDEO in the android.request.availableCapabilities
     * static metadata.
     */
    CONSTRAINED_HIGH_SPEED_MODE = 1,

    /**
     * A set of vendor-defined operating modes, for custom default camera
     * application features that can't be implemented in the fully flexible fashion
     * required for NORMAL_MODE.
     */
    VENDOR_MODE_0 = 0x8000,
    VENDOR_MODE_1,
    VENDOR_MODE_2,
    VENDOR_MODE_3,
    VENDOR_MODE_4,
    VENDOR_MODE_5,
    VENDOR_MODE_6,
    VENDOR_MODE_7,
}
