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

package android.hardware.camera.provider;

import android.hardware.camera.common.VendorTagSection;
import android.hardware.camera.device.ICameraDevice;
import android.hardware.camera.provider.CameraIdAndStreamCombination;
import android.hardware.camera.provider.ConcurrentCameraIdCombination;
import android.hardware.camera.provider.ICameraProviderCallback;

/**
 * Camera provider HAL, which enumerates the available individual camera devices
 * known to the provider, and provides updates about changes to device status,
 * such as connection, disconnection, or torch mode enable/disable.
 *
 * The provider is responsible for generating a list of camera device service
 * names that can then be opened via the hardware service manager.
 *
 * Multiple camera provider HALs may be present in a single system.
 * For discovery, the service names, and process names, must be of the form
 * "android.hardware.camera.provider.ICameraProvider/<type>/<instance>"
 * where
 *   - <type> is the type of devices this provider knows about, such as
 *     "internal", "external", "remote" etc. The camera framework
 *     must not differentiate or chage its behavior based on the specific type.
 *   - <instance> is a non-negative integer starting from 0 to disambiguate
 *     between multiple HALs of the same type.
 *
 * The device instance names enumerated by the provider in getCameraIdList() or
 * ICameraProviderCallback::cameraDeviceStatusChange() must be of the form
 * "device@<major>.<minor>/<type>/<id>" where
 * <major>/<minor> is the AIDL version of the interface. Major version is the version baked into the
 * name of the device interface. Minor version is the version that would be returned by calling
 * getInterfaceVersion on the interface binder returned getCameraDeviceInterface.
 * <id> is either a small incrementing integer for "internal" device types, with 0 being the main
 * back-facing camera and 1 being the main front-facing camera, if they exist.
 * Or, for external devices, a unique serial number (if possible) that can be
 * used to identify the device reliably when it is disconnected and reconnected.
 *
 * Multiple providers must not enumerate the same device ID.
 */

@VintfStability
interface ICameraProvider {
    /**
     * Device states to be passed to notifyDeviceStateChange().
     */
    const long DEVICE_STATE_NORMAL = 0;
    const long DEVICE_STATE_BACK_COVERED = 1 << 0;
    const long DEVICE_STATE_FRONT_COVERED = 1 << 1;
    const long DEVICE_STATE_FOLDED = 1 << 2;

    /**
     * setCallback:
     *
     * Provide a callback interface to the HAL provider to inform framework of
     * asynchronous camera events. The framework must call this function once
     * during camera service startup, before any other calls to the provider
     * (note that in case the camera service restarts, this method must be
     * invoked again during its startup).
     *
     * @param callback
     *     A non-null callback interface to invoke when camera events occur.
     * A service specific error will be returned on the following conditions
     *     INTERNAL_ERROR:
     *         An unexpected internal error occurred while setting the callbacks
     *     ILLEGAL_ARGUMENT:
     *         The callback argument is invalid (for example, null).
     *
     */
    void setCallback(ICameraProviderCallback callback);

    /**
     * getVendorTags:
     *
     * Retrieve all vendor tags supported by devices discoverable through this
     * provider. The tags are grouped into sections.
     *
     * A service specific error will be returned on the following conditions
     *     INTERNAL_ERROR:
     *         An unexpected internal error occurred while setting the callbacks
     * @return
     *     The supported vendor tag sections; empty if there are no supported
     *     vendor tags.
     *
     */
    VendorTagSection[] getVendorTags();

    /**
     * getCameraIdList:
     *
     * Returns the list of internal camera device interfaces known to this
     * camera provider. These devices can then be accessed via the service manager.
     *
     * External camera devices (camera facing EXTERNAL) must be reported through
     * the device status change callback, not in this list. Only devices with
     * facing BACK or FRONT must be listed here.
     *
     * A service specific error will be returned on the following conditions
     *     INTERNAL_ERROR:
     *         A camera ID list cannot be created. This may be due to
     *         a failure to initialize the camera subsystem, for example.
     * @return The list of internal camera device names known to this provider.
     */
    String[] getCameraIdList();

    /**
     * getCameraDeviceInterface:
     *
     * Return a android.hardware.camera.device/ICameraDevice interface for
     * the requested device name. This does not power on the camera device, but
     * simply acquires the interface for querying the device static information,
     * or to additionally open the device for active use.
     *
     * Valid device names for this provider can be obtained via either
     * getCameraIdList(), or via availability callbacks from
     * ICameraProviderCallback::cameraDeviceStatusChange().
     *
     * @param cameraDeviceName the name of the device to get an interface to.
     *
     * A service specific error will be returned on the following conditions
     *     ILLEGAL_ARGUMENT:
     *         This device name is unknown, or has been disconnected
     *     OPERATION_NOT_SUPPORTED:
     *         The specified device does not support this major version of the
     *         HAL interface.
     *     INTERNAL_ERROR:
     *         A camera interface cannot be returned due to an unexpected
     *         internal error.
     * @return device The interface to this camera device, or null in case of
     *     error.
     */
    ICameraDevice getCameraDeviceInterface(String cameraDeviceName);

    /**
     * notifyDeviceStateChange:
     *
     * Notify the HAL provider that the state of the overall device has
     * changed in some way that the HAL may want to know about.
     *
     * For example, a physical shutter may have been uncovered or covered,
     * or a camera may have been covered or uncovered by an add-on keyboard
     * or other accessory.
     *
     * The state is a bitfield of potential states, and some physical configurations
     * could plausibly correspond to multiple different combinations of state bits.
     * The HAL must ignore any state bits it is not actively using to determine
     * the appropriate camera configuration.
     *
     * For example, on some devices the FOLDED state could mean that
     * backward-facing cameras are covered by the fold, so FOLDED by itself implies
     * BACK_COVERED. But other devices may support folding but not cover any cameras
     * when folded, so for those FOLDED would not imply any of the other flags.
     * Since these relationships are very device-specific, it is difficult to specify
     * a comprehensive policy.  But as a recommendation, it is suggested that if a flag
     * necessarily implies other flags are set as well, then those flags should be set.
     * So even though FOLDED would be enough to infer BACK_COVERED on some devices, the
     * BACK_COVERED flag should also be set for clarity.
     *
     * This method may be invoked by the HAL client at any time. It must not
     * cause any active camera device sessions to be closed, but may dynamically
     * change which physical camera a logical multi-camera is using for its
     * active and future output.
     *
     * The method must be invoked by the HAL client at least once before the
     * client calls ICameraDevice::open on any camera device interfaces listed
     * by this provider, to establish the initial device state.
     *
     * @param newState
     *    The new state of the device.
     */
    void notifyDeviceStateChange(long deviceState);

    /**
     * getConcurrentStreamingCameraIds
     *
     * Get a vector of combinations of camera device ids that are able to
     * configure streams concurrently. Each camera device advertised in a
     * combination MUST at the very least support the following streams while
     * streaming concurrently with the other camera ids in the combination.
     *
     *       Target 1                  Target 2
     * -----------------------------------------------------
     * | Type         |   Size   |   Type       |   Size   |
     * -----------------------------------------------------
     * | YUV          |  s1440p  |                         |
     * -----------------------------------------------------
     * | JPEG         |  s1440p  |                         |
     * -----------------------------------------------------
     * | PRIV         |  s1440p  |                         |
     * -----------------------------------------------------
     * | YUV / PRIV   |  s720p   |  YUV / PRIV   | s1440p  |
     * -----------------------------------------------------
     * | YUV / PRIV   |  s720p   |  JPEG         | s1440p  |
     * -----------------------------------------------------
     *
     * where:
     * s720p - min (max output resolution for the given format, 1280 X 720)
     * s1440p - min (max output resolution for the given format, 1920 X 1440)
     *
     * If a device has MONOCHROME capability (device's capabilities include
     * ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MONOCHROME) and therefore supports Y8
     * outputs, stream combinations mentioned above, where YUV is substituted by
     * Y8 must be also supported.
     *
     * Devices whose capabilities do not include
     * ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE, must support
     * at least a single Y16 stream, Dataspace::DEPTH with sVGA resolution,
     * during concurrent operation.
     * Where sVGA -  min (max output resolution for the given format, 640 X 480)
     *
     * The camera framework must call this method whenever it gets a
     * cameraDeviceStatusChange callback adding a new camera device or removing
     * a camera device known to it. This is so that the camera framework can get new combinations
     * of camera ids that can stream concurrently, that might have potentially appeared.
     *
     * For each combination (and their subsets) of camera device ids returned by
     * getConcurrentStreamingCameraIds(): If only the mandatory combinations can
     * be supported concurrently by each device, then the resource costs must
     * sum up to > 100 for the concurrent set, to ensure arbitration between
     * camera applications work as expected. Only if resources are sufficient
     * to run a set of cameras at full capability (maximally
     * resource-consuming framerate and stream size settings available in the
     * configuration settings exposed through camera metadata), should the sum
     * of resource costs for the combination be <= 100.
     *
     * For guaranteed concurrent camera operation, the camera framework must call
     * ICameraDevice.open() on all devices (intended for concurrent operation), before configuring
     * any streams on them. This gives the camera HAL process an opportunity to potentially
     * distribute hardware resources better before stream configuration.
     *
     * Due to potential hardware constraints around internal switching of physical camera devices,
     * a device's complete ZOOM_RATIO_RANGE(if supported), may not apply during concurrent
     * operation. If ZOOM_RATIO is supported, camera HALs must ensure ZOOM_RATIO_RANGE of
     * [1.0, ANDROID_SCALER_AVAILABLE_MAX_DIGITAL_ZOOM] is supported by that device, during
     * concurrent operation.
     *
     * A service specific error will be returned in the following case :
     *
     * INTERNAL_ERROR: the hal has encountered an internal error
     *
     * @return a list of camera id combinations that support
     *         concurrent stream configurations with the minimum guarantees
     *         specified.
     */
    ConcurrentCameraIdCombination[] getConcurrentCameraIds();

    /**
     * isConcurrentStreamCombinationSupported:
     *
     * Check for device support of specific camera stream combinations while
     * streaming concurrently with other devices.
     *
     * The per device streamList must contain at least one output-capable stream, and may
     * not contain more than one input-capable stream.
     * In contrast to regular stream configuration the framework does not create
     * or initialize any actual streams. This means that Hal must not use or
     * consider the stream "id" value.
     *
     * ------------------------------------------------------------------------
     *
     * Preconditions:
     *
     * The framework can call this method at any time before, during and
     * after active session configuration per device. This means that calls must not
     * impact the performance of pending camera requests in any way. In
     * particular there must not be any glitches or delays during normal
     * camera streaming.
     *
     * The framework must not call this method with any combination of camera
     * ids that is not a subset of the camera ids advertised by getConcurrentStreamingCameraIds of
     * the same provider.
     *
     * Performance requirements:
     * This call is expected to be significantly faster than stream
     * configuration. In general HW and SW camera settings must not be
     * changed and there must not be a user-visible impact on camera performance.
     *
     * @param configs a vector of camera ids and their corresponding stream
     *                configurations that need to be queried for support.
     *
     * On error, the service specific error for the operation will be, one of:
     *     OPERATION_NOT_SUPPORTED:
     *          The camera provider does not support stream combination query.
     *     INTERNAL_ERROR:
     *          The stream combination query cannot complete due to internal
     *          error.
     * @return true in case the stream combination is supported, false otherwise.
     *
     *
     */
    boolean isConcurrentStreamCombinationSupported(in CameraIdAndStreamCombination[] configs);
}
