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

import android.hardware.camera.common.CameraResourceCost;
import android.hardware.camera.device.CameraMetadata;
import android.hardware.camera.device.ICameraDeviceCallback;
import android.hardware.camera.device.ICameraDeviceSession;
import android.hardware.camera.device.ICameraInjectionSession;
import android.hardware.camera.device.StreamConfiguration;
import android.os.ParcelFileDescriptor;

/**
 * Camera device interface
 *
 * Supports the android.hardware.Camera API, and the android.hardware.camera2
 * API at LIMITED or better hardware level.
 *
 */
@VintfStability
interface ICameraDevice {
    /**
     * getCameraCharacteristics:
     *
     * Return the static camera information for this camera device. This
     * information may not change between consecutive calls.
     *
     * When an external camera is disconnected, its camera id becomes
     * invalid. Calling this method with this invalid camera id must result in an
     * ILLEGAL_ARGUMENT ServiceSpecificException on returning; this may happen even before the
     * device status callback is invoked by the HAL.
     *
     * A service specific error will be returned on the following conditions
     *     INTERNAL_ERROR:
     *         The camera device cannot be opened due to an internal
     *         error.
     *     CAMERA_DISCONNECTED:
     *         An external camera device has been disconnected, and is no longer
     *         available. This camera device interface is now stale, and a new
     *         instance must be acquired if the device is reconnected. All
     *         subsequent calls on this interface must return
     *         CAMERA_DISCONNECTED.
     *
     * @return The static metadata for this camera device, or an empty metadata
     *     structure if status is not OK.
     *
     */
    CameraMetadata getCameraCharacteristics();

    /**
     * getPhysicalCameraCharacteristics:
     *
     * Return the static camera information for a physical camera ID backing
     * this logical camera device. This information may not change between consecutive calls.
     *
     * The characteristics of all cameras returned by
     * ICameraProvider::getCameraIdList() must be queried via
     * getCameraCharacteristics(). Calling getPhysicalCameraCharacteristics() on
     * those cameras must return ILLEGAL_ARGUMENT ServiceSpecificException.
     *
     * @param physicalCameraId The physical camera id parsed from the logical
     *     camera's ANDROID_LOGICAL_MULTI_CAMERA_PHYSICAL_IDS static metadata
     *     key. The framework assumes that this ID is just the <id> part of fully
     *     qualified camera device name "device@<major>.<minor>/<type>/<id>". And
     *     the physical camera must be of the same version and type as the parent
     *     logical camera device.
     *
     * A service specific error will be returned on the following conditions
     *     INTERNAL_ERROR:
     *         The camera device cannot be opened due to an internal
     *         error.
     *     CAMERA_DISCONNECTED:
     *         An external camera device has been disconnected, and is no longer
     *         available. This camera device interface is now stale, and a new
     *         instance must be acquired if the device is reconnected. All
     *         subsequent calls on this interface must return
     *         CAMERA_DISCONNECTED.
     *     ILLEGAL_ARGUMENT:
     *         If the physicalCameraId is not a valid physical camera Id outside
     *         of ICameraProvider::getCameraIdList().
     *
     * @return The static metadata for this logical camera device's physical device, or an empty
     *     metadata structure if a service specific error is returned.
     *
     */
    CameraMetadata getPhysicalCameraCharacteristics(in String physicalCameraId);

    /**
     * Get camera device resource cost information.
     *
     * A service specific error will be returned on the following conditions
     *     INTERNAL_ERROR:
     *         An unexpected internal camera HAL error occurred, and the
     *         resource cost is not available.
     *     CAMERA_DISCONNECTED:
     *         An external camera device has been disconnected, and is no longer
     *         available. This camera device interface is now stale, and a new
     *         instance must be acquired if the device is reconnected. All
     *         subsequent calls on this interface must return
     *         CAMERA_DISCONNECTED.
     * @return resourceCost
     *     The resources required to open this camera device, or unspecified
     *     values if status is not OK.
     */
    CameraResourceCost getResourceCost();

    /**
     * isStreamCombinationSupported:
     *
     * Check for device support of specific camera stream combination.
     *
     * The streamList must contain at least one output-capable stream, and may
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
     * after active session configuration. This means that calls must not
     * impact the performance of pending camera requests in any way. In
     * particular there must not be any glitches or delays during normal
     * camera streaming.
     *
     * Performance requirements:
     * This call is expected to be significantly faster than stream
     * configuration. In general HW and SW camera settings must not be
     * changed and there must not be a user-visible impact on camera performance.
     *
     *
     * A service specific error will be returned on the following conditions
     *
     *     INTERNAL_ERROR:
     *          The stream combination query cannot complete due to internal
     *          error.
     * @param streams The StreamConfiguration to be tested for support.
     * @return true in case the stream combination is supported, false otherwise.
     *
     */
    boolean isStreamCombinationSupported(in StreamConfiguration streams);

    /**
     * open:
     *
     * Power on and initialize this camera device for active use, returning a
     * session handle for active operations.
     *
     * @param callback Interface to invoke by the HAL for device asynchronous
     *     events.
     *
     * A service specific error will be returned on the following conditions
     *     INTERNAL_ERROR:
     *         The camera device cannot be opened due to an internal
     *         error.
     *     ILLEGAL_ARGUMENT:
     *         The callbacks handle is invalid (for example, it is null).
     *     CAMERA_IN_USE:
     *         This camera device is already open.
     *     MAX_CAMERAS_IN_USE:
     *         The maximal number of camera devices that can be
     *         opened concurrently were opened already.
     *     CAMERA_DISCONNECTED:
     *         This external camera device has been disconnected, and is no
     *         longer available. This interface is now stale, and a new instance
     *         must be acquired if the device is reconnected. All subsequent
     *         calls on this interface must return CAMERA_DISCONNECTED.
     * @return The interface to the newly-opened camera session,
     *     or null if status is not OK.
     */
    ICameraDeviceSession open(in ICameraDeviceCallback callback);

    /**
     * openInjection:
     *
     * Similar to open, except that this return an ICameraInjectionSession instead.
     * Details about ICameraInjectionSession can be found in ICameraInjectionSession.aidl
     *
     * @param callback Interface to invoke by the HAL for device asynchronous
     *     events.
     *
     * A service specific error will be returned on the following conditions
     *     INTERNAL_ERROR:
     *         The camera device cannot be opened due to an internal
     *         error.
     *     OPERATION_NOT_SUPPORTED:
     *         This camera device does not support opening an injection session.
     *     ILLEGAL_ARGUMENT:
     *         The callbacks handle is invalid (for example, it is null).
     *     CAMERA_IN_USE:
     *         This camera device is already open.
     *     MAX_CAMERAS_IN_USE:
     *         The maximal number of camera devices that can be
     *         opened concurrently were opened already.
     *     CAMERA_DISCONNECTED:
     *         This external camera device has been disconnected, and is no
     *         longer available. This interface is now stale, and a new instance
     *         must be acquired if the device is reconnected. All subsequent
     *         calls on this interface must return CAMERA_DISCONNECTED.
     * @return The interface to the newly-opened camera session, or null if status is not OK.
     */
    ICameraInjectionSession openInjectionSession(in ICameraDeviceCallback callback);

    /**
     * setTorchMode:
     *
     * Turn on or off the torch mode of the flash unit associated with this
     * camera device. If the operation is successful, HAL must notify the
     * framework torch state by invoking
     * ICameraProviderCallback::torchModeStatusChange() with the new state.
     *
     * An active camera session has a higher priority accessing the flash
     * unit. When there are any resource conflicts, such as when open() is
     * called to fully activate a camera device, the provider must notify the
     * framework through ICameraProviderCallback::torchModeStatusChange() that
     * the torch mode has been turned off and the torch mode state has become
     * TORCH_MODE_STATUS_NOT_AVAILABLE. When resources to turn on torch mode
     * become available again, the provider must notify the framework through
     * ICameraProviderCallback::torchModeStatusChange() that the torch mode
     * state has become TORCH_MODE_STATUS_AVAILABLE_OFF for set_torch_mode() to
     * be called.
     *
     * When the client calls setTorchMode() to turn on the torch mode of a flash
     * unit, if the HAL cannot keep multiple torch modes on simultaneously, the
     * HAL must turn off the torch mode(s) that were turned on by previous
     * setTorchMode() calls and notify the framework that the torch mode state
     * of those flash unit(s) has become TORCH_MODE_STATUS_AVAILABLE_OFF.
     *
     * @param on Whether to turn the turn mode ON - specified by true or OFF, specified by false
     *
     * A service specific error will be returned on the following conditions
     *
     *     INTERNAL_ERROR:
     *         The flash unit cannot be operated due to an unexpected internal
     *         error.
     *     ILLEGAL_ARGUMENT:
     *         The camera ID is unknown.
     *     CAMERA_IN_USE:
     *         This camera device has been opened, so the torch cannot be
     *         controlled until it is closed.
     *     MAX_CAMERAS_IN_USE:
     *         Due to other camera devices being open, or due to other
     *         resource constraints, the torch cannot be controlled currently.
     *     OPERATION_NOT_SUPPORTED:
     *         This camera device does not have a flash unit. This can
     *         be returned if and only if android.flash.info.available is
     *         false.
     *     CAMERA_DISCONNECTED:
     *         An external camera device has been disconnected, and is no longer
     *         available. This camera device interface is now stale, and a new
     *         instance must be acquired if the device is reconnected. All
     *         subsequent calls on this interface must return
     *         CAMERA_DISCONNECTED.
     *
     */
    void setTorchMode(boolean on);

    /**
     * turnOnTorchWithStrengthLevel:
     *
     * Change the brightness level of the flash unit associated with this camera device
     * and set it to value in torchStrength. This function also turns ON the torch
     * with specified torchStrength if the torch is OFF.
     *
     * The torchStrength value must be within the valid range i.e. >=1 and
     * <= FLASH_INFO_STRENGTH_MAXIMUM_LEVEL. Whenever the torch is turned OFF,
     * the brightness level will reset to FLASH_INFO_STRENGTH_DEFAULT_LEVEL.
     * When the client calls setTorchMode(ON) after turnOnTorchWithStrengthLevel(N),
     * the flash unit will have brightness level equal to N. This level does not
     * represent the real brightness units. It is linear in nature i.e. flashlight
     * at level 10 is twice as bright as at level 5.
     *
     * @param torchStrength Brightness level to be set for the flashlight.
     *
     * A service specific error will be returned on the following conditions
     *     INTERNAL_ERROR:
     *         The flash unit cannot be operated due to an unexpected internal
     *         error.
     *     CAMERA_IN_USE:
     *         This status code is returned when:
     *           - This camera device has been opened, so the torch cannot be
     *             controlled until it is closed.
     *           - Due to other camera devices being open, or due to other
     *             resource constraints, the torch cannot be controlled currently.
     *     ILLEGAL_ARGUMENT:
     *         If the torchStrength value is not within the range i.e. < 1 or
     *         > FLASH_INFO_STRENGTH_MAXIMUM_LEVEL.
     *     OPERATION_NOT_SUPPORTED:
     *         This status code is returned when:
     *           - This camera device does not support direct operation of flashlight
     *             torch mode. The framework must open the camera device and turn
     *             the torch on through the device interface.
     *           - This camera device does not have a flash unit.
     *           - This camera device has flash unit but does not support torch
     *             strength control.
     *     CAMERA_DISCONNECTED:
     *         An external camera device has been disconnected, and is no longer
     *         available. This camera device interface is now stale, and a new
     *         instance must be acquired if the device is reconnected. All
     *         subsequent calls on this interface must return
     *         CAMERA_DISCONNECTED.
     *
     */
    void turnOnTorchWithStrengthLevel(int torchStrength);

    /**
     * getTorchStrengthLevel:
     *
     * Get current torch strength level.
     * If the device supports torch strength control, when the torch is OFF the
     * strength level will reset to default level, so the return
     * value in this case will be equal to FLASH_INFO_STRENGTH_DEFAULT_LEVEL.
     *
     * A service specific error will be returned on the following conditions
     *      INTERNAL_ERROR:
     *           An unexpected error occurred and the information is not
     *           available.
     *      OPERATION_NOT_SUPPORTED:
     *          This status code is returned when:
     *            - This camera device does not support direct operation of flashlight
     *              torch mode. The framework must open the camera device and turn
     *              the torch on through the device interface.
     *            - This camera device does not have a flash unit.
     *            - This camera device has flash unit but does not support torch
     *              strength control.
     *
     * @return torchStrength Current torch strength level.
     *
     */
    int getTorchStrengthLevel();
}
