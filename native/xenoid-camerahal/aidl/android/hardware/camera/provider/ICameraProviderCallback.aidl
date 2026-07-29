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

import android.hardware.camera.common.CameraDeviceStatus;
import android.hardware.camera.common.TorchModeStatus;

@VintfStability
interface ICameraProviderCallback {
    /**
     * cameraDeviceStatusChange:
     *
     * Callback to the camera service to indicate that the state of a specific
     * camera device has changed.
     *
     * On camera service startup, when ICameraProvider::setCallback is invoked,
     * the camera service must assume that all internal camera devices are in
     * the CAMERA_DEVICE_STATUS_PRESENT state.
     *
     * The provider must call this method to inform the camera service of any
     * initially NOT_PRESENT devices, and of any external camera devices that
     * are already present, as soon as the callbacks are available through
     * setCallback.
     *
     * @param cameraDeviceName The name of the camera device that has a new status.
     * @param newStatus The new status that device is in.
     *
     */
    void cameraDeviceStatusChange(String cameraDeviceName, CameraDeviceStatus newStatus);

    /**
     * torchModeStatusChange:
     *
     * Callback to the camera service to indicate that the state of the torch
     * mode of the flash unit associated with a specific camera device has
     * changed. At provider registration time, the camera service must assume
     * the torch modes are in the TORCH_MODE_STATUS_AVAILABLE_OFF state if
     * android.flash.info.available is reported as true via the
     * ICameraDevice::getCameraCharacteristics call.
     *
     * @param cameraDeviceName The name of the camera device that has a
     *     new status.
     * @param newStatus The new status that the torch is in.
     *
     */
    void torchModeStatusChange(String cameraDeviceName, TorchModeStatus newStatus);

    /**
     * cameraPhysicalDeviceStatusChange:
     *
     * Callback to the camera service to indicate that the state of a physical
     * camera device of a logical multi-camera has changed.
     *
     * On camera service startup, when ICameraProvider::setCallback is invoked,
     * the camera service must assume that all physical devices backing internal
     * multi-camera devices are in the CAMERA_DEVICE_STATUS_PRESENT state.
     *
     * The provider must call this method to inform the camera service of any
     * initially NOT_PRESENT physical devices, as soon as the callbacks are available
     * through setCallback.
     *
     * @param cameraDeviceName The name of the logical multi-camera whose
     *     physical camera has a new status.
     * @param physicalCameraDeviceName The name of the physical camera device
     *     that has a new status.
     * @param newStatus The new status that device is in.
     *
     */
    void physicalCameraDeviceStatusChange(
            String cameraDeviceName, String physicalCameraDeviceName, CameraDeviceStatus newStatus);
}
