/*
 * Copyright (C) 2021 The Android Open Source Project
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

package android.hardware.camera.common;

/**
 * CameraDeviceStatus
 *
 * The current status of a camera device, as sent by a camera provider HAL
 * through the ICameraProviderCallback::cameraDeviceStatusChange() call.
 *
 * At startup, the camera service must assume all internal camera devices listed
 * by ICameraProvider::getCameraIdList() are in the PRESENT state. The provider
 * must invoke ICameraProviderCallback::cameraDeviceStatusChange to inform the
 * service of any initially NOT_PRESENT internal devices, and of any PRESENT
 * external camera devices, as soon as the camera service has called
 * ICameraProvider::setCallback().
 *
 * Allowed state transitions:
 *      PRESENT            -> NOT_PRESENT
 *      NOT_PRESENT        -> ENUMERATING
 *      NOT_PRESENT        -> PRESENT
 *      ENUMERATING        -> PRESENT
 *      ENUMERATING        -> NOT_PRESENT
 */
@VintfStability
@Backing(type="int")
enum CameraDeviceStatus {
    /**
     * The camera device is not currently connected, and trying to reference it
     * in provider method calls must return status code ILLEGAL_ARGUMENT.
     *
     */
    NOT_PRESENT = 0,
    /**
     * The camera device is connected, and opening it is possible, as long as
     * sufficient resources are available.
     *
     * By default, the framework must assume all devices returned by
     * ICameraProvider::getCameraIdList() are in this state.
     */
    PRESENT = 1,
    /**
     * The camera device is connected, but it is undergoing enumeration and
     * startup, and so opening the device must return CAMERA_IN_USE.
     *
     * Attempting to call ICameraProvider::getCameraCharacteristics() must
     * succeed, however.
     */
    ENUMERATING = 2,
}
