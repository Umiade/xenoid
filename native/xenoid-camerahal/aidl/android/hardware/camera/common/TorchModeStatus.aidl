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
 * TorchModeStatus:
 *
 * The current status of the torch mode on a given camera device, sent by a
 * camera provider HAL via the ICameraProviderCallback::TorchModeStatusChange()
 * call.
 *
 * The torch mode status of a camera device is applicable only when the camera
 * device is present. The camera service must not call
 * ICameraProvider::setTorchMode() to turn on torch mode of a camera device if
 * the camera device is not present. At camera service startup time, the
 * framework must assume torch modes are in the AVAILABLE_OFF state if the
 * camera device is present and the camera characteristics entry
 * android.flash.info.available is reported as true via
 * ICameraProvider::getCameraCharacteristics() call. The same is assumed for
 * external camera devices when they are initially connected.
 *
 * The camera service requires the following behaviors from the camera provider
 * HAL when a camera device's status changes:
 *
 *  1. A previously-disconnected camera device becomes connected. After
 *      ICameraProviderCallback::CameraDeviceStatusChange() is invoked to inform
 *      the camera service that the camera device is present, the framework must
 *      assume the camera device's torch mode is in AVAILABLE_OFF state if it
 *      has a flash unit. The camera provider HAL does not need to invoke
 *      ICameraProviderCallback::TorchModeStatusChange() unless the flash unit
 *      is unavailable to use by ICameraProvider::setTorchMode().
 *
 *  2. A previously-connected camera becomes disconnected. After
 *      ICameraProviderCallback::CameraDeviceStatusChange() is invoked to inform
 *      the camera service that the camera device is not present, the framework
 *      must not call ICameraProvider::setTorchMode() for the disconnected camera
 *      device until it is connected again. The camera provider HAL does not
 *      need to invoke ICameraProviderCallback::TorchModeStatusChange()
 *      separately to inform that the flash unit has become NOT_AVAILABLE.
 *
 *  3. openCameraDevice() or openCameraDeviceVersion() is called to open a
 *      camera device. The camera provider HAL must invoke
 *      ICameraProviderCallback::TorchModeStatusChange() for all flash units
 *      that have entered NOT_AVAILABLE state and can not be turned on by
 *      calling ICameraProvider::setTorchMode() due to this open() call.
 *      openCameraDevice() must not trigger AVAILABLE_OFF before NOT_AVAILABLE
 *      for all flash units that have become unavailable.
 *
 *  4. ICameraDevice.close() is called to close a camera device. The camera
 *      provider HAL must call ICameraProviderCallback::torchModeStatusChange()
 *      for all flash units that have now entered the AVAILABLE_OFF state and
 *      can be turned on by calling ICameraProvider::setTorchMode() again because
 *      of sufficient new camera resources being freed up by this close() call.
 *
 *  Note that the camera service calling ICameraProvider::setTorchMode()
 *  successfully must trigger AVAILABLE_OFF or AVAILABLE_ON callback for the
 *  given camera device. Additionally it must trigger AVAILABLE_OFF callbacks
 *  for other previously-on torch modes if HAL cannot keep multiple devices'
 *  flashlights on simultaneously.
 */
@VintfStability
@Backing(type="int")
enum TorchModeStatus {
    /**
     * The flash unit is no longer available and the torch mode can not be
     * turned on by calling setTorchMode(). If the torch mode was AVAILABLE_ON,
     * the flashlight must be turned off by the provider HAL before the provider
     * HAL calls torchModeStatusChange().
     */
    NOT_AVAILABLE = 0,
    /**
     * A torch mode has become off and is available to be turned on via
     * ICameraProvider::setTorchMode(). This may happen in the following
     * cases:
     *   1. After the resources to turn on the torch mode have become available.
     *   2. After ICameraProvider::setTorchMode() is called to turn off the torch
     *      mode.
     *   3. After the camera service turned on the torch mode for some other
     *      camera device and the provider HAL had to turn off the torch modes
     *      of other camera device(s) that were previously on, due to lack of
     *      resources to keep them all on.
     */
    AVAILABLE_OFF = 1,
    /**
     * A torch mode has become on and is available to be turned off via
     * ICameraProvider::setTorchMode(). This can happen only after
     * ICameraProvider::setTorchMode() has been called to turn on the torch mode.
     */
    AVAILABLE_ON = 2,
}
